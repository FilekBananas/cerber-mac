"""Compile ClamAV databases (.cvd/.cld or loose files) into Cerber's matcher format.

Output directory layout (db/compiled/clamav/):
    meta.json            counts, source versions, unsupported-feature statistics
    sigs.pkl             list[SigRec]      one entry per ndb/ldb signature
    pats.pkl             (pat_sig array, pat_spec list, pat_exact bytearray, pat_alen array)
    groups.pkl           list[tuple[int,...]]   automaton value -> pattern ids
    slow.pkl             dict[target, list[sig_id]] signatures without any usable anchor
    ac_<target>_<cs|ci>.pkl   (anchor keys, group ids) for the Rust Aho-Corasick prefilter
Hash-type signatures (.hdb/.hsb/.mdb/.msb/.fp/.sfp …) go to the shared hash
database (see cerber/engines/hashdb.py) through `iter_hash_sigs()`.
"""
from __future__ import annotations

import array
import gzip
import io
import json
import os
import pickle
import re
import tarfile
import time
from collections import Counter, defaultdict
from typing import Iterable, Iterator


from .clamav_sig import (SigError, anchor_score, compile_pattern, compile_pcre, expr_needs_anchor,
                         parse_expr, pcre_anchor, split_pcre_subsig)

BODY_EXT = {".ndb", ".ndu", ".ldb", ".ldu"}
HASH_EXT = {".hdb", ".hsb", ".hdu", ".hsu", ".mdb", ".msb", ".mdu", ".msu", ".fp", ".sfp"}
PUA_EXT = {".ndu", ".ldu", ".hdu", ".hsu", ".mdu", ".msu"}
TARGETS = (0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12)

CONTAINERS = {
    "CL_TYPE_ZIP": ("zip", "jar", "apk", "crx_zip", "vsix"),
    "CL_TYPE_MSOLE2": ("ole2",), "CL_TYPE_MAIL": ("email",),
    "CL_TYPE_OOXML_WORD": ("ooxml",), "CL_TYPE_OOXML_XL": ("ooxml",), "CL_TYPE_OOXML_PPT": ("ooxml",),
    "CL_TYPE_XML_WORD": ("xml",), "CL_TYPE_XML_XL": ("xml",), "CL_TYPE_PDF": ("pdf",),
    "CL_TYPE_HTML": ("html", "hta"), "CL_TYPE_DMG": ("dmg",), "CL_TYPE_NULSFT": ("pe",),
    "CL_TYPE_AUTOIT": ("pe",), "CL_TYPE_MSEXE": ("pe",), "CL_TYPE_MSCAB": ("cab",),
    "CL_TYPE_RTF": ("rtf",), "CL_TYPE_RAR": ("rar",), "CL_TYPE_7Z": ("7z",),
    "CL_TYPE_GZ": ("gzip",), "CL_TYPE_BZ": ("bzip2",), "CL_TYPE_POSIX_TAR": ("tar",),
    "CL_TYPE_OLD_TAR": ("tar",), "CL_TYPE_ISO9660": ("iso",), "CL_TYPE_XAR": ("xar",),
    "CL_TYPE_CPIO_ODC": ("cpio",), "CL_TYPE_CPIO_NEWC": ("cpio",), "CL_TYPE_SWF": ("swf",),
    "CL_TYPE_ANY": None,
}


# --------------------------------------------------------------------------- input

def read_cvd(path: str) -> Iterator[tuple[str, bytes]]:
    """Yield (member name, content) from a .cvd/.cld (512-byte header + [gzip] tar)."""
    with open(path, "rb") as fh:
        raw = fh.read()
    body = raw[512:]
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:") as tf:
        for m in tf.getmembers():
            if m.isfile():
                f = tf.extractfile(m)
                if f is not None:
                    yield m.name, f.read()


def cvd_header(path: str) -> dict:
    with open(path, "rb") as fh:
        h = fh.read(512).split(b"\x00", 1)[0].decode("latin-1").split(":")
    keys = ["magic", "date", "version", "sigs", "flevel", "md5", "dsig", "builder", "stime"]
    return dict(zip(keys, h))


def iter_db_files(dbdir: str) -> Iterator[tuple[str, bytes]]:
    """All signature files from every .cvd/.cld plus loose files in dbdir."""
    for fn in sorted(os.listdir(dbdir)):
        p = os.path.join(dbdir, fn)
        ext = os.path.splitext(fn)[1].lower()
        if ext in (".cvd", ".cld"):
            yield from read_cvd(p)
        elif ext in BODY_EXT | HASH_EXT | {".ign", ".ign2"}:
            with open(p, "rb") as fh:
                yield fn, fh.read()


# --------------------------------------------------------------------------- hash sigs

def iter_hash_sigs(files: Iterable[tuple[str, bytes]]) -> Iterator[tuple[str, bytes, int | None, str, bool]]:
    """Yield (table, digest, size, name, pua) with table in {"file", "section", "fp"}."""
    for name, content in files:
        ext = os.path.splitext(name)[1].lower()
        if ext not in HASH_EXT:
            continue
        pua = ext in PUA_EXT
        section = ext in (".mdb", ".msb", ".mdu", ".msu")
        table = "fp" if ext in (".fp", ".sfp") else ("section" if section else "file")
        for line in content.decode("latin-1").splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 3:
                continue
            if section:
                size_s, h, sname = parts[0], parts[1], parts[2]
            else:
                h, size_s, sname = parts[0], parts[1], parts[2]
            try:
                digest = bytes.fromhex(h)
            except ValueError:
                continue
            if len(digest) not in (16, 20, 32):
                continue
            size = None if size_s == "*" else (int(size_s) if size_s.isdigit() else None)
            yield table, digest, size, sname, pua or sname.startswith("PUA.")


# --------------------------------------------------------------------------- body sigs

def _parse_range(v: str) -> tuple[int, int]:
    if "-" in v:
        a, b = v.split("-", 1)
        return int(a or 0), int(b or 1 << 62)
    n = int(v)
    return n, n


def _parse_tdb(tdb: str) -> tuple[int, dict | None, str | None]:
    """-> (target, constraints or None, reason-if-unsupported)."""
    target = 0
    cons: dict = {}
    for field in tdb.split(","):
        if ":" not in field:
            continue
        k, v = field.split(":", 1)
        if k == "Target":
            target = int(v)
        elif k == "Engine":
            continue
        elif k == "FileSize":
            cons["size"] = _parse_range(v)
        elif k == "EntryPoint":
            cons["ep"] = _parse_range(v)
        elif k == "NumberOfSections":
            cons["nsect"] = _parse_range(v)
        elif k == "Container":
            c = CONTAINERS.get(v, None)
            if c is not None:
                cons["container"] = c
        elif k in ("IconGroup1", "IconGroup2", "HandlerType"):
            return target, None, k
        elif k == "Intermediates":
            continue
    return target, (cons or None), None


_MOD_RE = re.compile(r"^(.*?)::([a-z]*)$")


class Compiler:
    def __init__(self, log=print):
        self.log = log
        self.sigs: list[tuple] = []
        self.pat_sig = array.array("I")
        self.pat_spec: list[tuple] = []
        self.pat_exact = bytearray()
        self.pat_alen = array.array("H")
        self.keys: dict[tuple[int, int], dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
        self.slow: dict[int, list[int]] = defaultdict(list)
        self.stats = Counter()
        self.ignored: set[str] = set()

    # -- patterns ------------------------------------------------------------
    def _add_pattern(self, sid: int, target: int, hexsig: str, offset: str, nocase: bool, wide: bool,
                     fullword: bool) -> tuple[int, bytes | None] | None:
        """Create one pattern variant (not yet registered in an automaton)."""
        try:
            pat = compile_pattern(hexsig, offset, nocase, wide, fullword, build_regex=False)
        except (SigError, re.error, ValueError, OverflowError) as exc:
            self.stats[f"bad_pattern:{type(exc).__name__}"] += 1
            return None
        pid = len(self.pat_spec)
        self.pat_sig.append(sid)
        self.pat_spec.append((hexsig, offset, nocase, wide, fullword))
        self.pat_exact.append(1 if pat.exact is not None else 0)
        self.pat_alen.append(0)
        return pid, pat.anchor

    def _new_pseudo(self, sid: int, spec: tuple) -> int:
        pid = len(self.pat_spec)
        self.pat_sig.append(sid)
        self.pat_spec.append(spec)
        self.pat_exact.append(0)
        self.pat_alen.append(0)
        return pid

    def _register(self, pid: int, target: int, anchor: bytes, nocase: bool) -> None:
        self.pat_alen[pid] = len(anchor)
        self.keys[(target, 1 if nocase else 0)][anchor.decode("latin-1")].append(pid)
        self.stats["anchored"] += 1

    def add_ndb(self, line: str, pua: bool) -> None:
        parts = line.split(":")
        if len(parts) < 4:
            return
        name, target_s, offset, hexsig = parts[0], parts[1], parts[2], parts[3]
        if name in self.ignored:
            self.stats["ignored"] += 1
            return
        try:
            target = int(target_s)
        except ValueError:
            return
        if target not in TARGETS:
            self.stats[f"ndb_target_{target}"] += 1
            return
        sid = len(self.sigs)
        r = self._add_pattern(sid, target, hexsig, offset, False, False, False)
        if r is None:
            return
        pid, anchor = r
        if anchor is not None and len(anchor) >= 3:
            self._register(pid, target, anchor, False)
        else:
            self.slow[target].append(sid)
            self.stats["unanchored"] += 1
        self.sigs.append((name, target, pua or name.startswith("PUA."), 0, None, [("hex", [pid])], None))
        self.stats["ndb"] += 1

    def add_ldb(self, line: str, pua: bool) -> None:
        parts = line.split(";")
        if len(parts) < 4:
            return
        name, tdb, expr = parts[0], parts[1], parts[2]
        if name in self.ignored:
            self.stats["ignored"] += 1
            return
        target, cons, unsupported = _parse_tdb(tdb)
        if unsupported:
            self.stats[f"ldb_unsupported_{unsupported}"] += 1
            return
        if target not in TARGETS:
            self.stats[f"ldb_target_{target}"] += 1
            return
        if not re.fullmatch(r"[0-9&|()=<>,\s]+", expr):
            self.stats["ldb_bad_expr"] += 1
            return
        try:
            tree = parse_expr(expr.replace(" ", ""))
        except (SigError, ValueError, IndexError, RecursionError):
            self.stats["ldb_bad_expr"] += 1
            return
        sid = len(self.sigs)
        subs: list[tuple] = []
        cands: list[tuple[int, int, bytes, bool, float]] = []   # (sub idx, pid, anchor, nocase, score)
        variant_pids: dict[int, list[int]] = {}
        for idx, raw in enumerate(parts[3:]):
            raw = raw.strip()
            if not raw:
                subs.append(("bad",))
                continue
            pc = split_pcre_subsig(raw) if "/" in raw else None
            if pc is not None:
                offset, trigger, pcre, flags = pc
                try:
                    compile_pcre(pcre, flags)
                except SigError:
                    subs.append(("bad",))
                    self.stats["pcre_bad"] += 1
                    continue
                anchor, ci = pcre_anchor(pcre, flags)
                apid = -1
                if anchor is not None:
                    apid = self._new_pseudo(sid, ("PCRE", pcre, flags))
                    cands.append((idx, apid, anchor, ci, anchor_score(anchor)))
                    variant_pids[idx] = [apid]
                subs.append(("pcre", offset, trigger, pcre, flags, apid))
                self.stats["pcre"] += 1
                continue
            if "#" in raw or raw.startswith("${") or re.match(r"^\d+\(", raw):
                subs.append(("bad",))          # byte-compare / macro: not supported -> never matches
                self.stats["bytecmp_or_macro"] += 1
                continue
            mods = ""
            m = _MOD_RE.match(raw)
            if m:
                raw, mods = m.group(1), m.group(2)
            offset = "*"
            if ":" in raw:
                offset, raw = raw.split(":", 1)
            nocase, fullword = "i" in mods, "f" in mods
            variants = [True, False] if ("w" in mods and "a" in mods) else ([True] if "w" in mods else [False])
            pids = []
            anchors = []
            for wide in variants:
                r = self._add_pattern(sid, target, raw, offset, nocase, wide, fullword)
                if r is not None:
                    pids.append(r[0])
                    anchors.append(r[1])
            if not pids:
                subs.append(("bad",))
                continue
            subs.append(("hex", pids))
            if all(a is not None and len(a) >= 3 for a in anchors):
                variant_pids[idx] = pids
                for pid, a in zip(pids, anchors):
                    cands.append((idx, pid, a, nocase, anchor_score(a) if len(a) >= 4 else 0.0))
        # register good anchors; weak ones only if nothing better exists in this signature
        good = [c for c in cands if c[4] >= 6]
        chosen = good if good else sorted(cands, key=lambda c: -c[4])[:len(variant_pids.get(cands[0][0], [1])) if cands else 0]
        if not good and cands:
            best_idx = max(cands, key=lambda c: c[4])[0]
            chosen = [c for c in cands if c[0] == best_idx]
        reg_idx: dict[int, int] = {}
        for idx, pid, anchor, ci, _s in chosen:
            self._register(pid, target, anchor, ci)
            reg_idx[idx] = reg_idx.get(idx, 0) + 1
        # a subsig counts as anchored only when *all* its variants are registered
        anchored = {idx: reg_idx.get(idx, 0) == len(variant_pids.get(idx, [])) and idx in reg_idx
                    for idx in range(len(subs))}
        for idx, sub in enumerate(subs):   # PCRE whose trigger needs an anchor is anchored too
            if sub[0] == "pcre" and not anchored.get(idx) and sub[2]:
                try:
                    anchored[idx] = expr_needs_anchor(parse_expr(sub[2]), anchored)
                except (SigError, ValueError, IndexError, RecursionError):
                    pass
        self.sigs.append((name, target, pua or name.startswith("PUA."), 1, expr.replace(" ", ""), subs, cons))
        if not expr_needs_anchor(tree, anchored):
            self.slow[target].append(sid)
            self.stats["ldb_slow"] += 1
        self.stats["ldb"] += 1

    # -- driver --------------------------------------------------------------
    def load_files(self, files: Iterable[tuple[str, bytes]]) -> None:
        files = list(files)
        for name, content in files:
            if name.endswith((".ign", ".ign2")):
                for line in content.decode("latin-1").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.ignored.add(line.split(":")[-1] if name.endswith(".ign") else line)
        for name, content in files:
            ext = os.path.splitext(name)[1].lower()
            if ext not in BODY_EXT:
                continue
            pua = ext in PUA_EXT
            t0 = time.time()
            n0 = len(self.sigs)
            is_ldb = ext in (".ldb", ".ldu")
            for line in content.decode("latin-1").splitlines():
                if not line or line.startswith("#"):
                    continue
                (self.add_ldb if is_ldb else self.add_ndb)(line, pua)
            self.log(f"  {name}: {len(self.sigs) - n0} signatures ({time.time() - t0:.1f}s)")

    def save(self, outdir: str, sources: dict) -> dict:
        os.makedirs(outdir, exist_ok=True)
        for fn in os.listdir(outdir):
            if fn.startswith("ac_") and fn.endswith(".bin"):
                os.remove(os.path.join(outdir, fn))
        groups: list[tuple[int, ...]] = []
        automata = {}
        for fn in os.listdir(outdir):
            if fn.startswith("ac_"):
                os.remove(os.path.join(outdir, fn))
        for (target, ci), keymap in self.keys.items():
            keys: list[bytes] = []
            gids = array.array("I")
            for key, pids in keymap.items():
                gid = len(groups)
                groups.append(tuple(pids))
                keys.append(key.encode("latin-1"))
                gids.append(gid)
            fn = f"ac_{target}_{'ci' if ci else 'cs'}.pkl"
            with open(os.path.join(outdir, fn), "wb") as fh:
                pickle.dump((keys, gids), fh, protocol=pickle.HIGHEST_PROTOCOL)
            automata[fn] = len(keys)
        with open(os.path.join(outdir, "sigs.pkl"), "wb") as fh:
            pickle.dump(self.sigs, fh, protocol=pickle.HIGHEST_PROTOCOL)
        with open(os.path.join(outdir, "pats.pkl"), "wb") as fh:
            pickle.dump((self.pat_sig, self.pat_spec, self.pat_exact, self.pat_alen), fh,
                        protocol=pickle.HIGHEST_PROTOCOL)
        with open(os.path.join(outdir, "groups.pkl"), "wb") as fh:
            pickle.dump(groups, fh, protocol=pickle.HIGHEST_PROTOCOL)
        with open(os.path.join(outdir, "slow.pkl"), "wb") as fh:
            pickle.dump(dict(self.slow), fh, protocol=pickle.HIGHEST_PROTOCOL)
        meta = {
            "built": time.strftime("%Y-%m-%d %H:%M:%S"),
            "signatures": len(self.sigs),
            "patterns": len(self.pat_spec),
            "automata": automata,
            "slow": {str(k): len(v) for k, v in self.slow.items()},
            "stats": dict(self.stats),
            "sources": sources,
        }
        with open(os.path.join(outdir, "meta.json"), "w") as fh:
            json.dump(meta, fh, indent=1)
        return meta


def compile_clamav(dbdir: str, outdir: str, log=print) -> dict:
    sources = {fn: cvd_header(os.path.join(dbdir, fn)) for fn in sorted(os.listdir(dbdir))
               if fn.endswith((".cvd", ".cld"))}
    comp = Compiler(log)
    comp.load_files(iter_db_files(dbdir))
    log(f"  building automata for {sum(len(v) for v in comp.keys.values())} anchors ...")
    return comp.save(outdir, sources)
