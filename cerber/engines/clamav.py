"""ClamAV signature engine (ndb body signatures + ldb logical signatures).

Matching per object and target:
  1. run the Aho-Corasick prefilter (case-sensitive + case-insensitive
     automata) over the right *view* of the object (raw bytes, normalized
     text, normalized HTML);
  2. every hit marks candidate patterns; exact literal patterns are matches
     immediately, the rest are verified with their regex around the hit;
  3. logical signatures touched by a hit are evaluated (counts, unique
     subsignature counts, lazy PCRE / unanchored subsignatures).
"""
from __future__ import annotations

import html
import json
import os
import re
from collections import defaultdict

import ahocorasick_rs

from ..core import Confidence, Detection, ScanContext, ScanObject
from ..formats import exeinfo
from ..pipeline import Engine
from .clamav_db import load_pickle
from .clamav_sig import SigError, compile_pattern, compile_pcre, parse_expr, parse_offset, resolve_offset

TEXT_TYPES = {"script", "shell", "python", "powershell", "vbs", "javascript", "batch", "applescript",
              "php", "html", "hta", "perl", "ruby", "text", "json", "xml", "plist", "email", "url",
              "desktop"}
GRAPHICS = {"png", "jpeg", "gif", "bmp", "tiff", "ico", "webp", "psd"}
EXE_TYPES = {"pe", "elf", "macho"}
MAX_HITS = 256


def get_exe(obj: ScanObject):
    """Parsed executable structure, cached on the object (key starts with _ = not reported)."""
    if "_exe" not in obj.meta:
        obj.meta["_exe"] = exeinfo.parse(obj.data) if obj.ftype in EXE_TYPES else None
    return obj.meta["_exe"]


def object_targets(obj: ScanObject) -> set[int]:
    t = {0}
    ft = obj.ftype
    if ft == "pe":
        t.add(1)
    elif ft == "elf":
        t.add(6)
    elif ft == "macho":
        t.add(9)
    elif ft == "pdf":
        t.add(10)
    elif ft == "swf":
        t.add(11)
    elif ft == "java_class":
        t.add(12)
    elif ft == "email":
        t.update((4, 7))
    elif ft in GRAPHICS:
        t.add(5)
    elif ft == "ole2":
        t.add(2)
    if ft in ("html", "hta"):
        t.update((3, 7))
    elif ft in TEXT_TYPES:
        t.add(7)
    if ft != "ole2" and any(a.ftype in ("ole2", "ooxml") for a in obj.ancestors()):
        t.add(2)  # OLE2 components (streams, VBA source)
    return t


_WS = re.compile(rb"\s+")
_COMMENT = re.compile(rb"<!--.*?-->", re.S)
_TAG = re.compile(rb"<[^>]{0,4096}>")
_ENT = re.compile(rb"&#(x[0-9a-fA-F]{1,6}|[0-9]{1,7});")


def _as_ascii(data: bytes) -> bytes:
    if data[:2] == b"\xff\xfe" or (len(data) > 64 and data[1:512:2].count(0) > 200):
        try:
            return data.decode("utf-16-le", "ignore").encode("latin-1", "ignore")
        except Exception:
            return data
    return data


def norm_text(data: bytes) -> bytes:
    return _WS.sub(b" ", _as_ascii(data).lower())


def _entity(m: "re.Match[bytes]") -> bytes:
    v = m.group(1)
    try:
        n = int(v[1:], 16) if v[:1] in (b"x", b"X") else int(v)
        return bytes([n]) if n < 256 else b"?"
    except ValueError:
        return m.group(0)


def norm_html(data: bytes) -> tuple[bytes, bytes]:
    d = _COMMENT.sub(b"", _as_ascii(data))
    d = _ENT.sub(_entity, d)
    nocomment = _WS.sub(b" ", d.lower())
    notags = _WS.sub(b" ", _TAG.sub(b" ", nocomment))
    return nocomment, notags


class ClamAVEngine(Engine):
    name = "clamav"

    def __init__(self, compiled_dir: str, log=None, disabled: set[str] | None = None):
        self.dir = compiled_dir
        self.disabled = disabled or set()
        with open(os.path.join(compiled_dir, "meta.json")) as fh:
            self.meta = json.load(fh)
        # restricted unpickler: plain containers and array.array only, never code (see clamav_db.DBUnpickler)
        with open(os.path.join(compiled_dir, "sigs.pkl"), "rb") as fh:
            self.sigs = load_pickle(fh)
        with open(os.path.join(compiled_dir, "pats.pkl"), "rb") as fh:
            self.pat_sig, self.pat_spec, self.pat_exact, self.pat_alen = load_pickle(fh)
        with open(os.path.join(compiled_dir, "groups.pkl"), "rb") as fh:
            self.groups = load_pickle(fh)
        with open(os.path.join(compiled_dir, "slow.pkl"), "rb") as fh:
            self.slow = load_pickle(fh)
        # automata are built lazily (Rust Aho-Corasick); call preload() before forking workers
        self._ac_files: dict[tuple[int, int], str] = {}
        for fn in os.listdir(compiled_dir):
            m = re.match(r"ac_(\d+)_(cs|ci)\.pkl$", fn)
            if m:
                self._ac_files[(int(m.group(1)), 1 if m.group(2) == "ci" else 0)] = os.path.join(compiled_dir, fn)
        self.ac: dict[tuple[int, int], tuple] = {}
        self._pat_cache: dict[int, object] = {}
        self._pcre_cache: dict[tuple, object] = {}
        self._expr_cache: dict[int, object] = {}
        self._trig_cache: dict[str, object] = {}
        self.stats = defaultdict(int)

    def _automaton(self, key: tuple[int, int]):
        a = self.ac.get(key)
        if a is None:
            path = self._ac_files.get(key)
            if path is None:
                return None
            with open(path, "rb") as fh:
                keys, gids = load_pickle(fh)
            a = (ahocorasick_rs.BytesAhoCorasick(keys, matchkind=ahocorasick_rs.MATCHKIND_STANDARD), gids)
            self.ac[key] = a
        return a

    def preload(self) -> None:
        for key in self._ac_files:
            self._automaton(key)

    @property
    def signature_count(self) -> int:
        return len(self.sigs)

    # ------------------------------------------------------------------ helpers
    def _pattern(self, pid: int):
        p = self._pat_cache.get(pid, False)
        if p is False:
            hexsig, offset, nocase, wide, fullword = self.pat_spec[pid]
            try:
                p = compile_pattern(hexsig, offset, nocase, wide, fullword)
            except (SigError, re.error, ValueError, OverflowError, RecursionError):
                p = None
            self._pat_cache[pid] = p
        return p

    def _pcount(self, pid: int, view: bytes, exe, hits: dict) -> int:
        ends = hits.get(pid)
        if self.pat_exact[pid]:
            return len(ends) if ends else 0
        if self.pat_alen[pid] and not ends:
            return 0  # the anchor is a mandatory literal of the pattern
        pat = self._pattern(pid)
        if pat is None:
            return 0
        self.stats["verify"] += 1
        return pat.count(view, exe, ends if self.pat_alen[pid] else None)

    def _pcre_count(self, sub: tuple, view: bytes, exe) -> int:
        _, offset, _trigger, pcre, flags, _apid = sub
        key = (pcre, flags)
        rx = self._pcre_cache.get(key, False)
        if rx is False:
            try:
                rx = compile_pcre(pcre, flags)
            except SigError:
                rx = None
            self._pcre_cache[key] = rx
        if rx is None:
            return 0
        try:
            off = parse_offset(offset)
        except SigError:
            return 0
        rng = resolve_offset(off, len(view), exe)
        if rng is None:
            return 0
        lo, hi, endpos = rng
        n = 0
        view_ = view if len(view) <= (32 << 20) else view[: 32 << 20]
        for m in rx.finditer(view_, lo, endpos):
            if off.kind != "any" and m.start() > hi:
                break
            n += 1
            if n >= 64:
                break
        return n

    def _expr(self, sid: int):
        t = self._expr_cache.get(sid, False)
        if t is False:
            try:
                t = parse_expr(self.sigs[sid][4])
            except (SigError, ValueError, IndexError, RecursionError):
                t = None
            self._expr_cache[sid] = t
        return t

    def _trigger(self, trig: str):
        t = self._trig_cache.get(trig)
        if t is None:
            t = parse_expr(trig)
            self._trig_cache[trig] = t
        return t

    def _eval_ldb(self, sid: int, view: bytes, exe, hits: dict) -> bool:
        subs = self.sigs[sid][5]
        tree = self._expr(sid)
        if tree is None:
            return False
        cache: dict[int, int] = {}

        def subcount(i: int) -> int:
            if i in cache:
                return cache[i]
            cache[i] = 0  # recursion guard for self-referencing triggers
            c = 0
            if i < len(subs):
                s = subs[i]
                if s[0] == "hex":
                    c = sum(self._pcount(pid, view, exe, hits) for pid in s[1])
                elif s[0] == "pcre":
                    trig = s[2]
                    ok = True
                    if trig:
                        try:
                            ok = ev(self._trigger(trig), False)[0]
                        except (SigError, RecursionError):
                            ok = False
                    if ok and s[5] >= 0 and s[5] not in hits:
                        ok = False          # the PCRE's mandatory literal is absent
                    if ok:
                        c = self._pcre_count(s, view, exe)
            cache[i] = c
            return c

        def ev(node, need_count: bool):
            k = node[0]
            if k == "sub":
                c = subcount(node[1])
                return c > 0, c, ({node[1]} if c else set())
            if k == "cmp":
                _, op, x, y, inner = node
                _, cnt, uniq = ev(inner, True)
                if op == "=":
                    ok = cnt == x
                elif op == ">":
                    ok = cnt > x
                else:
                    ok = cnt < x
                if ok and y is not None:
                    ok = len(uniq) >= y
                return ok, cnt, uniq
            a = ev(node[1], need_count)
            if not need_count:
                if k == "and" and not a[0]:
                    return False, a[1], a[2]
                if k == "or" and a[0]:
                    return True, a[1], a[2]
            b = ev(node[2], need_count)
            ok = (a[0] and b[0]) if k == "and" else (a[0] or b[0])
            return ok, a[1] + b[1], a[2] | b[2]

        return ev(tree, False)[0]

    def _check_cons(self, cons: dict, obj: ScanObject, exe) -> bool:
        if "size" in cons:
            lo, hi = cons["size"]
            if not lo <= obj.size <= hi:
                return False
        if "container" in cons:
            if obj.parent is None or obj.parent.ftype not in cons["container"]:
                return False
        if "ep" in cons:
            if exe is None or exe.ep is None or not cons["ep"][0] <= exe.ep <= cons["ep"][1]:
                return False
        if "nsect" in cons:
            if exe is None or not cons["nsect"][0] <= exe.nsections <= cons["nsect"][1]:
                return False
        return True

    # ------------------------------------------------------------------ scanning
    def _scan_view(self, target: int, view: bytes, obj: ScanObject, exe, found: dict) -> None:
        if not view:
            return
        hits_g: dict[int, list[int]] = {}
        for ci in (0, 1):
            a = self._automaton((target, ci))
            if a is None:
                continue
            ac, gids = a
            hay = view.lower() if ci else view
            for idx, _start, end in ac.find_matches_as_indexes(hay, overlapping=True):
                gid = gids[idx]
                lst = hits_g.get(gid)
                if lst is None:
                    hits_g[gid] = [end - 1]
                elif len(lst) < MAX_HITS:
                    lst.append(end - 1)
        hits: dict[int, list[int]] = {}
        sids: set[int] = set(self.slow.get(target, ()))
        pat_sig = self.pat_sig
        for gid, ends in hits_g.items():
            for pid in self.groups[gid]:
                hits[pid] = ends
                sids.add(pat_sig[pid])
        self.stats["candidates"] += len(sids)
        for sid in sids:
            name, _t, pua, kind, _expr, subs, cons = self.sigs[sid]
            if name in found:
                continue
            if cons and not self._check_cons(cons, obj, exe):
                continue
            try:
                if kind == 0:
                    ok = any(self._pcount(pid, view, exe, hits) for pid in subs[0][1])
                else:
                    ok = self._eval_ldb(sid, view, exe, hits)
            except (RecursionError, re.error, ValueError, IndexError, OverflowError) as exc:
                self.stats["sig_errors"] += 1
                if self.stats["sig_errors"] < 20:
                    obj.errors.append(f"clamav sig {name}: {exc!r}")
                continue
            if ok:
                found[name] = pua

    def scan(self, obj: ScanObject, ctx: ScanContext) -> None:
        if obj.meta.get("clamav_fp"):
            return
        exe = get_exe(obj)
        found: dict[str, bool] = {}
        for t in sorted(object_targets(obj)):
            if t == 7:
                if obj.ftype in ("html", "hta"):
                    continue  # handled with the html views below
                self._scan_view(7, norm_text(obj.data), obj, None, found)
            elif t == 3:
                nocomment, notags = norm_html(obj.data)
                for v in (nocomment, notags):
                    self._scan_view(3, v, obj, None, found)
                    self._scan_view(7, v, obj, None, found)
            else:
                self._scan_view(t, obj.data, obj, exe if t in (1, 6, 9) or t == 0 else None, found)
        for name, pua in found.items():
            if name in self.disabled:
                continue
            ctx.detect(obj, Detection(f"ClamAV:{name}", "clamav", Confidence.CERTAIN, 100,
                                      "ClamAV signature database match", pua=pua))
