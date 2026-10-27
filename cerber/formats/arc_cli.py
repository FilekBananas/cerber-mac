"""Extraction through external tools: 7-Zip (7zz) for rar/7z/cab/iso/dmg/wim/vhd/chm/msi/NSIS/..., hdiutil as a
last resort for disk images, py7zr as a fallback for .7z when 7zz is missing.

Rules: arguments are always passed as lists, every call has a timeout, listings are checked *before*
extraction, extraction goes into a fresh sub-directory of ctx.tempdir(), the extracted tree is read back
without following symlinks and the directory is deleted afterwards.  Extracted content is never executed.
"""
from __future__ import annotations

import io
import os
import plistlib
import re
import stat
from dataclasses import dataclass, field
from typing import Callable

from ..core import Confidence, ScanContext, ScanObject
from .arc_common import (BOMB_READ_CAP, BOMB_TOTAL_CAP, Budget, BudgetExceeded, Sink, candidate_passwords, dir_free_bytes,
                         make_workdir, note_password_hints, ratio_suspicious, read_regular_file, run_tool,
                         safe_rmtree, vis, walk_tree)

# 7zz "Type" values that mean "this is an executable image, not a container"
NON_CONTAINER_TYPES = {"pe", "elf", "macho", "coff", "te", "mub", "swf", "swfc", "hash", "base64", "ihex"}

_NEEDS_PW = re.compile(r"(enter password|wrong password|cannot open encrypted archive)", re.I)


@dataclass
class SzEntry:
    path: str
    size: int = 0
    packed: int = 0
    is_dir: bool = False
    is_link: bool = False
    link: str = ""
    encrypted: bool = False
    method: str = ""
    mode: str = ""


@dataclass
class SzListing:
    rc: int = 0
    type: str = ""
    entries: list[SzEntry] = field(default_factory=list)
    props: dict[str, str] = field(default_factory=dict)
    needs_password: bool = False
    text: str = ""
    listed: bool = False        # a "----------" section was printed (archive opened)
    encrypted_headers: bool = False


def _int(v: str) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def parse_slt(out: str) -> tuple[dict[str, str], list[SzEntry], bool]:
    props: dict[str, str] = {}
    entries: list[SzEntry] = []
    lines = out.splitlines()
    i = 0
    n = len(lines)
    in_props = False
    listed = False
    cur: dict[str, str] = {}

    def flush() -> None:
        nonlocal cur
        if "Path" in cur:
            attrs = cur.get("Attributes", "").strip()
            mode = cur.get("Mode", "").strip()
            link = cur.get("Symbolic Link", "").strip()
            is_dir = cur.get("Folder", "") == "+" or attrs[:1] == "D" or mode[:1] == "d"
            is_link = bool(link) or mode[:1] == "l" or bool(re.search(r"\sl[r-][w-][x-]", " " + attrs))
            entries.append(SzEntry(cur["Path"], _int(cur.get("Size", "")), _int(cur.get("Packed Size", "")),
                                   is_dir, is_link, link, cur.get("Encrypted", "") == "+", cur.get("Method", ""),
                                   mode or attrs))
        cur = {}

    while i < n:
        ln = lines[i]
        i += 1
        if ln.startswith("----------"):
            listed = True
            in_props = False
            flush()
            continue
        if ln == "--":
            in_props = True
            continue
        if not listed:
            if in_props and " = " in ln:
                k, v = ln.split(" = ", 1)
                props.setdefault(k.strip(), v.strip())
            continue
        if not ln.strip():
            flush()
            continue
        if " = " in ln:
            k, v = ln.split(" = ", 1)
            if k == "Path" and "Path" in cur:
                flush()
            cur[k] = v
        elif ln.endswith(" =") and ln[:-2] in ("Path", "Symbolic Link", "Comment"):
            cur[ln[:-2]] = ""
    flush()
    return props, entries, listed


def sz_list(tool: str, path: str, password: str | None, timeout: float) -> SzListing:
    args = [tool, "l", "-slt", "-y", "-sccUTF-8"]
    if password is not None:
        args.append(f"-p{password}")
    args.append(path)
    rc, out, err = run_tool(args, timeout)
    lst = SzListing(rc=rc, text=(out + err)[-4000:])
    props, entries, listed = parse_slt(out)
    lst.props, lst.entries, lst.listed = props, entries, listed
    lst.type = props.get("Type", "")
    txt = out + err
    if rc != 0 and _NEEDS_PW.search(txt) and not listed:
        lst.needs_password = True
        lst.encrypted_headers = True
    return lst


def sz_test(tool: str, path: str, password: str, name: str, timeout: float) -> bool:
    rc, out, err = run_tool([tool, "t", "-y", "-spd", f"-p{password}", path, name], timeout)
    return rc == 0


def _write_list(dirpath: str, names: list[str]) -> str:
    lf = os.path.join(dirpath, "names.lst")
    with open(lf, "w", encoding="utf-8", errors="surrogateescape") as fh:
        fh.write("\n".join(names) + "\n")
    return lf


@dataclass
class CliResult:
    ok: bool = False            # the archive was opened
    type: str = ""
    entries: int = 0
    added: int = 0
    needs_password: bool = False
    password: str | None = None
    unopened_encrypted: list[str] = field(default_factory=list)
    error: str = ""
    non_container: bool = False


def prepare_input(ctx: ScanContext, obj: ScanObject, ext: str, data: bytes | None = None) -> tuple[str, str]:
    """Path 7zz can read: a symlink to the untouched top-level file, or a private copy."""
    d = make_workdir(ctx, "in-")
    target = os.path.join(d, f"container.{ext}")
    rp = obj.real_path
    if data is None:
        data = obj.data
    try:
        if data is obj.data and rp and os.path.isfile(rp) and os.path.getsize(rp) == len(obj.data):
            os.symlink(os.path.abspath(rp), target)
            return target, d
    except OSError:
        pass
    with open(target, "wb") as fh:
        fh.write(data)
    return target, d


def cli_extract(ctx: ScanContext, sink: Sink, tool: str, path: str, *,
                select: Callable[[SzEntry], bool] | None = None,
                passwords: list[str] | None = None, prefix: str = "",
                accept_non_container: bool = False, member_backslash: bool = False,
                count_members: bool = True) -> CliResult:
    """List, filter, extract with 7zz and feed every regular file back as a child."""
    res = CliResult()
    limits = ctx.limits
    budget = sink.budget
    cands = passwords if passwords is not None else candidate_passwords(sink.obj)
    lst = sz_list(tool, path, None, budget.time_left())
    pw: str | None = None
    if lst.needs_password:
        sink.encrypted = True
        for cand in cands:
            lst2 = sz_list(tool, path, cand, budget.time_left())
            if lst2.listed:
                lst, pw = lst2, cand
                break
        else:
            res.needs_password = True
            res.error = "encrypted headers, password unknown"
            return res
    if not lst.listed:
        res.error = (lst.text.strip().splitlines() or ["not an archive"])[-1][:200]
        return res
    res.type = lst.type
    if lst.type.lower() in NON_CONTAINER_TYPES and not accept_non_container:
        res.non_container = True
        return res
    res.ok = True
    entries = lst.entries
    res.entries = len(entries)

    # password search on the smallest encrypted entry
    enc_entries = [e for e in entries if e.encrypted and not e.is_dir]
    if enc_entries:
        sink.encrypted = True
        if pw is None:
            smallest = min(enc_entries, key=lambda e: e.size or 0)
            for cand in cands:
                if "\n" in smallest.path:
                    break
                if sz_test(tool, path, cand, smallest.path, min(60.0, budget.time_left())):
                    pw = cand
                    break
        if pw is None:
            res.needs_password = True
    res.password = pw

    # decide what to extract
    allowed: list[SzEntry] = []
    total = 0
    declared_total = sum(e.size for e in entries if not e.is_dir)
    for e in entries:
        if e.is_dir:
            continue
        if count_members:
            sink.members += 1
            sink.check_name(e.path, zip_like=True)
        if e.is_link:
            if count_members:
                sink.note_symlink(e.path, e.link or "")
            continue
        if select is not None and not select(e):
            continue
        if e.encrypted and pw is None:
            res.unopened_encrypted.append(e.path)
            continue
        if e.size == 0:
            continue
        if "\n" in e.path or "\r" in e.path:
            sink.skip(e.path, "unsupported file name")
            continue
        if e.size > limits.max_child_size:
            sink.skip(e.path, f"too large ({e.size} bytes)")
            if ratio_suspicious(e.size, e.packed or 1, limits.max_ratio):
                sink.bomb("member with absurd compression ratio", [vis(e.path)], score=25)
            continue
        if ratio_suspicious(e.size, e.packed or 1, limits.max_ratio) and e.packed:
            sink.bomb("member with absurd compression ratio", [vis(e.path)], score=25)
            # cannot be truncated on disk: extract only small offenders, within a shared allowance
            if e.size > BOMB_READ_CAP * 2 or sink.bomb_bytes + e.size > BOMB_TOTAL_CAP * 2:
                sink.skip(e.path, f"absurd compression ratio ({e.size} bytes), not extracted")
                continue
            sink.bomb_bytes += e.size
        if total + e.size > budget.remaining():
            sink.skip(e.path, "total extraction budget exhausted")
            if declared_total > 50 * max(1, len(sink.obj.data)):
                sink.bomb("extracted size exceeds the total extraction limit and dwarfs the archive itself",
                          [f"{declared_total} bytes declared, archive is {len(sink.obj.data)} bytes"])
            continue
        if len(allowed) >= max(0, limits.max_children - ctx.child_count):
            sink.skip(e.path, "max children reached")
            continue
        total += e.size
        allowed.append(e)
    if not allowed:
        return res
    tmp_root = ctx.tempdir()
    if dir_free_bytes(tmp_root) < total + (256 << 20):
        sink.skip("*", "not enough free disk space in the scan tempdir")
        res.error = "no disk space"
        return res

    out_dir = make_workdir(ctx, "out-")
    try:
        args = [tool, "x", "-y", "-aou", "-bd", "-sccUTF-8", f"-o{out_dir}"]
        if pw is not None:
            args.append(f"-p{pw}")
        everything = len(allowed) == len([e for e in entries if not e.is_dir])
        args.append(path)
        if not everything:
            lf = _write_list(make_workdir(ctx, "lst-"), [e.path for e in allowed])
            args += ["-spd", f"@{lf}"]
        rc, out, err = run_tool(args, budget.time_left())
        if rc == -999:
            sink.obj.errors.append("7zz extraction timed out")
            budget.reason = "extraction time limit"
        elif rc not in (0, 1):
            sink.obj.errors.append(f"7zz x rc={rc}: {(err or out).strip().splitlines()[-1][:200] if (err or out).strip() else ''}")
        _collect_tree(sink, out_dir, prefix, member_backslash)
    finally:
        safe_rmtree(out_dir)
    res.added = sink.added
    return res


def _collect_tree(sink: Sink, root: str, prefix: str = "", backslash: bool = False, count: bool = False) -> None:
    ctx = sink.ctx
    limits = ctx.limits
    for kind, rel, abspath, st in walk_tree(root):
        if sink.limit_reached():
            sink.skip("*", "max children reached")
            return
        if kind == "link":
            try:
                sink.note_symlink(rel, os.readlink(abspath))
            except OSError:
                pass
            continue
        if kind != "file":
            continue
        if count:
            sink.members += 1
            sink.check_name(rel, zip_like=False)
        if st.st_size == 0:
            continue
        if st.st_size > limits.max_child_size:
            sink.skip(rel, f"too large ({st.st_size} bytes)")
            continue
        data, trunc = read_regular_file(abspath, limits.max_child_size)
        if data is None:
            sink.skip(rel, "unreadable")
            continue
        sink.budget.charge(len(data))
        note_password_hints(sink, rel, data)
        c = sink.add(prefix + rel, data, {"size": st.st_size, "mode": stat.S_IMODE(st.st_mode),
                                          "mtime": int(st.st_mtime), "truncated": trunc}, backslash=backslash)
        if c is not None:
            sink.added += 1


# ---------------------------------------------------------------------------
# hdiutil fallback for disk images
# ---------------------------------------------------------------------------
def hdiutil_extract(ctx: ScanContext, sink: Sink, tool: str, path: str) -> bool:
    """Mount read-only (no browse, random mountpoint below our tempdir), copy files out in memory, detach."""
    parent = make_workdir(ctx, "mnt-")
    devs: list[str] = []
    mounts: list[str] = []
    ok = False
    try:
        args = [tool, "attach", "-readonly", "-nobrowse", "-noautoopen", "-noverify", "-noautofsck",
                "-mountrandom", parent, "-plist", path]
        rc, out, err = run_tool(args, min(120.0, sink.budget.time_left()), stdin_data=b"Y\n")
        i = out.find("<?xml")
        if i >= 0:
            try:
                pl = plistlib.loads(out[i:].encode("utf-8"))
                for ent in pl.get("system-entities", []):
                    if ent.get("dev-entry"):
                        devs.append(ent["dev-entry"])
                    if ent.get("mount-point"):
                        mounts.append(ent["mount-point"])
            except Exception as exc:  # noqa: BLE001
                sink.obj.errors.append(f"hdiutil plist: {exc}")
        if not mounts:
            # something may still be mounted below our directory
            try:
                mounts = [os.path.join(parent, d) for d in os.listdir(parent) if os.path.ismount(os.path.join(parent, d))]
            except OSError:
                pass
        if rc != 0 and not mounts:
            sink.obj.errors.append(f"hdiutil attach failed (rc={rc}): {(err or '').strip()[-160:]}")
            return False
        ok = True
        for mp in mounts:
            vol = os.path.basename(mp.rstrip("/")) or "volume"
            _collect_tree(sink, mp, prefix=f"{vol}/" if len(mounts) > 1 else "", count=True)
        return ok
    finally:
        # always detach: whole-disk device first, then any leftover mount point
        done = set()
        for dev in devs:
            whole = re.sub(r"s\d+$", "", dev)
            if whole in done:
                continue
            done.add(whole)
            run_tool([tool, "detach", "-force", whole], 60)
        for mp in mounts:
            if os.path.ismount(mp):
                run_tool([tool, "detach", "-force", mp], 60)
        try:
            for d in os.listdir(parent):
                p = os.path.join(parent, d)
                if os.path.ismount(p):
                    run_tool([tool, "detach", "-force", p], 60)
        except OSError:
            pass
        safe_rmtree(parent)


# ---------------------------------------------------------------------------
# py7zr fallback (7z only)
# ---------------------------------------------------------------------------
def py7zr_extract(ctx: ScanContext, sink: Sink, data: bytes) -> bool:
    """Fallback for .7z when 7zz is unavailable. Returns True when the archive was opened."""
    try:
        import py7zr
    except ImportError:
        return False
    limits = ctx.limits
    out_dir = None
    sz = None
    try:
        def is_pw_error(exc: Exception) -> bool:
            return type(exc).__name__ == "PasswordRequired" or "assword" in str(exc)

        infos = None
        pw_used: str | None = None
        try:
            sz = py7zr.SevenZipFile(io.BytesIO(data), mode="r")
            infos = sz.list()
            needs_pw = sz.needs_password()
        except Exception as exc:  # noqa: BLE001
            if not is_pw_error(exc):
                sink.obj.errors.append(f"py7zr: {type(exc).__name__}: {exc}")
                return False
            needs_pw = True
            sz = None
        if needs_pw:
            sink.encrypted = True
            sz = None
            for cand in candidate_passwords(sink.obj):
                try:
                    trial = py7zr.SevenZipFile(io.BytesIO(data), mode="r", password=cand)
                    infos = trial.list()
                    bad = trial.testzip()
                    if bad is None:
                        sz, pw_used = trial, cand
                        break
                    trial.close()
                except Exception:  # noqa: BLE001
                    continue
            if sz is None:
                return True                     # encrypted, password unknown (caller reports it)
            sink.extra["password_used"] = pw_used
            # testzip consumed the reader: reopen for extraction
            sz.close()
            sz = py7zr.SevenZipFile(io.BytesIO(data), mode="r", password=pw_used)
        targets: list[str] = []
        total = 0
        for fi in infos or []:
            if fi.is_directory:
                continue
            sink.members += 1
            sink.check_name(fi.filename)
            if fi.is_symlink:
                continue
            size = fi.uncompressed or 0
            if size == 0:
                continue
            if size > limits.max_child_size or total + size > sink.budget.remaining():
                sink.skip(fi.filename, f"too large ({size} bytes)")
                continue
            total += size
            targets.append(fi.filename)
        if targets:
            out_dir = make_workdir(ctx, "py7-")
            sz.extract(path=out_dir, targets=targets)
            _collect_tree(sink, out_dir, count=False)
        return True
    except BudgetExceeded:
        raise
    except Exception as exc:  # noqa: BLE001
        sink.obj.errors.append(f"py7zr: {type(exc).__name__}: {exc}")
        return False
    finally:
        try:
            if sz is not None:
                sz.close()
        except Exception:  # noqa: BLE001
            pass
        safe_rmtree(out_dir)
