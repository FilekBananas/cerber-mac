"""Code-integrity seal of Cerber's backend (used by app/build.sh and Cerber.app).

Cerber.app runs with Full Disk Access and every process it starts inherits that permission. The backend is
plain Python in a user-writable folder (project, .venv, Homebrew interpreter and libraries), so without a check
any user-level program could edit one file and get the whole disk. Therefore:

* app/build.sh runs `python -I cerber/integrity.py seal …`: it discovers everything the backend executes or
  deserialises – cerber/, rules/, .venv, the interpreter with its stdlib and native libraries (every symlink on
  the way, e.g. /opt/homebrew/opt/python@3.14), the Homebrew tools the backend may run (7-Zip, UPX,
  llama-server, libimobiledevice) and the pickle/YARA databases in db/compiled – and writes a manifest with the
  SHA-256 of every file. The SHA-256 of the manifest itself is linked into the Cerber executable
  (section __TEXT,__cerber_seal), i.e. it is covered by the app's code signature.
* Cerber.app recomputes the manifest before it starts any backend process (Backend.swift, same rules as
  `entries()` below) and refuses to run Python on any difference. A deliberate re-seal ("I updated it myself")
  stores the new digest in a root-owned file, which needs the administrator password.

Manifest format (ASCII, one record per line, paths percent-escaped – see `esc()`):

    cerber-manifest 1
    R <project root>            C <precompiled .pyc tree>     Y <import path dir (only `cerber` in it)>
    X <excluded name>           P <excluded path>
    T <tree>  F <file>  L <symlink>  N <must not exist>
    --
    f <path> <x|-> <sha256>     l <path> <link target>     n <path>     o <path> (fifo/socket/device)

Stdlib only and runnable as a plain script (`python -I cerber/integrity.py …`): it must not import Cerber.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import os
import stat
import subprocess
import sys

FORMAT = "cerber-manifest 1"
SEPARATOR = "--"
EXCLUDE_NAMES = ("__pycache__", ".DS_Store")
TOOLS = ("7zz", "7z", "upx", "llama-server", "idevice_id", "ideviceinfo", "idevicepair", "idevicebackup2",
         "ideviceinstaller", "idevicecrashreport", "ideviceprovision")
TOOL_DIRS = ("/opt/homebrew/bin", "/usr/local/bin")          # PATH order used by Cerber.app (after system dirs)
SYSTEM_LIBS = ("/usr/lib/", "/System/")
KEG_ROOT = "/opt/homebrew/Cellar/"
MACHO_MAGIC = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
               b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce")
PYPATH_DIR = os.path.join(".venv", "cerber-path")              # holds only the `cerber` -> ../../cerber link
HEADER_KINDS = "RCYXPTFLN"


class SealError(Exception):
    pass


# ------------------------------------------------------------------ encoding

def esc(raw: bytes | str) -> str:
    """Bytes 0x21-0x7e except '%' stay, everything else becomes %XX (same rule in Backend.swift)."""
    if isinstance(raw, str):
        raw = os.fsencode(raw)
    return "".join(chr(b) if 0x21 <= b <= 0x7E and b != 0x25 else f"%{b:02X}" for b in raw)


def unesc(s: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "%":
            out.append(int(s[i + 1:i + 3], 16))
            i += 3
        else:
            out.append(ord(c))
            i += 1
    return bytes(out)


# ------------------------------------------------------------------ spec

class Spec:
    def __init__(self, root: bytes = b""):
        self.root = root
        self.pycache: bytes | None = None
        self.pypath: bytes | None = None
        self.excludes: set[bytes] = {os.fsencode(n) for n in EXCLUDE_NAMES}
        self.skip: set[bytes] = set()
        self.trees: set[bytes] = set()
        self.files: set[bytes] = set()
        self.links: set[bytes] = set()
        self.absent: set[bytes] = set()

    def header(self) -> list[str]:
        lines = [FORMAT, f"R {esc(self.root)}"]
        if self.pycache:
            lines.append(f"C {esc(self.pycache)}")
        if self.pypath:
            lines.append(f"Y {esc(self.pypath)}")
        for kind, group in (("X", self.excludes), ("P", self.skip), ("T", self.trees), ("F", self.files),
                            ("L", self.links), ("N", self.absent)):
            lines += sorted(f"{kind} {esc(p)}" for p in group)
        return lines

    def covered(self, path: bytes) -> bool:
        """True when `path` lies inside one of the trees (and is not excluded)."""
        for t in self.trees:
            if path == t or path.startswith(t + b"/"):
                return not any(path == s or path.startswith(s + b"/") for s in self.skip)
        return False


def parse(text: str) -> tuple[Spec, list[str]]:
    lines = text.split("\n")
    if not lines or lines[0] != FORMAT:
        raise SealError("nieznany format manifestu")
    spec = Spec()
    spec.excludes = set()
    i = 1
    while i < len(lines) and lines[i] != SEPARATOR:
        line = lines[i]
        kind, _, arg = line.partition(" ")
        if kind not in HEADER_KINDS or not arg:
            raise SealError(f"uszkodzony nagłówek manifestu: {line[:80]}")
        val = unesc(arg)
        if kind == "R":
            spec.root = val
        elif kind == "C":
            spec.pycache = val
        elif kind == "Y":
            spec.pypath = val
        else:
            {"X": spec.excludes, "P": spec.skip, "T": spec.trees, "F": spec.files, "L": spec.links,
             "N": spec.absent}[kind].add(val)
        i += 1
    if i >= len(lines):
        raise SealError("brak listy plików w manifeście")
    entries = [ln for ln in lines[i + 1:] if ln]
    return spec, entries


# ------------------------------------------------------------------ live entries (mirrored in Backend.swift)

def _sha256(path: bytes) -> str | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            h.update(chunk)
        return h.hexdigest()
    finally:
        os.close(fd)


def _file_entry(path: bytes, st: os.stat_result) -> str:
    digest = _sha256(path)
    if digest is None:
        return f"? {esc(path)} unreadable"
    return f"f {esc(path)} {'x' if st.st_mode & 0o111 else '-'} {digest}"


def _canonical(path: bytes) -> bool:
    try:
        return os.path.realpath(path) == path
    except OSError:
        return False


def entries(spec: Spec) -> list[str]:
    out: set[str] = set()
    for root in spec.trees:
        if not _canonical(root):
            out.add(f"? {esc(root)} not-canonical")
            continue
        try:
            if not stat.S_ISDIR(os.lstat(root).st_mode):
                out.add(f"? {esc(root)} not-a-directory")
                continue
        except OSError:
            out.add(f"? {esc(root)} missing")
            continue
        stack = [root]
        while stack:
            d = stack.pop()
            try:
                names = os.listdir(d)
            except OSError:
                out.add(f"? {esc(d)} unreadable")
                continue
            for name in names:
                if name in spec.excludes:
                    continue
                p = d + b"/" + name
                if p in spec.skip:
                    continue
                try:
                    st = os.lstat(p)
                except OSError:
                    out.add(f"? {esc(p)} vanished")
                    continue
                if stat.S_ISDIR(st.st_mode):
                    stack.append(p)
                elif stat.S_ISLNK(st.st_mode):
                    out.add(f"l {esc(p)} {esc(os.readlink(p))}")
                elif stat.S_ISREG(st.st_mode):
                    out.add(_file_entry(p, st))
                else:
                    out.add(f"o {esc(p)}")
    for p in spec.files:
        try:
            st = os.lstat(p)
        except OSError:
            out.add(f"? {esc(p)} missing")
            continue
        if not stat.S_ISREG(st.st_mode) or not _canonical(p):
            out.add(f"? {esc(p)} not-a-plain-file")
        else:
            out.add(_file_entry(p, st))
    for p in spec.links:
        try:
            st = os.lstat(p)
        except OSError:
            out.add(f"? {esc(p)} missing")
            continue
        if not stat.S_ISLNK(st.st_mode) or not _canonical(os.path.dirname(p)):
            out.add(f"? {esc(p)} not-a-plain-symlink")
        else:
            out.add(f"l {esc(p)} {esc(os.readlink(p))}")
    for p in spec.absent:
        try:
            os.lstat(p)
            out.add(f"? {esc(p)} exists")
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.ENOTDIR):
                out.add(f"n {esc(p)}")
            else:
                out.add(f"? {esc(p)} unknown")
    return sorted(out)


def manifest_text(spec: Spec, live: list[str] | None = None) -> str:
    return "\n".join(spec.header() + [SEPARATOR] + (entries(spec) if live is None else live)) + "\n"


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def diff(recorded: list[str], live: list[str], limit: int = 40) -> list[str]:
    """Human-readable differences (Polish), empty when identical."""
    def by_path(lines: list[str]) -> dict[str, str]:
        out = {}
        for ln in lines:
            parts = ln.split(" ")
            if len(parts) >= 2:
                out[parts[1]] = ln
        return out
    a, b = by_path(recorded), by_path(live)
    msgs = []
    for p in sorted(set(a) | set(b)):
        if a.get(p) == b.get(p):
            continue
        path = os.fsdecode(unesc(p))
        if p not in b:
            msgs.append(f"brak: {path}")
        elif p not in a:
            msgs.append(f"nowy plik: {path}")
        elif b[p].startswith("?"):
            msgs.append(f"niepoprawny: {path} ({b[p].rsplit(' ', 1)[-1]})")
        else:
            msgs.append(f"zmieniony: {path}")
        if len(msgs) >= limit:
            msgs.append("…")
            break
    return msgs


def verify(text: str) -> list[str]:
    """Differences between a manifest and the disk (empty list = intact)."""
    spec, recorded = parse(text)
    return diff(recorded, entries(spec))


# ------------------------------------------------------------------ build-time discovery

def chain(path: bytes, links: set[bytes], depth: int = 0) -> bytes:
    """Resolve `path` component by component; every symlink met on the way is added to `links`."""
    if depth > 32:
        raise SealError(f"pętla dowiązań: {os.fsdecode(path)}")
    cur = b"/"
    parts = [p for p in path.split(b"/") if p and p != b"."]
    for comp in parts:
        if comp == b"..":
            cur = os.path.dirname(cur) or b"/"
            continue
        nxt = os.path.join(cur, comp)
        st = os.lstat(nxt)
        if stat.S_ISLNK(st.st_mode):
            links.add(nxt)
            target = os.readlink(nxt)
            base = target if target.startswith(b"/") else os.path.join(cur, target)
            cur = chain(os.path.normpath(base), links, depth + 1)
        else:
            cur = nxt
    return cur


def _is_macho(path: bytes) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) in MACHO_MAGIC
    except OSError:
        return False


def _deps(path: bytes) -> list[bytes]:
    """Absolute, non-system libraries linked by a Mach-O file (otool -L)."""
    try:
        out = subprocess.run(["/usr/bin/otool", "-L", path], capture_output=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    deps = []
    for line in out.splitlines()[1:]:
        dep = line.strip().split(b" (", 1)[0]
        if dep.startswith(b"/") and not dep.startswith(tuple(os.fsencode(s) for s in SYSTEM_LIBS)):
            deps.append(dep)
    return deps


def _keg(real: bytes) -> bytes | None:
    k = os.fsencode(KEG_ROOT)
    if not real.startswith(k):
        return None
    parts = real[len(k):].split(b"/")
    return k + parts[0] + b"/" + parts[1] if len(parts) >= 3 else None


def _walk_files(spec: Spec, root: bytes):
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in spec.excludes and os.path.join(d, x) not in spec.skip]
        for f in files:
            p = os.path.join(d, f)
            if f not in spec.excludes and p not in spec.skip and not os.path.islink(p):
                yield p


def discover(root: str, pycache: str | None = None, pypath: str | None = None,
             data: bool = True) -> Spec:
    """Everything the backend run by Cerber.app executes or deserialises (see the module docstring)."""
    rootb = os.path.realpath(os.fsencode(root))
    spec = Spec(rootb)
    venv = os.path.join(rootb, b".venv")
    if os.path.realpath(os.fsencode(sys.prefix)) != venv:
        raise SealError(f"uruchom pieczętowanie interpreterem {os.fsdecode(venv)}/bin/python (jest: {sys.prefix})")
    py_prefix = os.path.realpath(os.fsencode(sys.base_prefix))
    spec.trees |= {os.path.join(rootb, b"cerber"), os.path.join(rootb, b"rules"), venv, py_prefix}
    ver = os.fsencode(f"python{sys.version_info.major}.{sys.version_info.minor}")
    spec.skip |= {os.path.join(py_prefix, b"include"), os.path.join(py_prefix, b"share"),
                  os.path.join(py_prefix, b"lib", ver, b"test"), os.path.join(py_prefix, b"lib", ver, b"idlelib"),
                  os.path.join(py_prefix, b"lib", ver, b"turtledemo")}
    if pycache:
        spec.pycache = os.path.realpath(os.fsencode(pycache))
        spec.trees.add(spec.pycache)
    if pypath:
        spec.pypath = os.path.realpath(os.fsencode(pypath))
        if not spec.covered(spec.pypath):
            spec.trees.add(spec.pypath)
    mock = os.path.join(rootb, b"app", b"mock_backend.py")
    if os.path.isfile(mock):
        spec.files.add(mock)
    if data:                    # deserialised with pickle / yara.load – as dangerous as code
        compiled = os.path.join(rootb, b"db", b"compiled")
        if os.path.isdir(os.path.join(compiled, b"clamav")):
            spec.trees.add(os.path.join(compiled, b"clamav"))
        yb = os.path.join(compiled, b"yara.bin")
        (spec.files if os.path.isfile(yb) else spec.absent).add(yb)

    links: set[bytes] = set()
    chain(os.path.join(venv, b"bin", b"python"), links)
    try:
        with open(os.path.join(venv, b"pyvenv.cfg"), "rb") as fh:
            for line in fh.read().splitlines():
                k, _, v = line.partition(b"=")
                if k.strip() == b"home" and v.strip():
                    chain(v.strip(), links)
    except OSError:
        pass

    todo: list[bytes] = []
    for name in TOOLS:
        for d in TOOL_DIRS:
            p = os.fsencode(os.path.join(d, name))
            if os.path.lexists(p):
                try:
                    real = chain(p, links)
                except OSError:                 # dangling link: not runnable, but record what it points to
                    links.add(p)
                    break
                if not spec.covered(real):
                    spec.files.add(real)
                todo.append(real)
                break
            if os.access(d, os.W_OK):
                spec.absent.add(p)

    scanned_trees: set[bytes] = set()
    seen: set[bytes] = set()
    while True:
        for t in sorted(spec.trees - scanned_trees):
            scanned_trees.add(t)
            todo += [p for p in _walk_files(spec, t) if _is_macho(p)]
        if not todo:
            break
        while todo:
            f = todo.pop()
            if f in seen:
                continue
            seen.add(f)
            keg = _keg(os.path.realpath(f))
            if keg:
                for sub in (b"lib", b"libexec"):
                    kd = os.path.join(keg, sub)
                    if os.path.isdir(kd) and not spec.covered(kd):
                        spec.trees.add(kd)
            for dep in _deps(f):
                try:
                    real = chain(dep, links)
                except (OSError, SealError):
                    continue
                if not spec.covered(real):
                    spec.files.add(real)
                todo.append(real)
        if spec.trees <= scanned_trees:
            break
    spec.links = {ln for ln in links if not spec.covered(ln)}
    spec.files = {f for f in spec.files if not spec.covered(f)}
    return spec


def ensure_pypath(root: str) -> str:
    """.venv/cerber-path/cerber -> ../../cerber: the backend's import path without the project root on it
    (a stray json.py or mlx/ next to cerber/ can then never shadow a module)."""
    d = os.path.join(os.path.realpath(root), PYPATH_DIR)
    os.makedirs(d, exist_ok=True)
    link = os.path.join(d, "cerber")
    want = os.path.join("..", "..", "cerber")
    if os.path.islink(link) and os.readlink(link) == want:
        pass
    else:
        if os.path.lexists(link):
            os.remove(link)
        os.symlink(want, link)
    for name in os.listdir(d):
        if name != "cerber":
            raise SealError(f"nieoczekiwany plik w {d}: {name}")
    return d


def seal(root: str, out: str, seal_out: str | None = None, pycache: str | None = None, data: bool = True) -> str:
    pypath = ensure_pypath(root)
    spec = discover(root, pycache=pycache, pypath=pypath, data=data)
    live = entries(spec)
    bad = [ln for ln in live if ln.startswith("?")]
    if bad:
        raise SealError("nie można zapieczętować: " + "; ".join(os.fsdecode(unesc(b.split(" ")[1])) + " " +
                                                                b.rsplit(" ", 1)[-1] for b in bad[:10]))
    text = manifest_text(spec, live)
    with open(out, "w", encoding="ascii") as fh:
        fh.write(text)
    d = digest(text)
    if seal_out:
        with open(seal_out, "w", encoding="ascii") as fh:
            fh.write(f"cerber-seal 1\n{d}\n")
    return d


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="integrity.py", description="Pieczęć integralności backendu Cerbera.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seal", help="utwórz manifest (app/build.sh)")
    s.add_argument("--root", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--seal-out")
    s.add_argument("--pycache")
    s.add_argument("--no-data", action="store_true", help="bez baz db/compiled (tylko do testów)")
    v = sub.add_parser("verify", help="porównaj manifest z dyskiem")
    v.add_argument("manifest")
    y = sub.add_parser("pypath", help="utwórz .venv/cerber-path (ścieżka importu backendu)")
    y.add_argument("--root", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "pypath":
            print(ensure_pypath(a.root))
            return 0
        if a.cmd == "seal":
            d = seal(a.root, a.out, a.seal_out, a.pycache, data=not a.no_data)
            with open(a.out, encoding="ascii") as fh:
                n = sum(1 for ln in fh if ln[:2] in ("f ", "l ", "n ", "o "))
            print(f"{d} ({n} wpisów)")
            return 0
        with open(a.manifest, encoding="ascii") as fh:
            problems = verify(fh.read())
        for p in problems:
            print(p)
        print("OK – zgodne z pieczęcią" if not problems else f"NIEZGODNE ({len(problems)})")
        return 0 if not problems else 1
    except (SealError, OSError) as exc:
        print(f"Błąd pieczęci: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
