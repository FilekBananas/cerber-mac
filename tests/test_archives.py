"""Tests for the archive/container extractors (cerber.analyzers.archives).

Samples are built programmatically into tests/samples/archives/ (harmless contents only; nothing is executed).

    python -m unittest tests.test_archives -v
    python tests/test_archives.py            # just (re)build the samples and print a summary
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
import zlib
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from cerber.analyzers import load_all  # noqa: E402
from cerber.devtool import default_tools  # noqa: E402
from cerber.pipeline import Pipeline  # noqa: E402

SAMPLES = ROOT / "samples" / "archives"
SEVENZ = shutil.which("7zz") or shutil.which("7z")

TEXT = b"CERBER harmless test payload\n"
SCRIPT = b"#!/bin/sh\necho harmless\n"


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------
def _w(name: str, data: bytes) -> Path:
    SAMPLES.mkdir(parents=True, exist_ok=True)
    p = SAMPLES / name
    p.write_bytes(data)
    return p


def _zip_bytes(members: dict[str, bytes], compression=zipfile.ZIP_DEFLATED) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression) as zf:
        for n, d in members.items():
            zf.writestr(n, d)
    return bio.getvalue()


def _tar_bytes(members: dict[str, bytes], mode: str = "w") -> bytes:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode=mode) as tf:
        for n, d in members.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(d))
    return bio.getvalue()


def build_nested() -> Path:
    inner2 = _zip_bytes({"payload.txt": TEXT + b"level3\n"})
    inner = _zip_bytes({"inner2.zip": inner2, "note.txt": b"level2 note\n"})
    return _w("nested.tar.gz", gzip.compress(_tar_bytes({"inner.zip": inner, "run.sh": SCRIPT})))


def build_7z() -> Path | None:
    try:
        import py7zr
    except ImportError:
        return None
    SAMPLES.mkdir(parents=True, exist_ok=True)
    p = SAMPLES / "sample.7z"
    with py7zr.SevenZipFile(p, "w") as z:
        z.writestr(TEXT, "docs/readme.txt")
        z.writestr(SCRIPT, "bin/run.sh")
    return p


def _sevenz_zip(name: str, files: dict[str, bytes], password: str, method: str | None = None) -> Path | None:
    if not SEVENZ:
        return None
    SAMPLES.mkdir(parents=True, exist_ok=True)
    out = SAMPLES / name
    if out.exists():
        out.unlink()
    with tempfile.TemporaryDirectory() as td:
        for n, d in files.items():
            fp = Path(td, n)
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_bytes(d)
        args = [SEVENZ, "a", f"-p{password}", "-tzip"]
        if method:
            args.append(f"-mem={method}")
        args += [str(out)] + list(files)
        subprocess.run(args, cwd=td, capture_output=True, check=True)
    return out


def build_encrypted() -> dict[str, Path | None]:
    return {
        "infected": _sevenz_zip("infected.zip", {"sample.txt": TEXT, "run.sh": SCRIPT}, "infected", "ZipCrypto"),
        "aes": _sevenz_zip("infected_aes.zip", {"sample.txt": TEXT + b"aes\n"}, "infected", "AES256"),
        "unknown": _sevenz_zip("unknown_pw.zip", {"setup.exe": b"not really an exe\n", "readme.txt": b"hi\n"},
                               "Zk93!xq-no-guess", "ZipCrypto"),
    }


def build_dmg() -> Path | None:
    if not shutil.which("hdiutil"):
        return None
    SAMPLES.mkdir(parents=True, exist_ok=True)
    out = SAMPLES / "sample.dmg"
    with tempfile.TemporaryDirectory() as td:
        src = Path(td, "src")
        (src / "Test.app/Contents/MacOS").mkdir(parents=True)
        (src / "Test.app/Contents/MacOS/run").write_bytes(SCRIPT)
        os.chmod(src / "Test.app/Contents/MacOS/run", 0o755)
        (src / "README.txt").write_bytes(TEXT)
        os.symlink("/Applications", src / "Applications")
        if out.exists():
            out.unlink()
        r = subprocess.run(["hdiutil", "create", "-srcfolder", str(src), "-format", "UDZO", "-volname", "CerberTest",
                            "-ov", str(out)], capture_output=True)
        if r.returncode != 0:
            return None
    return out


def build_iso() -> Path | None:
    if not shutil.which("hdiutil"):
        return None
    SAMPLES.mkdir(parents=True, exist_ok=True)
    out = SAMPLES / "sample.iso"
    with tempfile.TemporaryDirectory() as td:
        src = Path(td, "src")
        (src / "docs").mkdir(parents=True)
        (src / "README.TXT").write_bytes(TEXT)
        (src / "docs/run.sh").write_bytes(SCRIPT)
        if out.exists():
            out.unlink()
        r = subprocess.run(["hdiutil", "makehybrid", "-iso", "-joliet", "-o", str(out), str(src)], capture_output=True)
        if r.returncode != 0:
            return None
    return out


def build_wim() -> Path | None:
    if not SEVENZ:
        return None
    SAMPLES.mkdir(parents=True, exist_ok=True)
    out = SAMPLES / "sample.wim"
    if out.exists():
        out.unlink()
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "a.txt").write_bytes(TEXT)
        (Path(td) / "run.sh").write_bytes(SCRIPT)
        subprocess.run([SEVENZ, "a", "-twim", str(out), "a.txt", "run.sh"], cwd=td, capture_output=True, check=True)
    return out


BREW_FIXTURES = Path("/opt/homebrew/Library/Homebrew/test/support/fixtures/cask")


def build_pkg() -> dict[str, Path | None]:
    res: dict[str, Path | None] = {"component": None, "product": None, "installerjs": None}
    if not (shutil.which("pkgbuild") and shutil.which("xar")):
        return res
    SAMPLES.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        root = Path(td, "root/usr/local/share/cerber")
        root.mkdir(parents=True)
        (root / "data.txt").write_bytes(TEXT)
        scripts = Path(td, "scripts")
        scripts.mkdir()
        (scripts / "postinstall").write_bytes(b"#!/bin/sh\necho postinstall-marker\nexit 0\n")
        (scripts / "preinstall").write_bytes(b"#!/bin/sh\nexit 0\n")
        os.chmod(scripts / "postinstall", 0o755)
        os.chmod(scripts / "preinstall", 0o755)
        comp = SAMPLES / "component.pkg"
        subprocess.run(["pkgbuild", "--root", str(Path(td, "root")), "--scripts", str(scripts), "--identifier",
                        "test.pkg", "--version", "1.0", str(comp)], capture_output=True, check=True)
        res["component"] = comp
        if shutil.which("productbuild"):
            prod = SAMPLES / "product.pkg"
            subprocess.run(["productbuild", "--package", str(comp), str(prod)], capture_output=True, check=True)
            res["product"] = prod
        # hand made flat package whose Distribution runs a program from InstallerJS (never executed here)
        dist = (b'<?xml version="1.0" encoding="utf-8"?>\n<installer-gui-script minSpecVersion="1">\n'
                b'  <script>function pre_check() { return system.run("/usr/bin/true") == 0; }</script>\n'
                b'  <installation-check script="pre_check()"/>\n</installer-gui-script>\n')
        d2 = Path(td, "js")
        d2.mkdir()
        (d2 / "Distribution").write_bytes(dist)
        out = SAMPLES / "installerjs.pkg"
        if out.exists():
            out.unlink()
        subprocess.run(["xar", "-c", "-f", str(out), "Distribution"], cwd=d2, capture_output=True, check=True)
        res["installerjs"] = out
    return res


def _cpio(members: dict[str, bytes], fmt: str = "newc") -> bytes:
    """Minimal cpio writer (newc / odc)."""
    out = bytearray()
    ino = 1
    for name, data in list(members.items()) + [("TRAILER!!!", b"")]:
        nb = name.encode() + b"\x00"
        mode = 0o100755 if name != "TRAILER!!!" else 0
        if fmt == "newc":
            hdr = b"070701" + b"".join(b"%08X" % v for v in (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nb), 0))
            out += hdr + nb
            out += b"\x00" * ((-len(out)) % 4)
            out += data + b"\x00" * ((-len(data)) % 4)
        else:
            hdr = b"070707" + b"%06o" % 0 + b"%06o" % ino + b"%06o" % mode + b"%06o" % 0 + b"%06o" % 0 + b"%06o" % 1 \
                + b"%06o" % 0 + b"%011o" % 0 + b"%06o" % len(nb) + b"%011o" % len(data)
            out += hdr + nb + data
        ino += 1
    return bytes(out)


def build_cpio() -> dict[str, Path]:
    m = {"./etc/config.txt": TEXT, "./bin/tool.sh": SCRIPT}
    return {"newc": _w("sample_newc.cpio", _cpio(m, "newc")), "odc": _w("sample_odc.cpio", _cpio(m, "odc"))}


def build_pbzx() -> Path:
    cpio = _cpio({"./Applications/Test.app/Contents/Info.txt": TEXT, "./scripts/postinstall": SCRIPT}, "odc")
    xz = lzma.compress(cpio, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32)
    data = b"pbzx" + struct.pack(">Q", 0x01000000) + struct.pack(">QQ", len(cpio), len(xz)) + xz
    return _w("payload.pbzx", data)


def _zero_zip(path: Path, member: str, size: int) -> None:
    """A zip (zip64) whose only member is `size` zero bytes, deflated (~1000:1)."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        with zf.open(member, "w", force_zip64=True) as fp:
            block = bytes(1 << 20)
            for _ in range(size >> 20):
                fp.write(block)


def build_bombs() -> dict[str, Path]:
    SAMPLES.mkdir(parents=True, exist_ok=True)
    zp = SAMPLES / "bomb_2gb.zip"
    if not zp.exists() or zp.stat().st_size < 1000:
        _zero_zip(zp, "zeros.bin", 2 << 30)
    gp = SAMPLES / "bomb_2gb.bin.gz"
    if not gp.exists() or gp.stat().st_size < 1000:
        c = zlib.compressobj(9, zlib.DEFLATED, 31)
        block = bytes(1 << 20)
        with open(gp, "wb") as fh:
            for _ in range(2048):
                fh.write(c.compress(block))
            fh.write(c.flush())
    # a "nested" bomb: many highly compressible members (total limit)
    zp2 = SAMPLES / "bomb_many.zip"
    if not zp2.exists():
        with zipfile.ZipFile(zp2, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for i in range(40):
                zf.writestr(f"part{i:02d}.bin", bytes([0x80 + i]) * (48 << 20))     # 40 x 48 MB, each ~48 KB
    return {"zip": zp, "gz": gp, "many": zp2}


def build_names() -> dict[str, Path]:
    out = {}
    out["traversal"] = _w("traversal.zip", _zip_bytes({"../../evil.txt": TEXT, "/abs/path.txt": TEXT, "ok/fine.txt": b"fine\n"}))
    out["rtlo"] = _w("rtlo.zip", _zip_bytes({"invoice‮txt.exe": b"harmless\n", "readme.txt": b"hi\n"}))
    out["doubleext"] = _w("doubleext.zip", _zip_bytes({"invoice.pdf.exe": b"harmless\n", "photo.jpg.app/Contents/x": b"harmless\n",
                                                      "scan.doc.js": b"// harmless\n"}))
    out["nulname"] = None
    return {k: v for k, v in out.items() if v}


def build_crx() -> Path:
    z = _zip_bytes({"manifest.json": b'{"manifest_version":3,"name":"t","version":"1"}', "background.js": b"// bg\n"})
    hdr = b"\x0a\x04test\x12\x04sign"
    return _w("ext.crx", b"Cr24" + struct.pack("<II", 3, len(hdr)) + hdr + z)


def build_email() -> dict[str, Path | None]:
    res: dict[str, Path | None] = {}
    z = _zip_bytes({"docs/invoice.pdf.exe": b"harmless zip member\n", "readme.txt": TEXT})
    m = EmailMessage()
    m["From"] = "a@example.invalid"
    m["To"] = "b@example.invalid"
    m["Subject"] = "Invoice"
    m.set_content("Please see the attachment.\n")
    m.add_alternative("<html><body><p>Please see the attachment.</p></body></html>", subtype="html")
    m.add_attachment(z, maintype="application", subtype="zip", filename="invoice.zip")
    m.add_attachment(b"harmless\n", maintype="application", subtype="octet-stream", filename="statement.pdf.scr")
    res["zip"] = _w("mail_zip.eml", m.as_bytes())
    enc = _sevenz_zip("hint_enc.zip", {"secret.txt": TEXT + b"hint\n"}, "Zk93xq", "ZipCrypto")
    if enc:
        m2 = EmailMessage()
        m2["From"] = "a@example.invalid"
        m2["To"] = "b@example.invalid"
        m2["Subject"] = "Documents"
        m2.set_content("Files are attached. The password is: Zk93xq\n")
        m2.add_attachment(enc.read_bytes(), maintype="application", subtype="zip", filename="docs.zip")
        res["hint"] = _w("mail_password_hint.eml", m2.as_bytes())
        enc.unlink()
    m3 = EmailMessage()
    m3["From"] = "c@example.invalid"
    m3["To"] = "b@example.invalid"
    m3["Subject"] = "Second"
    m3.set_content("A second, different message.\n")
    m3.add_attachment(b"second attachment\n", maintype="application", subtype="octet-stream", filename="notes.txt")
    mbox = (b"From a@example.invalid Mon Jan  1 00:00:00 2024\n" + m.as_bytes() + b"\n\n"
            b"From c@example.invalid Tue Jan  2 00:00:00 2024\n" + m3.as_bytes() + b"\n")
    res["mbox"] = _w("sample.mbox", mbox)
    return res


def build_damaged_zips() -> dict[str, Path]:
    out = {}
    good = _zip_bytes({"a.txt": TEXT, "sub/b.sh": SCRIPT, "c.bin": bytes(range(256)) * 4})
    # central directory destroyed
    eocd = good.rfind(b"PK\x05\x06")
    cd = good.rfind(b"PK\x01\x02")
    out["nocd"] = _w("broken_nocd.zip", good[:cd])
    # two zips concatenated: the first one is invisible to a central-directory reader
    hidden = _zip_bytes({"hidden/evil.sh": b"#!/bin/sh\necho hidden-marker\n"})
    out["hidden"] = _w("hidden_entries.zip", hidden + good)
    # bad CRC
    stored = _zip_bytes({"crc.txt": TEXT}, zipfile.ZIP_STORED)
    b = bytearray(stored)
    struct.pack_into("<I", b, 14, 0xDEADBEEF)                 # local header CRC
    cdp = stored.rfind(b"PK\x01\x02")
    struct.pack_into("<I", b, cdp + 16, 0xDEADBEEF)           # central directory CRC
    out["badcrc"] = _w("badcrc.zip", bytes(b))
    del eocd
    return out


def _mk_pe(body: bytes = b"\x90" * 512) -> bytes:
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)
    sec = struct.pack("<8sIIIIIIHHI", b".text", len(body), 0x1000, len(body), 0x200, 0, 0, 0, 0, 0x60000020)
    hdr = (bytes(dos) + b"PE\0\0" + coff + bytes(opt) + sec).ljust(0x200, b"\0")
    return hdr + body


def build_sfx() -> dict[str, Path]:
    pe = _mk_pe()
    return {"zip": _w("sfx_zip.exe", pe + _zip_bytes({"payload/run.bat": b"echo harmless\r\n", "payload/data.txt": TEXT}))}


def _xxh32(data: bytes, seed: int = 0) -> int:
    P1, P2, P3, P4, P5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
    M = 0xFFFFFFFF
    rotl = lambda x, r: ((x << r) | (x >> (32 - r))) & M  # noqa: E731
    n = len(data)
    i = 0
    if n >= 16:
        v1, v2, v3, v4 = (seed + P1 + P2) & M, (seed + P2) & M, seed & M, (seed - P1) & M
        while i <= n - 16:
            for k, v in enumerate((v1, v2, v3, v4)):
                w = struct.unpack_from("<I", data, i + 4 * k)[0]
                v = (rotl((v + w * P2) & M, 13) * P1) & M
                if k == 0:
                    v1 = v
                elif k == 1:
                    v2 = v
                elif k == 2:
                    v3 = v
                else:
                    v4 = v
            i += 16
        h = (rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18)) & M
    else:
        h = (seed + P5) & M
    h = (h + n) & M
    while i <= n - 4:
        h = (rotl((h + struct.unpack_from("<I", data, i)[0] * P3) & M, 17) * P4) & M
        i += 4
    while i < n:
        h = (rotl((h + data[i] * P5) & M, 11) * P1) & M
        i += 1
    h ^= h >> 15
    h = (h * P2) & M
    h ^= h >> 13
    h = (h * P3) & M
    h ^= h >> 16
    return h


def build_streams() -> dict[str, Path]:
    out = {}
    tar = _tar_bytes({"dir/a.txt": TEXT, "dir/run.sh": SCRIPT})
    out["tar"] = _w("plain.tar", tar)
    out["tar.xz"] = _w("sample.tar.xz", lzma.compress(tar))
    out["tar.bz2"] = _w("sample.tar.bz2", bz2.compress(tar))
    out["gz"] = _w("single.txt.gz", gzip.compress(SCRIPT))
    out["bz2"] = _w("single.sh.bz2", bz2.compress(SCRIPT))
    out["xz"] = _w("single.sh.xz", lzma.compress(SCRIPT))
    out["gz_trailing"] = _w("trailing.txt.gz", gzip.compress(TEXT) + b"#!/bin/sh\necho appended-after-gzip\n" * 3)
    try:
        from compression import zstd
        out["zst"] = _w("single.sh.zst", zstd.compress(SCRIPT))
    except ImportError:
        pass
    # lz4 frame: one compressed block + one raw block
    desc = bytes([0x60, 0x40])
    hc = (_xxh32(desc) >> 8) & 0xFF
    cblk = bytes([0x44]) + b"abcd" + b"\x04\x00" + bytes([0x50]) + b"hello"
    payload = b"abcdabcdabcdhello"
    rawblk = b"\n" + SCRIPT
    frame = (b"\x04\x22\x4d\x18" + desc + bytes([hc]) + struct.pack("<I", len(cblk)) + cblk +
             struct.pack("<I", len(rawblk) | 0x80000000) + rawblk + b"\x00\x00\x00\x00")
    out["lz4"] = _w("single.txt.lz4", frame)
    del payload
    # lzip
    comp = lzma.LZMACompressor(lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20, "lc": 3,
                                                          "lp": 0, "pb": 2}])
    body = comp.compress(SCRIPT) + comp.flush()
    trailer = struct.pack("<IQQ", zlib.crc32(SCRIPT), len(SCRIPT), 6 + len(body) + 20)
    out["lz"] = _w("single.sh.lz", b"LZIP\x01" + bytes([20]) + body + trailer)
    return out


def _ar(members: list[tuple[str, bytes]]) -> bytes:
    out = bytearray(b"!<arch>\n")
    for name, data in members:
        out += b"%-16s%-12d%-6d%-6d%-8s%-10d`\n" % (name.encode(), 0, 0, 0, b"100644", len(data))
        out += data
        if len(data) % 2:
            out += b"\n"
    return bytes(out)


def build_deb() -> Path:
    control = gzip.compress(_tar_bytes({"./control": b"Package: cerbertest\nVersion: 1\n", "./postinst": SCRIPT}))
    data = lzma.compress(_tar_bytes({"./usr/share/cerber/data.txt": TEXT}))
    return _w("sample.deb", _ar([("debian-binary", b"2.0\n"), ("control.tar.gz", control), ("data.tar.xz", data)]))


def build_rpm() -> Path:
    def hdr(entries):
        index = b""
        store = b""
        for tag, typ, cnt, d in entries:
            index += struct.pack(">IIII", tag, typ, len(store), cnt)
            store += d
        return b"\x8e\xad\xe8\x01\x00\x00\x00\x00" + struct.pack(">II", len(entries), len(store)) + index + store

    lead = b"\xed\xab\xee\xdb" + bytes([3, 0]) + struct.pack(">HH", 0, 1) + b"cerbertest".ljust(66, b"\0") + \
        struct.pack(">HH", 1, 5) + bytes(16)
    sig = hdr([])
    main = hdr([(1000, 6, 1, b"cerbertest\0"), (1001, 6, 1, b"1.0\0"),
                (1024, 6, 1, b"#!/bin/sh\necho rpm-postin-marker\n\0"), (1125, 6, 1, b"gzip\0")])
    payload = gzip.compress(_cpio({"./usr/share/cerber/data.txt": TEXT}, "newc"))
    return _w("sample.rpm", lead + sig + main + payload)


def build_symlink_tar() -> Path:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tf:
        ti = tarfile.TarInfo("escape")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/Users/victim/Library/LaunchAgents"
        tf.addfile(ti)
        d = b"harmless\n"
        ti2 = tarfile.TarInfo("escape/evil.plist")
        ti2.size = len(d)
        tf.addfile(ti2, io.BytesIO(d))
    return _w("symlink_escape.tar", bio.getvalue())


def build_all() -> dict[str, object]:
    s: dict[str, object] = {}
    s["nested"] = build_nested()
    s["7z"] = build_7z()
    s["enc"] = build_encrypted()
    s["dmg"] = build_dmg()
    s["iso"] = build_iso()
    s["wim"] = build_wim()
    s["pkg"] = build_pkg()
    s["cpio"] = build_cpio()
    s["pbzx"] = build_pbzx()
    s["names"] = build_names()
    s["crx"] = build_crx()
    s["email"] = build_email()
    s["damaged"] = build_damaged_zips()
    s["sfx"] = build_sfx()
    s["streams"] = build_streams()
    s["deb"] = build_deb()
    s["rpm"] = build_rpm()
    s["symtar"] = build_symlink_tar()
    return s


# ---------------------------------------------------------------------------
# helpers for the tests
# ---------------------------------------------------------------------------
_PIPE: Pipeline | None = None


def scan(path: Path | str):
    global _PIPE
    if _PIPE is None:
        _PIPE = Pipeline(analyzers=[a for a in load_all() if a.name in ("archives", "email_extract")],
                         options={"deep": True, "macos": True, "tools": default_tools()})
    return _PIPE.scan_file(str(path))


def members(root) -> set[str]:
    """Display path of every descendant relative to the root, e.g. 'inner.zip>>inner2.zip>>payload.txt'."""
    out = set()
    for o in root.iter_tree():
        if o is root:
            continue
        out.add(o.display_path.split(">>", 1)[1])
    return out


def leaf_names(root) -> set[str]:
    return {o.display_path.rsplit(">>", 1)[-1] for o in root.iter_tree() if o is not root}


def det_names(root) -> set[str]:
    return {d.name for o in root.iter_tree() for d in o.detections}


def dets(root, name: str):
    return [d for o in root.iter_tree() for d in o.detections if d.name == name]


class ArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.S = build_all()

    # -- containers ---------------------------------------------------------
    def test_nested_zip_in_zip_in_targz(self):
        r = scan(self.S["nested"])
        m = members(r)
        self.assertIn("inner.zip", m)
        self.assertIn("inner.zip>>inner2.zip", m)
        self.assertIn("inner.zip>>inner2.zip>>payload.txt", m)
        self.assertIn("run.sh", m)
        self.assertEqual(r.meta["archive"]["format"], "gzip+tar")
        self.assertEqual(r.meta["verdict"].name, "CLEAN")

    @unittest.skipUnless(SEVENZ or True, "")
    def test_7z(self):
        p = self.S["7z"]
        if p is None:
            self.skipTest("py7zr missing")
        r = scan(p)
        self.assertLessEqual({"docs/readme.txt", "bin/run.sh"}, members(r))

    def test_encrypted_zip_common_password(self):
        p = self.S["enc"]["infected"]
        if p is None:
            self.skipTest("7zz missing")
        r = scan(p)
        self.assertLessEqual({"sample.txt", "run.sh"}, members(r))
        self.assertTrue(r.meta["archive"]["encrypted"])
        self.assertEqual(r.meta["archive"]["password_used"], "infected")
        self.assertIn("Heur:Archive.Encrypted", det_names(r))
        self.assertNotIn("Heur:Archive.EncryptedExecutable", det_names(r))

    def test_encrypted_zip_aes(self):
        p = self.S["enc"]["aes"]
        if p is None:
            self.skipTest("7zz missing")
        r = scan(p)
        self.assertIn("sample.txt", members(r))

    def test_encrypted_unknown_password_executable(self):
        p = self.S["enc"]["unknown"]
        if p is None:
            self.skipTest("7zz missing")
        r = scan(p)
        self.assertIn("Heur:Archive.Encrypted", det_names(r))
        self.assertIn("Heur:Archive.EncryptedExecutable", det_names(r))
        self.assertNotIn("setup.exe", members(r))

    def test_dmg(self):
        p = self.S["dmg"]
        if p is None:
            self.skipTest("hdiutil missing")
        r = scan(p)
        m = members(r)
        self.assertIn("README.txt", m)
        self.assertIn("Test.app/Contents/MacOS/run", m)

    def test_wim(self):
        p = self.S["wim"]
        if p is None:
            self.skipTest("7zz missing")
        self.assertLessEqual({"a.txt", "run.sh"}, members(scan(p)))

    def test_rar_and_cab_fixtures(self):
        # tiny harmless fixtures shipped with Homebrew (7zz cannot create rar/cab itself)
        found = 0
        for n in ("container.rar", "container.cab"):
            p = BREW_FIXTURES / n
            if p.exists() and SEVENZ:
                found += 1
                self.assertIn("container", members(scan(p)), n)
        if not found:
            self.skipTest("no rar/cab fixtures available")

    def test_iso(self):
        p = self.S["iso"]
        if p is None or not SEVENZ:
            self.skipTest("hdiutil/7zz missing")
        r = scan(p)
        self.assertLessEqual({"README.TXT", "docs/run.sh"}, members(r))

    def test_pkg_component_scripts_and_payload(self):
        p = self.S["pkg"]["component"]
        if p is None:
            self.skipTest("pkgbuild missing")
        r = scan(p)
        m = members(r)
        self.assertIn("Scripts>>postinstall", m)
        self.assertIn("Scripts>>preinstall", m)
        self.assertIn("Payload>>usr/local/share/cerber/data.txt", m)
        self.assertTrue(r.meta["archive"]["pkg"]["has_scripts"])

    def test_pkg_product_distribution(self):
        p = self.S["pkg"]["product"]
        if p is None:
            self.skipTest("productbuild missing")
        r = scan(p)
        m = members(r)
        self.assertIn("Distribution", m)
        self.assertIn("component.pkg/Scripts>>postinstall", m)
        self.assertNotIn("Heur:PKG.InstallerJS.SystemRun", det_names(r))

    def test_pkg_installerjs_system_run(self):
        p = self.S["pkg"]["installerjs"]
        if p is None:
            self.skipTest("xar missing")
        r = scan(p)
        self.assertIn("Heur:PKG.InstallerJS.SystemRun", det_names(r))

    def test_cpio(self):
        for fmt, p in self.S["cpio"].items():
            r = scan(p)
            self.assertLessEqual({"etc/config.txt", "bin/tool.sh"}, members(r), fmt)

    def test_pbzx_payload(self):
        r = scan(self.S["pbzx"])
        self.assertLessEqual({"Applications/Test.app/Contents/Info.txt", "scripts/postinstall"}, members(r))

    def test_deb(self):
        r = scan(self.S["deb"])
        m = members(r)
        self.assertIn("control.tar.gz>>postinst", m)
        self.assertIn("data.tar.xz>>usr/share/cerber/data.txt", m)

    def test_rpm(self):
        r = scan(self.S["rpm"])
        m = members(r)
        self.assertIn("scripts/%post", m)
        self.assertTrue(any(x.endswith("usr/share/cerber/data.txt") for x in m), m)

    def test_streams(self):
        S = self.S["streams"]
        for key in ("tar", "tar.xz", "tar.bz2"):
            self.assertLessEqual({"dir/a.txt", "dir/run.sh"}, members(scan(S[key])), key)
        for key in ("gz", "bz2", "xz", "zst", "lz4", "lz"):
            if key not in S:
                continue
            r = scan(S[key])
            self.assertEqual(len(r.children), 1 if key != "lz4" else 1, (key, r.errors))
            self.assertIn(b"echo harmless", r.children[0].data, key)
        r = scan(S["lz4"])
        self.assertEqual(r.children[0].data[:13], b"abcdabcdabcdh"[:13])

    def test_gzip_trailing_data(self):
        r = scan(self.S["streams"]["gz_trailing"])
        self.assertIn("Heur:Archive.TrailingData", det_names(r))
        self.assertIn("trailing-data", members(r))

    def test_sfx_exe(self):
        r = scan(self.S["sfx"]["zip"])
        self.assertLessEqual({"payload/run.bat", "payload/data.txt"}, members(r))

    def test_crx(self):
        r = scan(self.S["crx"])
        self.assertLessEqual({"manifest.json", "background.js"}, members(r))
        self.assertEqual(r.meta["archive"]["crx_version"], 3)

    # -- names / structure ----------------------------------------------------
    def test_path_traversal(self):
        r = scan(self.S["names"]["traversal"])
        self.assertIn("Heur:Archive.PathTraversal", det_names(r))
        self.assertIn("Heur:Archive.AbsolutePath", det_names(r))
        self.assertIn("ok/fine.txt", members(r))

    def test_rtlo(self):
        r = scan(self.S["names"]["rtlo"])
        self.assertIn("Heur:Archive.RTLOName", det_names(r))
        ev = dets(r, "Heur:Archive.RTLOName")[0].evidence[0]
        self.assertIn("\\u202e", ev)

    def test_double_extension(self):
        r = scan(self.S["names"]["doubleext"])
        d = dets(r, "Heur:Archive.DoubleExtension")
        self.assertTrue(d)
        ev = " ".join(d[0].evidence)
        self.assertIn("invoice.pdf.exe", ev)
        self.assertIn("photo.jpg.app", ev)
        self.assertIn("scan.doc.js", ev)

    def test_broken_central_directory_carved(self):
        r = scan(self.S["damaged"]["nocd"])
        self.assertLessEqual({"a.txt", "sub/b.sh", "c.bin"}, members(r))
        self.assertIn("Heur:Archive.Malformed", det_names(r))

    def test_hidden_entries(self):
        r = scan(self.S["damaged"]["hidden"])
        self.assertIn("hidden/evil.sh", members(r))
        self.assertIn("a.txt", members(r))
        self.assertIn("Heur:Archive.HiddenEntries", det_names(r))

    def test_bad_crc_recovered(self):
        r = scan(self.S["damaged"]["badcrc"])
        self.assertIn("crc.txt", members(r))
        self.assertIn("Heur:Archive.BadCRC", det_names(r))

    def test_symlink_escape_then_write(self):
        r = scan(self.S["symtar"])
        self.assertIn("Heur:Archive.SymlinkTraversal", det_names(r))

    # -- e-mail ---------------------------------------------------------------
    def test_email_zip_attachment(self):
        r = scan(self.S["email"]["zip"])
        m = members(r)
        self.assertIn("invoice.zip", m)
        self.assertIn("invoice.zip>>docs/invoice.pdf.exe", m)
        self.assertTrue(any(x.startswith("body-") for x in m))
        n = det_names(r)
        self.assertIn("Heur:Email.ExecutableAttachment", n)       # statement.pdf.scr
        self.assertIn("Heur:Email.DoubleExtension", n)
        self.assertIn("Heur:Email.ArchivedExecutable", n)
        self.assertIn("Heur:Archive.DoubleExtension", n)          # from the attachment's own members
        self.assertEqual(r.meta["email"]["subject"], "Invoice")

    def test_email_password_hint(self):
        p = self.S["email"].get("hint")
        if p is None:
            self.skipTest("7zz missing")
        r = scan(p)
        self.assertIn("docs.zip>>secret.txt", members(r))

    def test_mbox(self):
        r = scan(self.S["email"]["mbox"])
        m = members(r)
        self.assertIn("msg1/invoice.zip", m)
        self.assertTrue(any(x.startswith("msg2/") for x in m))

    # -- robustness --------------------------------------------------------------
    def test_deep_nesting(self):
        inner = b"leaf\n"
        for i in range(20):
            inner = _zip_bytes({"L.zip" if i else "leaf.txt": inner})
        r = scan(_w("deep20.zip", inner))
        self.assertIn("Heur:Archive.DeepNesting", det_names(r))

    def test_overlapping_members_flagged(self):
        # 300 central directory entries (same-length names) all pointing at one local header
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("m0000.bin", b"A" * (8 << 20))
        z = bytearray(bio.getvalue())
        cd = z.rfind(b"PK\x01\x02")
        entry = bytes(z[cd:z.rfind(b"PK\x05\x06")])
        n = 300
        newcd = b"".join(entry[:46] + b"m%04d.bin" % i for i in range(n))
        head = bytes(z[:cd])
        eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, n, n, len(newcd), len(head), 0)
        r = scan(_w("overlapping.zip", head + newcd + eocd))
        self.assertIn("Heur:Archive.Bomb", det_names(r))

    def test_truncated_7z_is_not_reported_encrypted(self):
        b = self.S["7z"].read_bytes() if self.S["7z"] else None
        if b is None:
            self.skipTest("py7zr missing")
        r = scan(_w("truncated.7z", b[: len(b) // 2]))
        self.assertNotIn("Heur:Archive.Encrypted", det_names(r))

    def test_py7zr_fallback_without_7zz(self):
        if self.S["7z"] is None:
            self.skipTest("py7zr missing")
        tools = {k: v for k, v in default_tools().items() if k != "7z"}
        pipe = Pipeline(analyzers=[a for a in load_all() if a.name == "archives"], options={"deep": True, "tools": tools})
        r = pipe.scan_file(str(self.S["7z"]))
        self.assertLessEqual({"docs/readme.txt", "bin/run.sh"}, members(r))

    def test_hdiutil_fallback_without_7zz(self):
        if self.S["dmg"] is None:
            self.skipTest("hdiutil missing")
        tools = {k: v for k, v in default_tools().items() if k != "7z"}
        pipe = Pipeline(analyzers=[a for a in load_all() if a.name == "archives"], options={"deep": True, "tools": tools})
        r = pipe.scan_file(str(self.S["dmg"]))
        self.assertIn("README.txt", members(r))
        self.assertEqual(r.meta["archive"].get("tool"), "hdiutil")
        mounted = subprocess.run(["mount"], capture_output=True, text=True).stdout
        # noexec workspaces of scans running at the same time (cerber-sandbox-*) are not ours
        leftovers = [ln for ln in mounted.splitlines() if "cerber-" in ln and "cerber-sandbox-" not in ln]
        self.assertEqual(leftovers, [])

    def test_script_with_appended_archive(self):
        tar = io.BytesIO()
        with tarfile.open(fileobj=tar, mode="w:gz") as tf:
            d = b"echo installed\n"
            ti = tarfile.TarInfo("install.sh")
            ti.size = len(d)
            tf.addfile(ti, io.BytesIO(d))
        script = b"#!/bin/sh\nSKIP=12\ntail -n +$SKIP $0 | tar xz\nexit 0\n" + b"# padding\n" * 300 + b"\n" + tar.getvalue()
        r = scan(_w("makeself_like.run", script))
        self.assertTrue(any(x.endswith(">>install.sh") for x in members(r)), members(r))

    def test_plain_text_starting_with_from_is_not_an_email(self):
        r = scan(_w("from.txt", b"From now on we will meet on Mondays.\nSee you there.\n" * 5))
        self.assertEqual(r.children, [])

    # -- bombs ----------------------------------------------------------------
    def test_zip_bomb(self):
        b = build_bombs()
        t0 = time.monotonic()
        r = scan(b["zip"])
        dt = time.monotonic() - t0
        self.assertIn("Heur:Archive.Bomb", det_names(r))
        self.assertLess(dt, 5.0, f"bomb scan took {dt:.1f}s")
        self.assertEqual(r.children, [])
        print(f"\n[bomb] 2 GB zip: {dt:.3f}s")

    def test_gzip_bomb(self):
        b = build_bombs()
        t0 = time.monotonic()
        r = scan(b["gz"])
        dt = time.monotonic() - t0
        self.assertIn("Heur:Archive.Bomb", det_names(r))
        self.assertLess(dt, 8.0, f"bomb scan took {dt:.1f}s")
        self.assertLessEqual(sum(c.size for c in r.children), 64 << 20)
        print(f"\n[bomb] 2 GB gzip: {dt:.3f}s")

    def test_many_members_bomb(self):
        b = build_bombs()
        t0 = time.monotonic()
        r = scan(b["many"])
        dt = time.monotonic() - t0
        self.assertIn("Heur:Archive.Bomb", det_names(r))
        self.assertLess(dt, 30.0)
        print(f"\n[bomb] 40x48MB zip: {dt:.3f}s, children={len(r.children)}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--build":
        s = build_all()
        build_bombs()
        print("built samples in", SAMPLES)
    else:
        unittest.main(verbosity=2)
