"""Safe benchmark: how well Cerber does on HARMLESS test material only (no real malware anywhere).

Three parts, each with its own score:

1. AMTSO "Security Features Check" (amtso.org/security-features-check) – the desktop test files the
   Anti-Malware Testing Standards Organization publishes so anyone can check that a product's protection
   works: EICAR download, compressed EICAR (zip, zipx, self-extracting .exe), the PUA test application and
   the "CloudCar" cloud-lookup test file. Plus the four official files from eicar.org. All harmless by
   design. `fetch` downloads them once (pinned SHA-256) into safe_samples/official/ (git-ignored).

2. EICAR container matrix – the 68-byte EICAR test file wrapped in every container format a Mac user meets
   (zip/zipx/7z, encrypted with the usual "infected" password or a year, nested up to 8 levels, tar/gz/bz2/xz/zst/lz4/
   Z, cpio, ar/deb, xar, .pkg, .dmg in 5 formats, .iso, Office/ODF/EPUB/JAR/CRX/ASAR/NuGet, e-mail
   attachments, mbox, PDF attachment, app bundle …). Tests what test labs call "archive scanning": the file
   is only found if every layer is opened. Each container also gets a harmless twin (a text file holding a
   near-miss string, one byte changed) that must stay CLEAN or at most INFO.

3. Published-hash coverage – SHA-256 values of macOS malware printed in Objective-See's yearly
   "The Mac Malware of 20XX" reports (2019–2024). Only looked up in the local hash database – nothing is
   downloaded. Our hash feeds (MalwareBazaar, ClamAV, macOS feeds) are independent of these reports; the
   number says how many of the year's notable Mac threats are known by hash, nothing more.

4. Family coverage – every macOS malware family named in those reports (2019–2025, ~90 families): does
   Cerber carry a signature NAMED after it (YARA rule / ClamAV signature) or at least known samples (hash
   labels)? Measured on the rule names only, no samples. A named rule is not proof it catches every variant.

What this does NOT measure: detection of new, real-world malware (AV-TEST, AV-Comparatives use hundreds of
live samples). EICAR/AMTSO verify that the machinery works end to end – they are not a protection score.

    .venv/bin/python tests/benchmark/safe_bench.py fetch
    .venv/bin/python tests/benchmark/safe_bench.py run [--label NAME] [--only official|matrix|hashes|families]
"""
from __future__ import annotations

import argparse
import base64
import gzip
import bz2
import hashlib
import io
import json
import lzma
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, ROOT)

SAFE = os.path.join(HERE, "safe_samples")
OFFICIAL = os.path.join(SAFE, "official")
MATRIX = os.path.join(SAFE, "matrix")
RESULTS = os.path.join(HERE, "safe_results")

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
NEAR_MISS = EICAR.replace(b"EICAR-STANDARD", b"EICAR-STANDARX")    # must never be detected

# name, url, sha256, size, expectation ("malicious" = detected as malware/test file, "pua" = PUA or worse,
# "detected" = anything SUSPICIOUS or worse)
OFFICIAL_FILES = [
    ("eicar.org eicar.com", "https://secure.eicar.org/eicar.com",
     "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", 68, "malicious"),
    ("eicar.org eicar.com.txt", "https://secure.eicar.org/eicar.com.txt",
     "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", 68, "malicious"),
    ("eicar.org eicar_com.zip", "https://secure.eicar.org/eicar_com.zip",
     "2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad", 184, "malicious"),
    ("eicar.org eicar_com2.zip (zip in zip)", "https://secure.eicar.org/eicar_com2.zip",
     "e1105070ba828007508566e28a2b8d4c65d192e9eaf3b7868382b7cae747b397", 308, "malicious"),
    ("AMTSO download of malware (eicar.com)", "https://amtso.eicar.org/eicar.com",
     "e038b5168d9209267058112d845341cae83d92b1d1af0a10b66830acb7529494", 70, "malicious"),
    ("AMTSO compressed malware (eicar.zip)", "https://amtso.eicar.org/eicar.zip",
     "2fc33157dbc43f84d3c26a0e4abd4e41fc0d1764b07c90017888e2317564f891", 224, "malicious"),
    ("AMTSO compressed malware (eicar.zipx)", "https://amtso.eicar.org/eicar.zipx",
     "4a9e14e9693f1e07c4af27b20ad51acb12d1c89b833e856fd7e3391c167890cd", 222, "malicious"),
    ("AMTSO compressed malware (eicar.exe, self-extracting)", "https://amtso.eicar.org/eicar.exe",
     "35b6773084a21f123f70ef6749b43d1b6027c575ef8c3dd1ffb371e73d7b5e4b", 301199, "malicious"),
    ("AMTSO compressed malware (eicar_zip.exe, self-extracting)", "https://amtso.eicar.org/eicar_zip.exe",
     "6fb13d2e1d39ca9944ef05a2d188539b5645f6a23a07b6e3435d69d5b6326ed0", 254176, "malicious"),
    ("AMTSO potentially unwanted application", "https://amtso.eicar.org/PotentiallyUnwanted.exe",
     "42d6581dd0a2ba9bec6a40c5b7c85870a8019d7347c9130d24752ec5865f0732", 33282, "pua"),
    ("AMTSO cloud lookup (CloudCar)", "https://amtso.eicar.org/cloudcar.exe",
     "9f83b17ea375c8ecd4b2b992ae90b15f3d7655c575ef31f6c323bf07bbe1c1eb", 7180, "detected"),
]

# Objective-See, "The Mac Malware of 20XX" (objective-see.org/blog): every SHA-256 printed in the reports.
OBJECTIVE_SEE_HASHES = [
    (2019, "Siggen (HEYgiNb.py)", "f5808e9b9d204f646e33bbc4279b98b97b34086ffc3e9fb2ac828a8161099ee8"),
    (2019, "NewTab", "9237dc996a9e2c939f74414c87350009f11b147f1703823062f790921be30be9"),
    (2020, "watchcat (NukeSpeed)", "3bb96bfaf492782b38985f4bd6b7e7f9dc22c1332b42bb74b16041298fd31f93"),
    (2022, "SysJoker", "1a9a5c797777f37463b44de2b49a7f95abca786db3977dcdac0f79da739c08ac"),
    (2022, "SysJoker", "fe99db3268e058e1204aff679e0726dc77fd45d06757a5fda9eafc6a28cfb8df"),
    (2022, "SysJoker", "d0febda3a3d2d68b0374c26784198dc4309dbe4a8978e44bb7584fd832c325f0"),
    (2022, "DazzleSpy", "f9ad42a9bd9ade188e997845cae1b0587bf496a35c3bffacd20fefe07860a348"),
    (2022, "CoinMiner", "fe3700a52e86e250a9f38b7a5a48397196e7832fd848a7da3cc02fe52f49cdcf"),
    (2022, "CoinMiner", "fabe0b41fb5bce6bda8812197ffd74571fc9e8a5a51767bcceef37458e809c5c"),
    (2022, "CoinMiner", "a2909754783bb5c4fd6955bcebc356e9d6eda94f298ed3e66c7e13511275fbc4"),
    (2022, "Gimmick", "2a9296ac999e78f6c0bee8aca8bfa4d4638aa30d9c8ccc65124b1cbfc9caab5f"),
    (2022, "oRAT", "ee07dfd6443af8f20f5f11effb9cbcec07e125697a28aee78718caeed17f1407"),
    (2022, "Pymafka", "b117f042fe9bac7c7d39eab98891c2465ef45612f5355beea8d3c4ebd0665b45"),
    (2022, "VPN Trojan (Covid)", "7831806172857a563d7b4789acddc98fc11763aaf3cedf937630b4a9dce31419"),
    (2022, "VPN Trojan (Covid)", "d9bba1cfca6b1d20355ce08eda37d6d0bca8cb8141073b699000d05025510dcc"),
    (2022, "CloudMensis", "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"),
    (2022, "CloudMensis", "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"),
    (2022, "rShell", "3a9e72b3810b320fa6826a1273732fee7a8e2b2e5c0fd95b8c36bbab970e830a"),
    (2022, "rShell", "8c3be245cbbe9206a5d146017c14b8f965ab7045268033d70811d5bcc4b796ec"),
    (2022, "Insekt (exploit)", "ef130f1941077ffe383fe90e241620dde771cd0dd496dad29d2048d5fc478faf"),
    (2022, "Insekt (payload.so)", "ae9f370c89f0191492ed9c17a224d9c41778b47ca2768f732b4de6ee7d0d1459"),
    (2022, "KeySteal (ResignTool)", "410da3923ea30d5fdd69b9ae69716b094d276cc609f76590369ff254f71c65da"),
    (2022, "KeySteal", "f5b4a388fee4183dfa46908000c5c50dceb4bf8025c4cfcb4d478c5d03833202"),
    (2023, "LockBit macOS", "3e4bbd21756ae30c24ff7d6942656be024139f8180b7bddd4e5c62a9dfbd8c79"),
    (2023, "GoSorry (archive)", "c80c8c0e961e1692c5afdb8b3dd48e84fb6bb24911ad449ef75976cbf5bf1199"),
    (2023, "GoSorry (liboptimizer.dylib)", "17b84ed0f8bdbb6619d64bf686a6b990f497b378e3b70792e2cd896c2abda14d"),
    (2024, "fake MiroTalk.dmg", "9abf6b93eafb797a3556bea1fe8a3b7311d2864d5a9a3687fce84bc1ec4a428c"),
    (2024, "trojanised ultraedit.dmg", "9eb7bda5ffbb1a7549b1e481b1a6ed6efe2e28d0463370c87630fed74eee6228"),
    (2024, "libConfigurer64.dylib (ultraedit)", "ce40829673687b48d68defa3176c8ab59a2a50ee9c658fe46a5de7692fbc112d"),
    (2024, ".fseventsd (ultraedit)", "1b2d50cdacfd39205c3caff2925eb35b59312dbe099bd3a98ae3b2f2f909ab17"),
    (2024, "Khepri build (.test)", "21457a89317e4c6b8aaee5e461a6b4e444c736243d550efd0e681eda05b97007"),
    (2024, "vShell (Cloudflare Security Authenticator.dmg)",
     "c5686b85efb3ebf2ce07dba4192195c3dac7c335a371b7bcfbf52d5fb15cb507"),
    (2024, "SNOWLIGHT-like", "d1b7f3d88ed8d37774b229cc46df2c08c95067736cf418b4a76a8403cae4e2a6"),
]

# Families with their own section in Objective-See's "The Mac Malware of 20XX" (section anchors of the reports),
# regex over signature names / descriptions. Generic sections ("unnamed downloader", "coin miner") left out.
# A 4th field True = the name also exists on Windows/Linux: the same signature line must mention macOS.
OBJECTIVE_SEE_FAMILIES = [
    (2019, "BirdMiner / LoudMiner", r"bird.?miner|loud.?miner"), (2019, "CookieMiner", r"cookie.?miner"),
    (2019, "GMERA", r"gmera"), (2019, "Mokes", r"mokes", True), (2019, "NetWire", r"netwire|netwired", True),
    (2019, "Siggen", r"siggen", True), (2019, "Yort", r"\byort|yort\b|osx\.yort"),
    (2019, "Lazarus MacLoader / AppleJeus", r"apple.?jeus|macloader"),
    (2020, "GravityRAT", r"gravity.?rat", True), (2020, "IPStorm", r"ip.?storm|interplanetary", True), (2020, "Dacls", r"dacls", True),
    (2020, "EvilQuest / ThiefQuest", r"evil.?quest|thief.?quest"), (2020, "FinSpy", r"fin.?spy|finfisher", True),
    (2020, "WatchCat", r"watch.?cat"), (2020, "XCSSET", r"xcsset"),
    (2021, "ElectroRAT", r"electro.?rat"), (2021, "ElectrumStealer", r"electrum.?stealer"),
    (2021, "Macma / CDDS", r"macma|cdds"), (2021, "Silver Sparrow", r"silver.?sparrow"),
    (2021, "XcodeSpy / EggShell", r"xcode.?spy|egg.?shell"), (2021, "ZuRu", r"zuru"),
    (2021, "WildPressure (Milum)", r"wild.?pressure|milum"), (2021, "XLoader", r"xloader|formbook", True),
    (2022, "CloudMensis", r"cloud.?mensis"), (2022, "CrateDepression", r"crate.?depression"),
    (2022, "DazzleSpy", r"dazzle.?spy"), (2022, "Gimmick", r"gimmick", True), (2022, "Insekt", r"insekt", True),
    (2022, "KeySteal", r"key.?steal"), (2022, "oRAT", r"\borat\b", True), (2022, "Pymafka", r"pymafka"),
    (2022, "rShell", r"\brshell\b", True), (2022, "SentinelSneak", r"sentinel.?sneak"), (2022, "SysJoker", r"sys.?joker"),
    (2022, "VPN Trojan (Covid)", r"covid|vpn.?trojan", True),
    (2023, "SmoothOperator (3CX)", r"smooth.?operator|3cx"), (2023, "Atomic Stealer (AMOS)", r"atomic|\bamos|amos_|_amos"),
    (2023, "Geacon", r"geacon", True), (2023, "GoSorry", r"go.?sorry"), (2023, "JaskaGO", r"jaska.?go"),
    (2023, "JokerSpy", r"joker.?spy"), (2023, "KandyKorn", r"kandy.?korn"), (2023, "LockBit (macOS)", r"lockbit", True),
    (2023, "MacStealer", r"mac.?stealer"), (2023, "MetaStealer", r"meta.?stealer", True), (2023, "NokNok", r"nok.?nok", True),
    (2023, "ObjCShellz", r"objc.?shellz"), (2023, "PureLand", r"pure.?land", True), (2023, "Realst", r"realst", True),
    (2023, "RustBucket", r"rust.?bucket"), (2023, "SparkRAT", r"spark.?rat", True), (2023, "Turtle", r"turtle", True),
    (2023, "WSClient", r"ws.?client", True),
    (2024, "Activator", r"activator", True), (2024, "Banshee", r"banshee"), (2024, "BeaverTail", r"beaver.?tail"),
    (2024, "CloudChat", r"cloud.?chat", True), (2024, "Cthulhu", r"cthulhu"), (2024, "Hidden Risk", r"hidden.?risk"),
    (2024, "HZ Rat", r"hz.?rat", True), (2024, "InletDrift", r"inlet.?drift"), (2024, "LightSpy", r"light.?spy"),
    (2024, "NotLockBit", r"not.?lockbit"), (2024, "Poseidon", r"poseidon|rodrigo", True), (2024, "PyStealer", r"py.?stealer", True),
    (2024, "RustDoor", r"rust.?door"), (2024, "RustyAttr", r"rusty.?attr"), (2024, "SnowLight", r"snow.?light"),
    (2024, "SpectralBlur", r"spectral.?blur"), (2024, "ToDoSwift", r"to.?do.?swift"), (2024, "VShell", r"\bvshell\b", True),
    (2025, "ChillyHell", r"chilly.?hell"), (2025, "DigitStealer", r"digit.?stealer", True),
    (2025, "FlexibleFerret", r"flexible.?ferret"), (2025, "Frigid Stealer", r"frigid", True), (2025, "Kitty Stealer", r"kitty.?stealer", True),
    (2025, "Koi Stealer", r"\bkoi.?stealer", True), (2025, "MacSync", r"mac.?sync"), (2025, "NightPaw", r"night.?paw", True),
    (2025, "Paradox", r"paradox", True), (2025, "PasivRobber", r"pasiv.?robber"), (2025, "Phexia", r"phexia", True),
    (2025, "RN Loader / RN Stealer", r"\brn.?(loader|stealer)", True),
]

VERDICTS = ["CLEAN", "INFO", "SUSPICIOUS", "PUA", "MALICIOUS"]


def _ok(expect: str, verdict: str) -> bool:
    i = VERDICTS.index(verdict)
    return {"malicious": verdict == "MALICIOUS",
            "pua": i >= VERDICTS.index("PUA"),
            "detected": i >= VERDICTS.index("SUSPICIOUS"),
            "clean": verdict in ("CLEAN", "INFO")}[expect]


# ------------------------------------------------------------------ part 1: official test files

def fetch() -> int:
    os.makedirs(OFFICIAL, exist_ok=True)
    bad = 0
    for name, url, sha, size, _ in OFFICIAL_FILES:
        dest = os.path.join(OFFICIAL, url.split("//", 1)[1].split("/", 1)[0].split(".")[0] + "_" + url.rsplit("/", 1)[1])
        if os.path.exists(dest) and hashlib.sha256(open(dest, "rb").read()).hexdigest() == sha:
            continue
        req = urllib.request.Request(url, headers={"User-Agent": "Cerber-AV/1.0 (+local defensive scanner)"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read(2 << 20)
        got = hashlib.sha256(data).hexdigest()
        if got != sha or len(data) != size:
            print(f"  ZŁY SKRÓT {name}: {got} ({len(data)} B) – plik pominięty")
            bad += 1
            continue
        with open(dest, "wb") as fh:
            fh.write(data)
        print(f"  pobrano {name} ({size} B)")
    return bad


def official_items() -> list[dict]:
    out = []
    for name, url, sha, size, expect in OFFICIAL_FILES:
        p = os.path.join(OFFICIAL, url.split("//", 1)[1].split("/", 1)[0].split(".")[0] + "_" + url.rsplit("/", 1)[1])
        if os.path.exists(p):
            out.append({"name": name, "path": p, "expect": expect})
    return out


# ------------------------------------------------------------------ part 2: EICAR container matrix

def _zip(entries: list[tuple[str, bytes]], method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as z:
        for n, d in entries:
            z.writestr(n, d)
    return buf.getvalue()


def _tar(entries: list[tuple[str, bytes]], mode: str = "w") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as t:
        for n, d in entries:
            ti = tarfile.TarInfo(n)
            ti.size, ti.mtime = len(d), 1700000000
            t.addfile(ti, io.BytesIO(d))
    return buf.getvalue()


def _run(cmd: list[str], cwd: str | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, timeout=120)


def _cpio_newc(name: str, data: bytes) -> bytes:
    def hdr(n: bytes, size: int, mode: int, ino: int) -> bytes:
        f = [ino, mode, 0, 0, 1, 1700000000, size, 0, 0, 0, 0, len(n) + 1, 0]
        h = b"070701" + b"".join(b"%08X" % v for v in f) + n + b"\0"
        return h + b"\0" * (-len(h) % 4)
    out = hdr(name.encode(), len(data), 0o100644, 1) + data + b"\0" * (-len(data) % 4)
    out += hdr(b"TRAILER!!!", 0, 0, 0)
    return out


def _ar(name: str, data: bytes) -> bytes:
    h = f"{name[:15] + '/':<16}{1700000000:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n".encode()
    return b"!<arch>\n" + h + data + (b"\n" if len(data) % 2 else b"")


def _eml(attach_name: str, payload: bytes, ctype: str = "application/octet-stream") -> bytes:
    b64 = base64.encodebytes(payload).decode()
    return (f"From: test@example.invalid\nTo: you@example.invalid\nSubject: test\nMIME-Version: 1.0\n"
            f"Content-Type: multipart/mixed; boundary=\"XX\"\n\n--XX\nContent-Type: text/plain\n\nhello\n"
            f"--XX\nContent-Type: {ctype}; name=\"{attach_name}\"\nContent-Transfer-Encoding: base64\n"
            f"Content-Disposition: attachment; filename=\"{attach_name}\"\n\n{b64}--XX--\n").encode()


def _pdf_attachment(payload: bytes, name: str = "eicar.com") -> bytes:
    stream = zlib.compress(payload)
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 4 0 R >> >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        b"<< /Names [(" + name.encode() + b") 5 0 R] >>",
        b"<< /Type /Filespec /F (" + name.encode() + b") /EF << /F 6 0 R >> >>",
        b"<< /Type /EmbeddedFile /Filter /FlateDecode /Length " + str(len(stream)).encode() + b" >>\nstream\n"
        + stream + b"\nendstream",
    ]
    out, offs = b"%PDF-1.7\n", []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offs)
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return out


def _asar(name: str, data: bytes) -> bytes:
    header = json.dumps({"files": {name: {"size": len(data), "offset": "0"}}}).encode()
    pickled = len(header).to_bytes(4, "little") + header
    pad = b"\0" * (-len(pickled) % 4)
    inner = len(pickled) + len(pad)
    outer = (4).to_bytes(4, "little") + (inner + 4).to_bytes(4, "little") + inner.to_bytes(4, "little")
    return outer + pickled + pad + data


def build_matrix(payload: bytes, out: str, member: str = "eicar.com") -> list[tuple[str, str]]:
    """Writes one file (or bundle dir) per container format into `out`; returns [(format, path)]."""
    M = member
    os.makedirs(out, exist_ok=True)
    made: list[tuple[str, str]] = []
    have_7z = shutil.which("7zz") or shutil.which("7z")

    def put(fmt: str, name: str, data: bytes) -> None:
        p = os.path.join(out, name)
        with open(p, "wb") as fh:
            fh.write(data)
        made.append((fmt, p))

    def tool(fmt: str, name: str, fn) -> None:
        p = os.path.join(out, name)
        try:
            fn(p)
            made.append((fmt, p))
        except (subprocess.SubprocessError, OSError) as exc:
            print(f"  pominięto {fmt}: {exc}")

    put("plain .com", "eicar.com", payload)
    put("plain + CRLF (AMTSO style)", "eicar_crlf.com", payload + b"\r\n")
    put("plain .txt", "eicar.txt", payload)
    put("plain, no extension", "eicar", payload)
    put("zip (deflate)", "eicar.zip", _zip([(M, payload)]))
    put("zip (stored)", "eicar_stored.zip", _zip([(M, payload)], zipfile.ZIP_STORED))
    put("zip (bzip2)", "eicar_bz2.zip", _zip([(M, payload)], zipfile.ZIP_BZIP2))
    put("zip (lzma)", "eicar_lzma.zip", _zip([(M, payload)], zipfile.ZIP_LZMA))
    put("zip in folder inside zip", "eicar_dir.zip", _zip([("a/b/c/readme.txt", b"hi"), ("a/b/c/" + M, payload)]))
    nested = _zip([(M, payload)])
    for depth in range(2, 9):
        nested = _zip([(f"level{depth - 1}.zip", nested)])
        if depth in (2, 3, 5, 8):
            put(f"zip nested {depth}×", f"eicar_nested{depth}.zip", nested)
    put("gzip", "eicar.com.gz", gzip.compress(payload))
    put("bzip2", "eicar.com.bz2", bz2.compress(payload))
    put("xz", "eicar.com.xz", lzma.compress(payload))
    put("lzma (alone)", "eicar.com.lzma", lzma.compress(payload, format=lzma.FORMAT_ALONE))
    put("tar", "eicar.tar", _tar([(M, payload)]))
    put("tar.gz", "eicar.tar.gz", _tar([("x/" + M, payload)], "w:gz"))
    put("tar.bz2", "eicar.tar.bz2", _tar([("x/" + M, payload)], "w:bz2"))
    put("tar.xz", "eicar.tar.xz", _tar([("x/" + M, payload)], "w:xz"))
    put("cpio (newc)", "eicar.cpio", _cpio_newc(M, payload))
    put("ar", "eicar.a", _ar(M, payload))
    put("deb (ar + tar.gz)", "eicar.deb", b"!<arch>\n" + _ar("debian-binary", b"2.0\n")[8:]
        + _ar("data.tar.gz", _tar([("./usr/share/" + M, payload)], "w:gz"))[8:])
    put("jar", "eicar.jar", _zip([("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"), (M, payload)]))
    put("docx (OOXML part)", "eicar.docx", _zip([("[Content_Types].xml", b"<Types/>"), ("word/document.xml", b"<w/>"),
                                                 ("word/embeddings/" + M, payload)]))
    put("xlsx (OOXML part)", "eicar.xlsx", _zip([("[Content_Types].xml", b"<Types/>"), ("xl/workbook.xml", b"<w/>"),
                                                 ("xl/embeddings/" + M, payload)]))
    put("odt (ODF)", "eicar.odt", _zip([("mimetype", b"application/vnd.oasis.opendocument.text"),
                                         ("Pictures/" + M, payload)], zipfile.ZIP_STORED))
    put("epub", "eicar.epub", _zip([("mimetype", b"application/epub+zip"), ("OEBPS/" + M, payload)]))
    put("crx (Chrome extension)", "eicar.crx", b"Cr24" + (3).to_bytes(4, "little") + (0).to_bytes(4, "little")
        + _zip([("manifest.json", b"{}"), (M, payload)]))
    put("nupkg", "eicar.nupkg", _zip([("lib/" + M, payload)]))
    put("asar (Electron)", "eicar.asar", _asar(M, payload))
    put("e-mail attachment (base64)", "eicar.eml", _eml(M, payload))
    put("e-mail with zip attachment", "eicar_zip.eml", _eml("eicar.zip", _zip([(M, payload)]),
                                                             "application/zip"))
    put("mbox", "eicar.mbox", b"From test@example.invalid Mon Jan  1 00:00:00 2024\n" + _eml(M, payload))
    put("PDF attachment (FlateDecode)", "eicar.pdf", _pdf_attachment(payload, M))
    put("base64 file", "eicar.b64", base64.b64encode(payload) + b"\n")

    tmp = tempfile.mkdtemp(prefix="cerber-safe-")
    try:
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        with open(os.path.join(src, M), "wb") as fh:
            fh.write(payload)
        if shutil.which("compress"):
            def _z(p):
                with open(os.path.join(tmp, "eicar.com"), "wb") as fh:
                    fh.write(payload)
                _run(["compress", "-f", os.path.join(tmp, "eicar.com")])
                shutil.move(os.path.join(tmp, "eicar.com.Z"), p)
            tool("Unix compress (.Z)", "eicar.com.Z", _z)
        if shutil.which("zstd"):
            tool("zstd", "eicar.com.zst", lambda p: _run(["zstd", "-q", "-f", os.path.join(src, M), "-o", p]))
            tool("tar.zst", "eicar.tar.zst",
                 lambda p: _run(["tar", "--zstd", "-cf", p, "-C", src, M]))
        if shutil.which("lz4"):
            tool("lz4", "eicar.com.lz4", lambda p: _run(["lz4", "-q", "-f", os.path.join(src, M), p]))
        if have_7z:
            tool("7z", "eicar.7z", lambda p: _run([have_7z, "a", "-bd", "-y", p, os.path.join(src, M)]))
            tool("7z, password 'infected', names encrypted", "eicar_pw.7z",
                 lambda p: _run([have_7z, "a", "-bd", "-y", "-pinfected", "-mhe=on", p, os.path.join(src, M)]))
            tool("zip, password 'infected' (ZipCrypto)", "eicar_pw.zip",
                 lambda p: _run([have_7z, "a", "-tzip", "-bd", "-y", "-pinfected", "-mem=ZipCrypto", p,
                                 os.path.join(src, M)]))
            tool("zip, password 'infected' (AES-256)", "eicar_pw_aes.zip",
                 lambda p: _run([have_7z, "a", "-tzip", "-bd", "-y", "-pinfected", "-mem=AES256", p,
                                 os.path.join(src, M)]))
            tool("zip, password a year (2024)", "eicar_pw_num.zip",
                 lambda p: _run([have_7z, "a", "-tzip", "-bd", "-y", "-p2024", "-mem=AES256", p,
                                 os.path.join(src, M)]))
        if shutil.which("xar"):
            tool("xar", "eicar.xar", lambda p: _run(["xar", "-cf", p, M], cwd=src))
        if shutil.which("pkgbuild"):
            tool("macOS .pkg (pkgbuild)", "eicar.pkg",
                 lambda p: _run(["pkgbuild", "--root", src, "--identifier", "org.example.safebench",
                                 "--version", "1", "--install-location", "/tmp/safebench", p]))
        if shutil.which("hdiutil"):
            for fmt in ("UDZO", "UDBZ", "ULFO", "ULMO", "UDRO"):
                tool(f"DMG {fmt}", f"eicar_{fmt.lower()}.dmg",
                     lambda p, fmt=fmt: _run(["hdiutil", "create", "-quiet", "-fs", "HFS+", "-volname", "SafeBench",
                                              "-srcfolder", src, "-format", fmt, "-ov", p]))
            tool("ISO 9660", "eicar.iso",
                 lambda p: (_run(["hdiutil", "makehybrid", "-quiet", "-iso", "-joliet", "-o", p, src])))
            zdir = os.path.join(tmp, "zsrc")
            os.makedirs(zdir)
            with open(os.path.join(zdir, "eicar.zip"), "wb") as fh:
                fh.write(_zip([(M, payload)]))
            tool("zip inside DMG", "eicar_zip_in.dmg",
                 lambda p: _run(["hdiutil", "create", "-quiet", "-fs", "HFS+", "-volname", "SafeBench",
                                 "-srcfolder", zdir, "-format", "UDZO", "-ov", p]))
        # an app bundle (scanned as a folder)
        app = os.path.join(out, "SafeBench.app")
        os.makedirs(os.path.join(app, "Contents", "Resources"), exist_ok=True)
        with open(os.path.join(app, "Contents", "Resources", M), "wb") as fh:
            fh.write(payload)
        made.append(("app bundle (Contents/Resources)", app))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # DMG inside zip (built from the DMG above)
    udzo = os.path.join(out, "eicar_udzo.dmg")
    if os.path.exists(udzo):
        put("DMG inside zip", "eicar_dmg_in.zip", _zip([("Installer.dmg", open(udzo, "rb").read())],
                                                       zipfile.ZIP_STORED))
    return made


# ------------------------------------------------------------------ scanning

_BUNDLE: list = []


def scan(paths: list[str], log) -> dict[str, dict]:
    from cerber.scanner import ScanOptions, load_engines, scan_paths
    opts = ScanOptions(deep=True, level="deep", workers=4)
    if not _BUNDLE:
        _BUNDLE.append(load_engines(opts, lambda m: None))
    rep = scan_paths(paths, opts, log=lambda m: None, engines_bundle=_BUNDLE[0], progress=False)
    out = {}
    for r in rep["results"]:
        out[r["path"]] = r
    return out


def verdict_for(target: str, res: dict[str, dict]) -> tuple[str, list[str]]:
    """A folder (app bundle) counts as its worst file."""
    if os.path.isdir(target):
        hits = [r for p, r in res.items() if p.startswith(target + os.sep)]
        if not hits:
            return "CLEAN", []
        r = max(hits, key=lambda r: VERDICTS.index(r["verdict"]))
    else:
        r = res.get(target) or res.get(os.path.realpath(target))
        if r is None:
            return "CLEAN", []
    return r["verdict"], sorted({d.get("name", "") for d in r.get("detections", [])})[:4]


def run(label: str, only: str | None) -> int:
    os.makedirs(RESULTS, exist_ok=True)
    summary: dict = {"label": label, "date": time.strftime("%Y-%m-%d %H:%M"), "parts": {}}
    t0 = time.time()
    failed = 0

    if only in (None, "official"):
        items = official_items()
        if len(items) < len(OFFICIAL_FILES):
            print(f"Brak części plików AMTSO/EICAR ({len(items)}/{len(OFFICIAL_FILES)}) – uruchom `fetch`.")
        res = scan([i["path"] for i in items], print)
        rows = []
        for it in items:
            v, names = verdict_for(it["path"], res)
            ok = _ok(it["expect"], v)
            failed += not ok
            rows.append({"name": it["name"], "expect": it["expect"], "verdict": v, "ok": ok, "detections": names})
        summary["parts"]["official"] = {"passed": sum(r["ok"] for r in rows), "total": len(rows), "rows": rows}
        _print_part("1. AMTSO Security Features Check + eicar.org", rows)

    if only in (None, "matrix"):
        shutil.rmtree(MATRIX, ignore_errors=True)
        pos = build_matrix(EICAR, os.path.join(MATRIX, "eicar"))
        # the twins hold a harmless-looking text file: an Office document or a password-protected zip carrying a
        # program named .com is rightly suspicious whatever its content
        neg = build_matrix(NEAR_MISS, os.path.join(MATRIX, "near_miss"), member="notes.txt")
        res = scan([os.path.join(MATRIX, "eicar"), os.path.join(MATRIX, "near_miss")], print)
        rows = []
        for (fmt, p) in pos:
            v, names = verdict_for(p, res)
            ok = _ok("malicious", v)
            failed += not ok
            rows.append({"name": fmt, "expect": "malicious", "verdict": v, "ok": ok, "detections": names})
        fps = []
        for (fmt, p) in neg:
            v, names = verdict_for(p, res)
            ok = _ok("clean", v)
            failed += not ok
            fps.append({"name": fmt, "expect": "clean", "verdict": v, "ok": ok, "detections": names})
        summary["parts"]["matrix"] = {"passed": sum(r["ok"] for r in rows), "total": len(rows), "rows": rows,
                                      "near_miss_clean": sum(r["ok"] for r in fps), "near_miss_total": len(fps),
                                      "near_miss_rows": fps}
        _print_part("2. EICAR w kontenerach (wykrycie)", rows)
        _print_part("2b. Bliźniaki bez EICAR (muszą zostać czyste)", fps)

    if only in (None, "hashes"):
        from cerber import config
        from cerber.engines.hashdb import HashDB
        db = HashDB(config.HASHDB)
        rows = []
        for year, name, sha in OBJECTIVE_SEE_HASHES:
            hit = db._con().execute("SELECT name, src FROM file WHERE digest=?", (bytes.fromhex(sha),)).fetchone()
            rows.append({"name": f"{year} {name}", "sha256": sha, "ok": bool(hit), "verdict": hit[0] if hit else "-",
                         "expect": "known"})
        summary["parts"]["hashes"] = {"passed": sum(r["ok"] for r in rows), "total": len(rows), "rows": rows}
        _print_part("3. Skróty z raportów Objective-See (tylko baza, bez pobierania)", rows)

    if only in (None, "families"):
        import pickle
        import re
        import sqlite3
        import yara
        from cerber import config
        texts: dict[str, list[str]] = {"YARA": [], "ClamAV": [], "hash": []}
        for r in yara.load(config.YARA_BIN):
            texts["YARA"].append(" ".join([r.identifier] + [str(v) for v in r.meta.values() if isinstance(v, str)]))
        with open(os.path.join(config.CLAMAV_COMPILED, "sigs.pkl"), "rb") as fh:      # our own sealed database
            texts["ClamAV"] = [t[0] for t in pickle.load(fh)]
        con = sqlite3.connect(f"file:{config.HASHDB}?mode=ro", uri=True)
        texts["hash"] = [n for (n,) in con.execute("SELECT DISTINCT name FROM file WHERE src IN (2, 6)")]
        low = {k: [t.lower().replace("_", " ") for t in v] for k, v in texts.items()}
        macctx = re.compile(r"\b(osx|macos|mac|macho|mach-o|darwin|apple|dmg)\b|osx\.|macos\.|\.osx|xprotect")
        mac_lines = {k: [t for t in v if macctx.search(t)] for k, v in low.items()}
        joined = {k: "\n".join(v) for k, v in low.items()}
        mac_joined = {k: "\n".join(v) for k, v in mac_lines.items()}
        rows = []
        for year, fam_name, rx, *mac in OBJECTIVE_SEE_FAMILIES:
            pat = re.compile(rx.replace("_", " "), re.I)
            src = mac_joined if mac and mac[0] else joined
            where = [k for k in ("YARA", "ClamAV", "hash") if pat.search(src[k])]
            named = bool({"YARA", "ClamAV"} & set(where))
            rows.append({"name": f"{year} {fam_name}", "ok": named, "verdict": "+".join(where) or "-",
                         "expect": "named signature", "hash_only": not named and "hash" in where})
        summary["parts"]["families"] = {"passed": sum(r["ok"] for r in rows), "total": len(rows), "rows": rows,
                                        "hash_only": sum(r["hash_only"] for r in rows)}
        _print_part("4. Rodziny z raportów Objective-See: sygnatura nazwana od rodziny (YARA/ClamAV)", rows)

    summary["seconds"] = round(time.time() - t0, 1)
    out = os.path.join(RESULTS, f"safe-{label}.json")
    with open(out, "w") as fh:
        json.dump(summary, fh, indent=1, ensure_ascii=False)
    print("\nPODSUMOWANIE")
    for k, p in summary["parts"].items():
        extra = (f" · bliźniaki czyste {p['near_miss_clean']}/{p['near_miss_total']}" if "near_miss_total" in p else "")
        print(f"  {k:9s} {p['passed']}/{p['total']} ({100 * p['passed'] / max(1, p['total']):.1f}%){extra}")
    print(f"Wyniki: {out}")
    return 1 if failed else 0


def _print_part(title: str, rows: list[dict]) -> None:
    print(f"\n{title}: {sum(r['ok'] for r in rows)}/{len(rows)}")
    for r in rows:
        mark = "OK " if r["ok"] else "XX "
        det = ", ".join(r.get("detections") or [])
        print(f"  {mark}{r['name'][:52]:52s} {r['verdict']:10s} {det[:70]}")


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("fetch")
    r = sub.add_parser("run")
    r.add_argument("--label", default=time.strftime("%Y%m%d"))
    r.add_argument("--only", choices=("official", "matrix", "hashes", "families"))
    a = ap.parse_args()
    if a.cmd == "fetch":
        return fetch()
    return run(a.label, a.only)


if __name__ == "__main__":
    sys.exit(main())
