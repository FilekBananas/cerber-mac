"""Download public GitHub repositories and Hugging Face repos for scanning in the sandbox.

Nothing downloaded here is ever executed or unpacked outside the sandbox: GitHub repositories arrive
as one .tar.gz that the sandbox unpacks; Hugging Face files are written as plain files into the
workspace and scanned there.

Hugging Face weights can be many GB. Only formats that can run code on load matter, so:
* code / configs / small files: downloaded completely,
* pickle-based weights (.bin/.pt/.pth/.ckpt/.pkl/…): downloaded completely up to a size limit; larger
  PyTorch zip checkpoints are read with HTTP Range requests – only the zip directory and the embedded
  `*.pkl` members (the part that executes on torch.load) are fetched,
* safetensors / GGUF: only the header (safetensors cannot run code; GGUF headers carry the Jinja chat
  template that is checked for template injection),
* datasets' big data files (parquet/arrow/csv…): skipped, they cannot execute anything.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field
from typing import Callable

from . import config

GITHUB_MAX_BYTES = 3 << 30
HF_TOTAL_BUDGET = 6 << 30
HF_FULL_PICKLE_MAX = 768 << 20
HF_SMALL_FILE_MAX = 25 << 20
HF_MAX_FILES = 5000
HEADER_BYTES = {"safetensors": 8 << 20, "gguf": 48 << 20}
PICKLE_EXT = (".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib", ".dill", ".npy", ".npz", ".h5",
              ".hdf5", ".keras", ".pb", ".onnx", ".mar", ".nemo", ".model.pt", ".tar")
SAFE_WEIGHT_EXT = (".safetensors", ".gguf", ".ggml", ".msgpack")
DATA_EXT = (".parquet", ".arrow", ".csv", ".tsv", ".jsonl", ".json.gz", ".jsonl.gz", ".txt.gz", ".zst",
            ".wav", ".mp3", ".flac", ".png", ".jpg", ".jpeg", ".webp", ".mp4", ".tfrecord", ".lance")
TIMEOUT = 60


class FetchError(Exception):
    pass


def _req(url: str, headers: dict | None = None) -> urllib.request.Request:
    h = {"User-Agent": config.USER_AGENT}
    h.update(headers or {})
    return urllib.request.Request(url, headers=h)


def _json(url: str) -> dict | list:
    try:
        with urllib.request.urlopen(_req(url, {"Accept": "application/json"}), timeout=TIMEOUT) as r:
            return json.loads(r.read(32 << 20).decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403, 404):
            raise FetchError(f"brak dostępu ({exc.code}) – repozytorium nie istnieje, jest prywatne lub wymaga "
                             "zalogowania/akceptacji licencji") from exc
        raise FetchError(f"błąd HTTP {exc.code} dla {url}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FetchError(f"brak połączenia z {urllib.parse.urlparse(url).netloc}: {exc}") from exc


def _download(url: str, dest: str, limit: int, progress: Callable[[int, int | None], None] | None = None,
              cancel=None) -> int:
    """Stream url → dest; stops (and raises) when the file exceeds limit."""
    try:
        with urllib.request.urlopen(_req(url), timeout=TIMEOUT) as r, open(dest, "wb") as out:
            total = r.headers.get("Content-Length")
            total = int(total) if total and total.isdigit() else None
            if total and total > limit:
                raise FetchError(f"plik ma {total / 1e9:.1f} GB – powyżej limitu {limit / 1e9:.1f} GB")
            got = 0
            last = 0.0
            while True:
                if cancel is not None and cancel.is_set():
                    raise FetchError("przerwano")
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                got += len(chunk)
                if got > limit:
                    raise FetchError(f"pobieranie przekroczyło limit {limit / 1e9:.1f} GB")
                out.write(chunk)
                if progress and time.time() - last > 0.25:
                    last = time.time()
                    progress(got, total)
            if progress:
                progress(got, total)
            return got
    except urllib.error.HTTPError as exc:
        raise FetchError(f"błąd HTTP {exc.code} przy pobieraniu") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise FetchError(f"błąd połączenia: {exc}") from exc


def _range(url: str, start: int, end: int) -> bytes:
    """Bytes [start, end] (inclusive). Raises FetchError if the server ignores Range."""
    try:
        with urllib.request.urlopen(_req(url, {"Range": f"bytes={start}-{end}"}), timeout=TIMEOUT) as r:
            if r.status != 206:
                raise FetchError("serwer nie obsługuje pobierania fragmentów")
            return r.read(end - start + 1)
    except urllib.error.HTTPError as exc:
        raise FetchError(f"błąd HTTP {exc.code} (fragment)") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise FetchError(f"błąd połączenia: {exc}") from exc


# ------------------------------------------------------------------ GitHub

GH_RX = [
    re.compile(r"^(?:https?://)?(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/(?:tree|blob|commit)/(.+?))?/?$"),
    re.compile(r"^git@github\.com:([\w.-]+)/([\w.-]+?)(?:\.git)?$"),
    re.compile(r"^([\w.-]+)/([\w.-]+)$"),
]


def parse_github(url: str) -> tuple[str, str, str | None]:
    u = url.strip().split("#")[0].split("?")[0]
    for rx in GH_RX:
        m = rx.match(u)
        if m:
            owner, name = m.group(1), m.group(2)
            ref = m.group(3) if m.lastindex and m.lastindex >= 3 else None
            return owner, name, ref
    raise FetchError("to nie wygląda na adres repozytorium GitHub (np. https://github.com/wlasciciel/repo)")


def fetch_github(url: str, work: str, emit: Callable[[dict], None], cancel=None) -> tuple[str, dict]:
    owner, name, ref = parse_github(url)
    meta = _json(f"https://api.github.com/repos/{owner}/{name}")
    ref_in_url = ref
    if ref and "/" in ref:          # /tree/<branch>/<subdir>: try the longest prefix that is a real ref
        parts = ref.split("/")
        ref = parts[0]
    ref = ref or meta.get("default_branch") or "HEAD"
    info = {"source": "github", "owner": owner, "name": name, "kind": "repo", "ref": ref,
            "url": f"https://github.com/{owner}/{name}", "description": meta.get("description") or "",
            "stars": meta.get("stargazers_count"), "size_kb": meta.get("size"), "archived": meta.get("archived"),
            "pushed_at": meta.get("pushed_at"), "license": (meta.get("license") or {}).get("spdx_id"),
            "fork": meta.get("fork"), "skipped": []}
    if ref_in_url and ref_in_url != ref:
        info["note"] = f"skanowane jest całe repozytorium z gałęzi/tagu „{ref}”"
    dest = os.path.join(work, "in", f"{owner}-{name}.tar.gz")
    emit({"ev": "stage", "id": "download", "title": f"Pobieranie {owner}/{name} ({ref})…"})
    got = _download(f"https://codeload.github.com/{owner}/{name}/tar.gz/{urllib.parse.quote(ref, safe='/')}", dest,
                    GITHUB_MAX_BYTES, lambda b, t: emit({"ev": "progress", "stage": "download", "bytes": b, "total": t}),
                    cancel)
    info["archive_bytes"] = got
    emit({"ev": "log", "msg": f"Pobrano archiwum repozytorium: {got / 1e6:.1f} MB"})
    return dest, info


# ------------------------------------------------------------------ Hugging Face

HF_RX = re.compile(r"^(?:https?://)?(?:www\.)?(?:huggingface\.co|hf\.co)/(?:(datasets|spaces|models)/)?"
                   r"([\w.-]+)/([\w.-]+)(?:/(?:tree|blob|resolve)/([^/]+)(?:/.*)?)?/?$")


@dataclass
class HFPlan:
    full: list[dict] = field(default_factory=list)
    header: list[dict] = field(default_factory=list)
    pickle_zip: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)


def parse_hf(url: str) -> tuple[str, str, str]:
    u = url.strip().split("#")[0].split("?")[0]
    m = HF_RX.match(u)
    if m:
        kind = {"datasets": "dataset", "spaces": "space"}.get(m.group(1) or "", "model")
        return kind, f"{m.group(2)}/{m.group(3)}", m.group(4) or "main"
    m = re.match(r"^([\w.-]+)/([\w.-]+)$", u)
    if m:
        return "model", u, "main"
    raise FetchError("to nie wygląda na adres Hugging Face (np. https://huggingface.co/organizacja/model)")


def _hf_api_kind(kind: str) -> str:
    return {"model": "models", "dataset": "datasets", "space": "spaces"}[kind]


def _hf_prefix(kind: str) -> str:
    return {"model": "", "dataset": "datasets/", "space": "spaces/"}[kind]


def _safe_rel(path: str) -> str | None:
    parts = [p for p in path.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def plan_hf(files: list[dict]) -> HFPlan:
    plan = HFPlan()
    budget = HF_TOTAL_BUDGET
    for f in sorted(files, key=lambda f: f.get("size") or 0):
        path = f["path"]
        size = int(f.get("size") or 0)
        low = path.lower()
        if low.endswith(SAFE_WEIGHT_EXT):
            kind = "gguf" if low.endswith((".gguf", ".ggml")) else "safetensors"
            if kind == "safetensors" and low.endswith(".msgpack"):
                plan.skipped.append({"path": path, "size": size, "reason": "bezpieczny format wag (msgpack)"})
                continue
            plan.header.append({**f, "header": min(size, HEADER_BYTES.get(kind, 8 << 20))})
            continue
        if low.endswith(PICKLE_EXT):
            if size <= HF_FULL_PICKLE_MAX and size <= budget:
                plan.full.append(f)
                budget -= size
            else:
                plan.pickle_zip.append(f)
            continue
        if low.endswith(DATA_EXT) and size > (2 << 20):
            plan.skipped.append({"path": path, "size": size,
                                 "reason": "duży plik danych – nie może uruchomić kodu"})
            continue
        if size <= HF_SMALL_FILE_MAX and size <= budget:
            plan.full.append(f)
            budget -= size
        else:
            plan.skipped.append({"path": path, "size": size, "reason": "za duży, poza limitem pobierania"})
    return plan


def _zip_pickles(url: str, size: int) -> list[tuple[str, bytes]] | None:
    """Fetch only the *.pkl members of a remote zip (PyTorch checkpoint) via Range requests."""
    tail_len = min(size, 1 << 20)
    tail = _range(url, size - tail_len, size - 1)
    eocd = tail.rfind(b"PK\x05\x06")
    if eocd < 0:
        return None
    cd_size, cd_off = struct.unpack_from("<II", tail, eocd + 12)
    loc64 = tail.rfind(b"PK\x06\x07", 0, eocd)
    if (cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF) and loc64 >= 0:
        z64_off = struct.unpack_from("<Q", tail, loc64 + 8)[0]
        rec = _range(url, z64_off, z64_off + 55)
        if rec[:4] == b"PK\x06\x06":
            cd_size, cd_off = struct.unpack_from("<QQ", rec, 40)
    if cd_size > (64 << 20):
        return None
    cd = _range(url, cd_off, cd_off + cd_size - 1)
    out = []
    pos = 0
    while pos + 46 <= len(cd) and cd[pos:pos + 4] == b"PK\x01\x02":
        method, = struct.unpack_from("<H", cd, pos + 10)
        csize, usize = struct.unpack_from("<II", cd, pos + 20)
        nlen, elen, clen = struct.unpack_from("<HHH", cd, pos + 28)
        lho, = struct.unpack_from("<I", cd, pos + 42)
        name = cd[pos + 46:pos + 46 + nlen].decode("utf-8", "replace")
        extra = cd[pos + 46 + nlen:pos + 46 + nlen + elen]
        if 0xFFFFFFFF in (csize, usize, lho):          # zip64 extra field
            vals = []
            e = 0
            while e + 4 <= len(extra):
                hid, hlen = struct.unpack_from("<HH", extra, e)
                if hid == 1:
                    vals = [struct.unpack_from("<Q", extra, e + 4 + 8 * i)[0] for i in range(hlen // 8)]
                    break
                e += 4 + hlen
            it = iter(vals)
            if usize == 0xFFFFFFFF:
                usize = next(it, usize)
            if csize == 0xFFFFFFFF:
                csize = next(it, csize)
            if lho == 0xFFFFFFFF:
                lho = next(it, lho)
        pos += 46 + nlen + elen + clen
        if not name.endswith(".pkl") or csize > (256 << 20):
            continue
        hdr = _range(url, lho, lho + 29)
        if hdr[:4] != b"PK\x03\x04":
            continue
        ln, le = struct.unpack_from("<HH", hdr, 26)
        start = lho + 30 + ln + le
        data = _range(url, start, start + csize - 1) if csize else b""
        if method == 8:
            data = zlib.decompressobj(-15).decompress(data, 512 << 20)
        elif method != 0:
            continue
        out.append((name, data))
        if len(out) >= 20:
            break
    return out


def fetch_hf(url: str, work: str, emit: Callable[[dict], None], cancel=None) -> tuple[str, dict]:
    kind, repo, rev = parse_hf(url)
    api = f"https://huggingface.co/api/{_hf_api_kind(kind)}/{repo}"
    meta = _json(api)
    listing = _json(f"{api}/tree/{urllib.parse.quote(rev, safe='')}?recursive=true")
    if not isinstance(listing, list):
        raise FetchError("nieoczekiwana odpowiedź API Hugging Face")
    files = [f for f in listing if f.get("type") == "file" and _safe_rel(f.get("path", ""))][:HF_MAX_FILES]
    info = {"source": "huggingface", "owner": repo.split("/")[0], "name": repo.split("/")[1], "kind": kind,
            "ref": rev, "url": f"https://huggingface.co/{_hf_prefix(kind)}{repo}",
            "description": (meta.get("cardData") or {}).get("pipeline_tag") or meta.get("pipeline_tag") or "",
            "stars": meta.get("likes"), "downloads": meta.get("downloads"), "gated": meta.get("gated"),
            "files_total": len(files), "files_downloaded": 0, "skipped": [], "partial": []}
    if meta.get("gated"):
        info["note"] = "repozytorium wymaga akceptacji licencji – część plików może być niedostępna"
    plan = plan_hf(files)
    info["skipped"] = plan.skipped[:500]
    root = os.path.join(work, "in", "hf", info["name"])
    os.makedirs(root, mode=0o700, exist_ok=True)
    base = f"https://huggingface.co/{_hf_prefix(kind)}{repo}/resolve/{urllib.parse.quote(rev, safe='')}/"
    total_bytes = 0
    jobs = len(plan.full) + len(plan.header) + len(plan.pickle_zip)
    emit({"ev": "stage", "id": "download", "title": f"Pobieranie {repo} z Hugging Face ({jobs} plików)…"})

    def dest_for(path: str) -> str:
        d = os.path.join(root, _safe_rel(path))
        os.makedirs(os.path.dirname(d), mode=0o700, exist_ok=True)
        return d

    done = 0
    for f in plan.full:
        if cancel is not None and cancel.is_set():
            raise FetchError("przerwano")
        try:
            total_bytes += _download(base + urllib.parse.quote(f["path"]), dest_for(f["path"]),
                                     HF_FULL_PICKLE_MAX + 1, None, cancel)
            info["files_downloaded"] += 1
        except FetchError as exc:
            info["skipped"].append({"path": f["path"], "size": f.get("size"), "reason": f"nie pobrano: {exc}"})
        done += 1
        emit({"ev": "progress", "stage": "download", "bytes": total_bytes, "total": None, "files": done,
              "files_total": jobs})
    for f in plan.header:
        try:
            data = _range(base + urllib.parse.quote(f["path"]), 0, max(0, f["header"] - 1)) if f["header"] else b""
            with open(dest_for(f["path"]), "wb") as fh:
                fh.write(data)
            total_bytes += len(data)
            info["files_downloaded"] += 1
            info["partial"].append({"path": f["path"], "size": f.get("size"),
                                    "reason": f"bezpieczny format – sprawdzono nagłówek ({len(data) >> 20} MB)"})
        except FetchError as exc:
            info["skipped"].append({"path": f["path"], "size": f.get("size"), "reason": f"nie pobrano nagłówka: {exc}"})
        done += 1
        emit({"ev": "progress", "stage": "download", "bytes": total_bytes, "total": None, "files": done,
              "files_total": jobs})
    for f in plan.pickle_zip:
        url_f = base + urllib.parse.quote(f["path"])
        size = int(f.get("size") or 0)
        try:
            head = _range(url_f, 0, 3)
            members = _zip_pickles(url_f, size) if head == b"PK\x03\x04" else None
            if members:
                for name, data in members:
                    with open(dest_for(f"{f['path']}.{os.path.basename(name)}"), "wb") as fh:
                        fh.write(data)
                    total_bytes += len(data)
                info["files_downloaded"] += 1
                info["partial"].append({"path": f["path"], "size": size,
                                        "reason": f"duży plik – pobrano tylko część wykonywalną ({len(members)} × pickle)"})
            else:
                data = _range(url_f, 0, min(size, 64 << 20) - 1)
                with open(dest_for(f"{f['path']}.head"), "wb") as fh:
                    fh.write(data)
                total_bytes += len(data)
                info["files_downloaded"] += 1
                info["partial"].append({"path": f["path"], "size": size,
                                        "reason": "duży plik – sprawdzono pierwsze 64 MB (zawierają pickle)"})
        except FetchError as exc:
            info["skipped"].append({"path": f["path"], "size": size, "reason": f"nie pobrano: {exc}"})
        done += 1
        emit({"ev": "progress", "stage": "download", "bytes": total_bytes, "total": None, "files": done,
              "files_total": jobs})
    info["archive_bytes"] = total_bytes
    info["skipped"] = info["skipped"][:500]
    emit({"ev": "log", "msg": f"Pobrano {info['files_downloaded']} z {len(files)} plików ({total_bytes / 1e6:.1f} MB); "
                              f"pominięto {len(plan.skipped)} (bezpieczne/duże pliki danych)"})
    return root, info


# ------------------------------------------------------------------ any link ("Sprawdź link")

URL_MAX_FILE = 2 << 30
URL_MAX_TOTAL = 4 << 30
URL_MAX_FILES = 20
PAGE_MAX = 5 << 20
DOWNLOADABLE_EXT = (
    ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".dmg", ".pkg", ".mpkg", ".iso", ".img",
    ".exe", ".msi", ".msix", ".appx", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta",
    ".lnk", ".jar", ".apk", ".deb", ".rpm", ".appimage", ".sh", ".command", ".py", ".docm", ".xlsm", ".pptm",
    ".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pdf", ".rtf", ".one", ".vhd", ".vhdx", ".run", ".bin", ".cab",
    ".xip", ".scpt", ".workflow", ".terminal", ".webloc", ".url", ".svg", ".html", ".htm", ".chm", ".wsf", ".reg",
)
_HREF_RX = re.compile(r"""(?:href|src|data-href|data-url)\s*=\s*["']([^"'<>\s]{1,2000})["']""", re.I)
_DOWNLOAD_RX = re.compile(r"""<a\b[^>]*\bdownload\b[^>]*\bhref\s*=\s*["']([^"']+)["']|"""
                          r"""<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*\bdownload\b""", re.I)
_JSLOC_RX = re.compile(r"""(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']{1,2000})["']|"""
                       r"""<meta[^>]+http-equiv\s*=\s*["']?refresh[^>]+url\s*=\s*([^"'>\s]+)""", re.I)
_TITLE_RX = re.compile(r"<title[^>]*>(.{0,300}?)</title>", re.I | re.S)


class _Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append(newurl)
        if len(self.chain) > 10:
            raise FetchError("za dużo przekierowań (>10)")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _filename(resp, url: str, fallback: str) -> str:
    cd = resp.headers.get("Content-Disposition") or ""
    m = re.search(r"filename\*\s*=\s*[^']*'[^']*'([^;]+)", cd) or re.search(r'filename\s*=\s*"?([^";]+)"?', cd)
    name = urllib.parse.unquote(m.group(1)) if m else os.path.basename(urllib.parse.urlparse(url).path)
    name = re.sub(r"[/\\\x00-\x1f]", "_", name).strip(". ") or fallback
    return name[:150]


def _tls_info(host: str, port: int) -> dict | None:
    import socket
    import ssl
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as s, ctx.wrap_socket(s, server_hostname=host) as ss:
            c = ss.getpeercert() or {}
            issuer = dict(x[0] for x in c.get("issuer", ()) if x)
            subject = dict(x[0] for x in c.get("subject", ()) if x)
            return {"issuer": " ".join(v for k, v in issuer.items() if k in ("organizationName", "commonName")),
                    "subject": subject.get("commonName"), "expires": c.get("notAfter"), "version": ss.version(),
                    "valid": True}
    except ssl.SSLCertVerificationError as exc:
        return {"valid": False, "error": f"certyfikat NIEPRAWIDŁOWY: {exc.verify_message}"}
    except (OSError, ValueError) as exc:
        return {"valid": None, "error": str(exc)[:200]}


def _save_stream(resp, dest: str, limit: int, emit, state: dict, cancel) -> tuple[int, str]:
    h = hashlib.sha256()
    got = 0
    last = 0.0
    with open(dest, "wb") as out:
        while True:
            if cancel is not None and cancel.is_set():
                raise FetchError("przerwano")
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            got += len(chunk)
            if got > limit:
                raise FetchError(f"plik większy niż {limit >> 30} GB")
            state["bytes"] += len(chunk)
            if state["bytes"] > URL_MAX_TOTAL:
                raise FetchError(f"łącznie ponad {URL_MAX_TOTAL >> 30} GB")
            h.update(chunk)
            out.write(chunk)
            if time.time() - last > 0.3:
                last = time.time()
                emit({"ev": "progress", "stage": "download", "bytes": state["bytes"], "total": state.get("total"),
                      "files": state["files"], "files_total": state["files_total"]})
    return got, h.hexdigest()


def _open(url: str, handler: _Redirects | None = None):
    opener = urllib.request.build_opener(handler or _Redirects())
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                      "Version/18.0 Safari/605.1.15",
        "Accept": "*/*"})
    return opener.open(req, timeout=TIMEOUT)


def _ioc_hits(url: str, domain: str, ip: str | None) -> tuple[list[str], str]:
    """Local threat lists (URLhaus/ThreatFox). Returns (hits, verdict)."""
    hits, verdict = [], "CLEAN"
    try:
        from .engines.ioc_fuzzy import IocService, is_shared_domain
        svc = IocService(config.IOCDB)
    except Exception:  # noqa: BLE001
        return hits, verdict
    t = svc.lookup("url", url)
    if t:
        hits.append(f"adres URL na liście zagrożeń: {t}")
        verdict = "MALICIOUS"
    t = svc.lookup("domain", domain) if domain and not is_shared_domain(domain) else None
    if t:
        hits.append(f"domena {domain} na liście zagrożeń: {t}")
        verdict = "MALICIOUS" if verdict == "MALICIOUS" else "SUSPICIOUS"
    t = svc.lookup("ip", ip) if ip else None
    if t:
        hits.append(f"adres IP {ip} na liście zagrożeń: {t}")
        verdict = "MALICIOUS" if verdict == "MALICIOUS" else "SUSPICIOUS"
    return hits, verdict


def fetch_url(url: str, work: str, emit: Callable[[dict], None], cancel=None) -> tuple[str, dict]:
    import socket
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        if re.match(r"^[\w.-]+\.[a-z]{2,}(/|$)", url, re.I):
            url = "https://" + url
        else:
            raise FetchError("podaj adres zaczynający się od http:// lub https://")
    p = urllib.parse.urlparse(url)
    if not p.hostname:
        raise FetchError("nieprawidłowy adres")
    root = os.path.join(work, "in", "files")
    os.makedirs(root, mode=0o700, exist_ok=True)
    info: dict = {"input": url, "final_url": url, "redirects": [], "status": None, "content_type": None,
                  "server": None, "domain": p.hostname, "ip": None, "tls": None, "ioc": [], "ioc_verdict": "CLEAN",
                  "page": None, "files": [], "skipped": [], "notes": []}
    emit({"ev": "stage", "id": "check", "title": "Sprawdzanie adresu…"})
    try:
        info["ip"] = socket.gethostbyname(p.hostname)
    except OSError:
        info["notes"].append("nie udało się ustalić adresu IP (DNS)")
    hits, verdict = _ioc_hits(url, p.hostname, info["ip"])
    state = {"bytes": 0, "files": 0, "files_total": 1, "total": None}
    emit({"ev": "stage", "id": "download", "title": "Pobieranie w sandboksie…"})
    red = _Redirects()
    try:
        resp = _open(url, red)
    except urllib.error.HTTPError as exc:
        info["status"] = exc.code
        resp = exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FetchError(f"nie można połączyć się z {p.hostname}: {getattr(exc, 'reason', exc)}") from exc
    with resp:
        final = resp.geturl() if hasattr(resp, "geturl") else url
        info.update(final_url=final, redirects=red.chain, status=getattr(resp, "status", info["status"]),
                    content_type=resp.headers.get("Content-Type"), server=resp.headers.get("Server"))
        fp = urllib.parse.urlparse(final)
        if fp.hostname and fp.hostname != p.hostname:
            info["domain"] = fp.hostname
            try:
                info["ip"] = socket.gethostbyname(fp.hostname)
            except OSError:
                pass
            h2, v2 = _ioc_hits(final, fp.hostname, info["ip"])
            hits += [h for h in h2 if h not in hits]
            verdict = max(verdict, v2, key=["CLEAN", "SUSPICIOUS", "MALICIOUS"].index)
        for hop in red.chain:
            hh, vv = _ioc_hits(hop, urllib.parse.urlparse(hop).hostname or "", None)
            hits += [h for h in hh if h not in hits]
            verdict = max(verdict, vv, key=["CLEAN", "SUSPICIOUS", "MALICIOUS"].index)
        if fp.scheme == "https" and fp.hostname:
            info["tls"] = _tls_info(fp.hostname, fp.port or 443)
        elif fp.scheme == "http":
            info["notes"].append("połączenie nieszyfrowane (http) – treść mogła zostać podmieniona po drodze")
        if isinstance(resp, urllib.error.HTTPError):
            raise FetchError(f"serwer odpowiedział błędem HTTP {resp.code}")
        ctype = (info["content_type"] or "").lower()
        disposition = (resp.headers.get("Content-Disposition") or "").lower()
        length = resp.headers.get("Content-Length")
        state["total"] = int(length) if length and length.isdigit() else None
        is_page = "text/html" in ctype and "attachment" not in disposition
        name = _filename(resp, final, "strona.html" if is_page else "pobrany_plik")
        if is_page and not name.lower().endswith((".html", ".htm")):
            name += ".html"
        dest = os.path.join(root, name)
        size, sha = _save_stream(resp, dest, PAGE_MAX if is_page else URL_MAX_FILE, emit, state, cancel)
        state["files"] = 1
        info["files"].append({"name": name, "url": final, "size": size, "content_type": info["content_type"],
                              "sha256": sha, "kind": "strona" if is_page else "plik"})
    if is_page:
        with open(dest, "rb") as fh:
            html = fh.read().decode("utf-8", "replace")
        links: list[str] = []
        for m in _DOWNLOAD_RX.finditer(html):
            links.append(m.group(1) or m.group(2))
        for m in _JSLOC_RX.finditer(html):
            links.append(m.group(1) or m.group(2))
        for m in _HREF_RX.finditer(html):
            u = m.group(1)
            path = urllib.parse.urlparse(urllib.parse.urljoin(final, u)).path.lower()
            if path.endswith(DOWNLOADABLE_EXT) and not path.endswith((".html", ".htm")):
                links.append(u)
        seen, cand = set(), []
        for u in links:
            full = urllib.parse.urljoin(final, u.strip())
            if not full.lower().startswith(("http://", "https://")) or full in seen or full == final:
                continue
            seen.add(full)
            cand.append(full)
        t = _TITLE_RX.search(html)
        info["page"] = {"title": re.sub(r"\s+", " ", t.group(1)).strip()[:200] if t else None,
                        "links_found": len(cand)}
        if len(cand) > URL_MAX_FILES:
            info["skipped"] += [{"url": u, "reason": f"limit {URL_MAX_FILES} plików na stronę"} for u in cand[URL_MAX_FILES:]]
            cand = cand[:URL_MAX_FILES]
        state["files_total"] = 1 + len(cand)
        for i, u in enumerate(cand, 1):
            if cancel is not None and cancel.is_set():
                raise FetchError("przerwano")
            try:
                hh, vv = _ioc_hits(u, urllib.parse.urlparse(u).hostname or "", None)
                hits += [h for h in hh if h not in hits]
                verdict = max(verdict, vv, key=["CLEAN", "SUSPICIOUS", "MALICIOUS"].index)
                with _open(u) as r2:
                    ct2 = (r2.headers.get("Content-Type") or "").lower()
                    if "text/html" in ct2 and "attachment" not in (r2.headers.get("Content-Disposition") or "").lower():
                        info["skipped"].append({"url": u, "reason": "to kolejna strona, nie plik"})
                        continue
                    nm = _filename(r2, r2.geturl(), f"plik_{i}")
                    base_nm, k = nm, 1
                    while os.path.exists(os.path.join(root, nm)):
                        k += 1
                        nm = f"{k}_{base_nm}"
                    size, sha = _save_stream(r2, os.path.join(root, nm), URL_MAX_FILE, emit, state, cancel)
                    info["files"].append({"name": nm, "url": r2.geturl(), "size": size,
                                          "content_type": r2.headers.get("Content-Type"), "sha256": sha, "kind": "plik"})
            except FetchError as exc:
                if "przerwano" in str(exc):
                    raise
                info["skipped"].append({"url": u, "reason": str(exc)})
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                info["skipped"].append({"url": u, "reason": f"nie pobrano: {getattr(exc, 'reason', exc)}"})
            state["files"] = 1 + i
            emit({"ev": "progress", "stage": "download", "bytes": state["bytes"], "total": None,
                  "files": state["files"], "files_total": state["files_total"]})
    info["ioc"] = hits
    info["ioc_verdict"] = verdict
    emit({"ev": "log", "msg": f"Pobrano {len(info['files'])} plik(ów), {state['bytes'] / 1e6:.1f} MB"
                              + (f"; przekierowania: {len(info['redirects'])}" if info["redirects"] else "")})
    return root, info
