"""macOS trust information for top-level files (codesign / Gatekeeper / quarantine / WhereFroms).

Analyzer "exe_macos_trust" (order 20). Runs only on top-level objects that have obj.real_path, on
macOS, and only when ctx.options["macos"] is true. Results are cached per (path, inode, mtime, size)
and every external command has a bounded timeout; spctl is only consulted for quarantined files
(it can block for minutes on an online notarization lookup) and is disabled for the rest of the
process after a timeout.

  * quarantine xattr (read with getxattr(2) via ctypes, `xattr -p` fallback):
        "flags;hex-timestamp;agent;uuid"  -> root.meta["macos"]["quarantine"]
  * kMDItemWhereFroms (xattr binary plist, `mdls` fallback) -> root.meta["macos"]["where_froms"]
  * Mach-O / universal files:
        `codesign -dv --verbose=4`   -> identifier, authorities, team id, flags, notarization ticket
        `codesign --verify --strict` -> validity (Finder "detritus" complaints are re-checked non-strict)
        `spctl --assess` (quarantined only) -> Gatekeeper decision / notarization source
    Valid Apple / Developer ID / Mac App Store signatures set root.meta["trusted_signer"].

Detections (engine "macos"):
    Heur:MachO.CertificateRevoked           60  signing certificate revoked (codesign or Gatekeeper/OCSP verdict;
                                                Apple revokes certificates of malware developers)
    Heur:MachO.CertificateRevoked.AfterNotarization  10  cert revoked AFTER a valid notarization (stapled ticket +
                                                offline verification still pass): benign cert rotation, not malware
    Heur:MachO.Signature.Invalid         10-35  executable modified after signing: 30 (35 quarantined);
                                                only the bundle seal broken (added/modified resources): 10 (25 quarantined)
    Heur:MachO.Unsigned.Quarantined         15  downloaded (quarantined) executable that is not signed at all
    Heur:MachO.AdhocSigned.Quarantined      10  downloaded (quarantined) executable with only an ad-hoc signature
    Heur:MachO.Gatekeeper.Rejected          20  certificate-signed quarantined binary rejected by Gatekeeper
    Heur:MachO.Signature.Untrusted          15  signed with a certificate that does not chain to Apple
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import plistlib
import re
import shutil
import subprocess
import sys
import time
from collections import OrderedDict

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from . import register

CODESIGN_TIMEOUT = 30
SPCTL_TIMEOUT = 8
MDLS_TIMEOUT = 5
_CACHE: "OrderedDict[tuple, dict]" = OrderedDict()
_CACHE_MAX = 8192
_SPCTL_DISABLED = False

_libc = None
if sys.platform == "darwin":
    try:
        _libc = ctypes.CDLL(ctypes.util.find_library("c") or "libSystem.dylib", use_errno=True)
        _libc.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_uint32, ctypes.c_int]
        _libc.getxattr.restype = ctypes.c_ssize_t
    except Exception:  # noqa: BLE001
        _libc = None

BROKEN_SIG = ("a sealed resource is missing or invalid", "invalid signature (code or signature have been modified)",
              "code or signature have been modified", "code has no resources but signature indicates they must be present",
              "invalid info.plist (plist or signature have been modified)", "nested code is modified or invalid",
              "main executable failed strict validation", "code signature is not valid", "code failed to satisfy",
              "invalid resource specification rule", "the sealed resource directory is invalid",
              "file added:", "file modified:", "file missing:")
BENIGN_STRICT = ("detritus not allowed", "unsealed contents present in the bundle root",
                 "resource envelope is obsolete")


def getxattr(path: str, name: str) -> bytes | None:
    if _libc is not None:
        try:
            p, n = os.fsencode(path), name.encode()
            size = _libc.getxattr(p, n, None, 0, 0, 0)
            if size < 0:
                return None
            buf = ctypes.create_string_buffer(max(size, 1))
            r = _libc.getxattr(p, n, buf, size, 0, 0)
            return buf.raw[:r] if r >= 0 else None
        except Exception:  # noqa: BLE001
            pass
    tool = shutil.which("xattr")
    if not tool:
        return None
    try:
        r = subprocess.run([tool, "-px", name, path], capture_output=True, timeout=5)
        if r.returncode == 0:
            return bytes.fromhex(r.stdout.decode().replace("\n", " ").replace(" ", ""))
    except Exception:  # noqa: BLE001
        pass
    return None


def parse_quarantine(raw: bytes) -> dict:
    s = raw.decode("utf-8", "replace").strip("\x00\n ")
    parts = s.split(";")
    q: dict = {"raw": s}
    try:
        flags = int(parts[0], 16)
        q["flags"] = f"{flags:04x}"
        q["user_approved"] = bool(flags & 0x40)
    except (ValueError, IndexError):
        pass
    if len(parts) > 1:
        try:
            ts = int(parts[1], 16)
            q["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
        except ValueError:
            pass
    if len(parts) > 2:
        q["agent"] = parts[2]
    if len(parts) > 3:
        q["uuid"] = parts[3]
    return q


def _run(cmd: list[str], timeout: int) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return -9, "timeout"
    except Exception as exc:  # noqa: BLE001
        return -1, repr(exc)


def codesign_info(tool: str, path: str) -> dict:
    rc, out = _run([tool, "-dv", "--verbose=4", path], CODESIGN_TIMEOUT)
    info: dict = {"rc": rc}
    if "not signed at all" in out:
        info["state"] = "unsigned"
        return info
    auth = re.findall(r"^Authority=(.+)$", out, re.M)
    info["authorities"] = auth
    for key, rx in (("identifier", r"^Identifier=(.+)$"), ("team_id", r"^TeamIdentifier=(.+)$"),
                    ("format", r"^Format=(.+)$"), ("timestamp", r"^Timestamp=(.+)$"),
                    ("runtime_version", r"^Runtime Version=(.+)$"), ("signature", r"^Signature=(.+)$"),
                    ("notarization_ticket", r"^Notarization Ticket=(.+)$")):
        m = re.search(rx, out, re.M)
        if m:
            info[key] = m.group(1).strip()
    m = re.search(r"^CodeDirectory .*flags=(0x[0-9a-f]+)\(([^)]*)\)", out, re.M)
    if m:
        info["flags"] = m.group(1)
        info["flag_names"] = m.group(2)
    if info.get("team_id") == "not set":
        info["team_id"] = None
    if info.get("signature") == "adhoc" or (m and "adhoc" in m.group(2)):
        info["state"] = "adhoc"
    elif auth:
        info["state"] = "certificate"
    else:
        info["state"] = "unknown" if rc else "signed"
    return info


def codesign_verify(tool: str, path: str) -> dict:
    rc, out = _run([tool, "--verify", "--strict", path], CODESIGN_TIMEOUT)
    res = {"rc": rc, "message": out.strip()[-400:]}
    low = out.lower()
    if rc == 0:
        res["valid"] = True
    elif rc == -9:
        res["valid"] = None
    elif any(b in low for b in BENIGN_STRICT) and not any(b in low for b in BROKEN_SIG):
        rc2, out2 = _run([tool, "--verify", path], CODESIGN_TIMEOUT)
        res["valid"] = rc2 == 0
        res["strict_only_issue"] = True
        if rc2:
            res["message"] = out2.strip()[-400:]
    else:
        res["valid"] = False
    res["revoked"] = "cssmerr_tp_cert_revoked" in low or "revoked" in low
    res["broken"] = res.get("valid") is False and any(b in res["message"].lower() for b in BROKEN_SIG)
    res["not_signed"] = "not signed at all" in low
    res["untrusted"] = "cssmerr_tp_not_trusted" in low
    return res


def spctl_assess(tool: str, path: str, bundle: str | None) -> dict:
    global _SPCTL_DISABLED
    if _SPCTL_DISABLED:
        return {"skipped": "disabled after timeout"}
    if bundle:
        cmd = [tool, "--assess", "--type", "execute", "-vv", bundle]
    else:
        cmd = [tool, "--assess", "-vv", "--type", "open", "--context", "context:primary-signature", path]
    rc, out = _run(cmd, SPCTL_TIMEOUT)
    if rc == -9:
        _SPCTL_DISABLED = True
        return {"skipped": "timeout"}
    res: dict = {"rc": rc, "accepted": rc == 0 and ": accepted" in out}
    m = re.search(r"^source=(.+)$", out, re.M)
    if m:
        res["source"] = m.group(1).strip()
    m = re.search(r"^origin=(.+)$", out, re.M)
    if m:
        res["origin"] = m.group(1).strip()
    if "does not seem to be an app" in out:
        res["not_an_app"] = True
    res["message"] = out.strip()[-300:]
    return res


def _bundle_of(path: str) -> str | None:
    m = re.match(r"^(.*?\.app)/Contents/MacOS/[^/]+$", path)
    return m.group(1) if m else None


def _mdls_wherefroms(path: str) -> list[str]:
    tool = shutil.which("mdls")
    if not tool:
        return []
    rc, out = _run([tool, "-name", "kMDItemWhereFroms", "-raw", path], MDLS_TIMEOUT)
    if rc != 0 or out.strip() in ("(null)", ""):
        return []
    return [x.strip().strip('",') for x in out.strip().strip("()").splitlines() if x.strip().strip('",')][:10]


def _trusted(cs: dict, ver: dict) -> str | None:
    if not ver.get("valid"):
        return None
    auth = cs.get("authorities") or []
    if not auth or auth[-1] != "Apple Root CA":
        return None
    a0 = auth[0]
    if a0 == "Software Signing" and "Apple Code Signing Certification Authority" in auth:
        return "Apple"
    if a0.startswith("Developer ID Application:") and "Developer ID Certification Authority" in auth:
        return a0
    if a0.startswith("Apple Mac OS Application Signing"):
        return "Mac App Store"
    return None


@register
class MacOSTrustAnalyzer(Analyzer):
    name = "exe_macos_trust"
    order = 20

    def applies(self, obj: ScanObject) -> bool:
        return obj.parent is None and bool(obj.real_path) and sys.platform == "darwin"

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        if not ctx.options.get("macos"):
            return
        path = obj.real_path
        try:
            st = os.stat(path)
        except OSError as exc:
            obj.errors.append(f"macos_trust: {exc}")
            return
        is_macho = obj.ftype in ("macho", "macho_fat")
        key = (os.path.abspath(path), st.st_ino, st.st_mtime_ns, st.st_size, is_macho)
        res = _CACHE.get(key)
        if res is None:
            res = self._collect(obj, ctx, path, is_macho)
            _CACHE[key] = res
            if len(_CACHE) > _CACHE_MAX:
                _CACHE.popitem(last=False)
        else:
            _CACHE.move_to_end(key)
        info = obj.meta.setdefault("macos", {})
        info.update({k: v for k, v in res.items() if not k.startswith("_")})
        if res.get("_trusted"):
            obj.meta["trusted_signer"] = res["_trusted"]
        if is_macho:
            self._detections(obj, ctx, res)

    def _collect(self, obj: ScanObject, ctx: ScanContext, path: str, is_macho: bool) -> dict:
        res: dict = {}
        q = getxattr(path, "com.apple.quarantine")
        if q:
            res["quarantine"] = parse_quarantine(q)
        wf = getxattr(path, "com.apple.metadata:kMDItemWhereFroms")
        if wf:
            try:
                v = plistlib.loads(wf)
                res["where_froms"] = [str(x) for x in v][:10] if isinstance(v, list) else [str(v)]
            except Exception:  # noqa: BLE001
                pass
        if q and "where_froms" not in res:
            w = _mdls_wherefroms(path)
            if w:
                res["where_froms"] = w
        if not is_macho:
            low = path.lower()
            if low.endswith(".dmg"):
                self._container_dmg(ctx, path, res)
            elif low.endswith((".pkg", ".mpkg")):
                self._container_pkg(ctx, path, res)
            return res
        cs_tool = ctx.tool("codesign") or shutil.which("codesign")
        if not cs_tool:
            return res
        cs = codesign_info(cs_tool, path)
        res["codesign"] = cs
        if cs.get("state") != "unsigned":
            ver = codesign_verify(cs_tool, path)
            res["codesign_verify"] = {k: v for k, v in ver.items() if k != "rc"}
        else:
            ver = {"valid": False, "not_signed": True}
        trusted = _trusted(cs, ver)
        if trusted:
            res["_trusted"] = trusted
            res["trusted_signer"] = trusted
            res["notarized"] = cs.get("notarization_ticket") == "stapled" or None
        sp_tool = ctx.tool("spctl") or shutil.which("spctl")
        if q and sp_tool:
            gk = spctl_assess(sp_tool, path, _bundle_of(path))
            res["gatekeeper"] = gk
            if gk.get("source", "").startswith("Notarized"):
                res["notarized"] = True
            if "CSSMERR_TP_CERT_REVOKED" in gk.get("message", ""):
                # A revoked signing certificate is only authoritative proof of malice when the signature is
                # NOT intact: Apple revokes malware developers' certs, but also rotates/revokes legitimate
                # Developer ID certs for benign reasons. A binary that still passes `codesign --verify --strict`
                # AND chains to Apple (trusted_signer set) was not tampered with – its cert was simply revoked
                # after the fact (common for notarized apps and their nested helpers, which keep running). Treat
                # that as a weak signal, not a 60-point revocation; keep full strength for broken/unsigned code.
                if ver.get("valid") and res.get("_trusted"):
                    res["cert_revoked_sig_intact"] = True
                else:
                    res["revoked"] = True
                    res.pop("_trusted", None)
                    res.pop("trusted_signer", None)
        if ver.get("revoked"):
            res["revoked"] = True
            res.pop("_trusted", None)
            res.pop("trusted_signer", None)
        return res

    @staticmethod
    def _container_dmg(ctx: ScanContext, path: str, res: dict) -> None:
        """A disk image can carry its own Developer ID signature (`codesign` signs DMGs): a valid one chaining
        to Apple makes the installer trusted as a whole, so context hints about "downloaded, unsigned" do not
        fire on it. The apps inside are still scanned and judged on their own."""
        cs_tool = ctx.tool("codesign") or shutil.which("codesign")
        if not cs_tool:
            return
        cs = codesign_info(cs_tool, path)
        if cs.get("state") in ("unsigned", "adhoc"):
            return
        ver = codesign_verify(cs_tool, path)
        trusted = _trusted(cs, ver)
        if trusted and not ver.get("revoked"):
            res["_trusted"] = res["trusted_signer"] = trusted

    @staticmethod
    def _container_pkg(ctx: ScanContext, path: str, res: dict) -> None:
        """Installer packages are signed with a "Developer ID Installer" certificate (`pkgutil --check-signature`)."""
        tool = shutil.which("pkgutil")
        if not tool:
            return
        rc, out = _run([tool, "--check-signature", path], CODESIGN_TIMEOUT)
        if rc != 0 or "signed by a developer certificate issued by apple" not in out.lower() \
                and "signed by a certificate trusted by mac os x" not in out.lower() \
                and "signed apple software" not in out.lower():
            return
        m = re.search(r"1\.\s+(Developer ID Installer:[^\n]+|Apple Software Update[^\n]*|Software Update[^\n]*)", out)
        if m and "revoked" not in out.lower():
            res["_trusted"] = res["trusted_signer"] = m.group(1).strip()

    @staticmethod
    def _detections(obj: ScanObject, ctx: ScanContext, res: dict) -> None:
        def fire(name, conf, score, desc, ev):
            ctx.detect(obj, Detection(name, "macos", conf, score, desc, [str(e)[:200] for e in ev if e]))

        q = res.get("quarantine")
        cs = res.get("codesign") or {}
        ver = res.get("codesign_verify") or {}
        gk = res.get("gatekeeper") or {}
        agent = (q or {}).get("agent")
        src = (res.get("where_froms") or [None])[0]
        revoked = bool(ver.get("revoked") or res.get("revoked"))
        if res.get("cert_revoked_post_notarization") and not revoked:
            fire("Heur:MachO.CertificateRevoked.AfterNotarization", Confidence.LOW, 10,
                 "Signing certificate was revoked after notarization; the notarized build still validates "
                 "(benign cert rotation unless other signals say otherwise)",
                 [gk.get("message"), *(cs.get("authorities") or [])[:1]])
        if revoked:
            fire("Heur:MachO.CertificateRevoked", Confidence.HIGH, 60,
                 "Signing certificate has been revoked by Apple (Gatekeeper refuses it)",
                 [ver.get("message") if ver.get("revoked") else gk.get("message"), *(cs.get("authorities") or [])[:1]])
        if ver.get("broken"):
            msg = (ver.get("message") or "").lower()
            code_mod = any(x in msg for x in ("code or signature have been modified", "invalid signature",
                                              "main executable failed strict validation", "code signature is not valid"))
            if code_mod:
                fire("Heur:MachO.Signature.Invalid", Confidence.MEDIUM, 35 if q else 30,
                     "Code signature is broken: the executable was modified after signing",
                     [ver.get("message"), *(cs.get("authorities") or [])[:1]])
            else:
                fire("Heur:MachO.Signature.Invalid", Confidence.MEDIUM if q else Confidence.LOW, 25 if q else 10,
                     "Bundle seal is broken: sealed resources were added, removed or modified after signing",
                     [ver.get("message"), *(cs.get("authorities") or [])[:1]])
        state = cs.get("state")
        if q and state == "unsigned":
            fire("Heur:MachO.Unsigned.Quarantined", Confidence.MEDIUM, 15,
                 "Downloaded executable that is not code-signed", [f"agent={agent}", src])
        elif q and state == "adhoc":
            fire("Heur:MachO.AdhocSigned.Quarantined", Confidence.LOW, 10,
                 "Downloaded executable with only an ad-hoc signature (no developer identity)",
                 [f"agent={agent}", src, f"identifier={cs.get('identifier')}"])
        elif q and state == "certificate" and gk and gk.get("rc") not in (None, 0) and not gk.get("not_an_app") \
                and not gk.get("skipped") and not revoked and not res.get("cert_revoked_sig_intact"):
            fire("Heur:MachO.Gatekeeper.Rejected", Confidence.MEDIUM, 20,
                 "Gatekeeper rejects this downloaded binary (not notarized / untrusted)",
                 [gk.get("message"), f"agent={agent}", src])
        if state == "certificate" and ver.get("untrusted") and not ver.get("revoked"):
            fire("Heur:MachO.Signature.Untrusted", Confidence.MEDIUM, 15,
                 "Signed with a certificate that does not chain to Apple", (cs.get("authorities") or [])[:2])
