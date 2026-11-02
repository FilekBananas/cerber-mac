"""macOS Mach-O heuristics (own parser: load commands, code-signature superblob, entitlements).

Analyzer "exe_macho" (order 40) for ftype "macho" (thin files and the slices exe_unpack cuts out
of universal binaries). Info goes to obj.meta["macho"]: arch, filetype, flags, segments, dylibs,
rpaths, signature {state, flags, identifier, team_id, authorities, entitlements, apple_origin}, build
platforms, imports count, toolchain, go build info.

Detections (engine "heuristic"):
    Heur:MachO.Malformed                        15  inconsistent load commands (anti-analysis / corrupt)
    Heur:MachO.Unsigned                       2-10  no LC_CODE_SIGNATURE (arm64 executables must be signed)
    Heur:MachO.AdhocSigned                     1-3  ad-hoc signature (1 when only linker-signed; not for Apple
                                                    device-OS trust-cache code, see apple_origin())
    Heur:MachO.Entitlement.DisableLibraryValidation   1
    Heur:MachO.Entitlement.AllowUnsignedExecMemory    0  (info)
    Heur:MachO.Entitlement.AllowDyldEnv               2
    Heur:MachO.Entitlement.GetTaskAllow             1/3  3 on a Developer-ID signed (release) binary
    Heur:MachO.Entitlement.Debugger                   2
    Heur:MachO.Entitlement.DisableExecPageProtection  3
    Heur:MachO.AppleCodeMasquerade          15/25  signing identifier claims com.apple.* but code is not Apple-signed
    Heur:MachO.Entitlement.PrivateApple              20  com.apple.private.* on a non-Apple, non-App-Store binary
                                                  (Apple code = "Software Signing" CMS chain, or ad-hoc com.apple.*
                                                  code built for an Apple device OS: trust-cache signed, e.g. the
                                                  binaries of Xcode's DeveloperDiskImage.dmg)
    Heur:MachO.Entitlement.InjectionFriendly          5  hardened runtime + dyld env + no library validation, ad-hoc
    Heur:MachO.Dylib.SuspiciousPath          3/20  dylib loaded from /tmp, /Users/Shared, hidden dirs (3: /Users/<name>)
    Heur:MachO.RPath.Suspicious               5/10  relative (5) or world-writable (10) LC_RPATH
    Heur:MachO.DyldEnvironment                3/20  LC_DYLD_ENVIRONMENT (20 with DYLD_INSERT_LIBRARIES)
    Heur:MachO.NoPIE                           2/5  executable without MH_PIE
    Heur:MachO.ExecutableStack                  10  MH_ALLOW_STACK_EXECUTION
    Heur:MachO.Segment.RWX                      20  segment with initprot rwx
    Heur:MachO.Packed.HighEntropyText           20  __TEXT,__text near-random (packed/encrypted code)
    Heur:MachO.EncryptedSegment                 25  LC_ENCRYPTION_INFO cryptid != 0 outside App Store wrappers
    Heur:MachO.ProtectedSegment                  5  SG_PROTECTED_VERSION_1 segment
    Heur:MachO.NoEntryPoint                     10  MH_EXECUTE without LC_MAIN / LC_UNIXTHREAD
    Heur:MachO.LCUnixThread                      3  executable started via legacy LC_UNIXTHREAD
    Heur:MachO.API.PtraceDenyAttach              5  imports ptrace (PT_DENY_ATTACH anti-debugging; not for Go)
    Heur:MachO.API.TaskInjection              5/15  task_for_pid + mach_vm_write + remote thread creation (not on Apple code)
    Heur:MachO.API.EventTapKeylogger             5  keyboard event tap + unicode key string
    Heur:MachO.Toolchain.<Name>                  0  info: Go / Rust / PyInstaller / py2app / Electron / ...
    + shared string rules from exe_misc (Heur:MachO.Stealer.*, Heur:MachO.AntiVM, Heur:MachO.GatekeeperBypass,
      Heur:MachO.TCCTampering, Heur:MachO.ReverseShell, Heur:MachO.Downloader, ...)
"""
from __future__ import annotations

import plistlib
import re
import struct

from ..core import Analyzer, Confidence, ScanContext, ScanObject
from . import register
from .exe_misc import apply_rules, cstr, det, go_buildinfo, onion_rule, runtime_cap, sampled_entropy, string_hits
from .exe_pe import cert_common_names

MH_MAGIC = {b"\xce\xfa\xed\xfe": (False, False), b"\xcf\xfa\xed\xfe": (True, False),
            b"\xfe\xed\xfa\xce": (False, True), b"\xfe\xed\xfa\xcf": (True, True)}
CPU = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 0x0200000C: "arm64_32", 18: "ppc",
       0x01000012: "ppc64"}
FILETYPES = {1: "object", 2: "execute", 3: "fvmlib", 4: "core", 5: "preload", 6: "dylib", 7: "dylinker",
             8: "bundle", 9: "dylib_stub", 10: "dsym", 11: "kext_bundle", 12: "fileset", 13: "gpu_execute",
             14: "gpu_dylib"}
MH_EXECUTE, MH_DYLIB, MH_BUNDLE = 2, 6, 8
MH_PIE = 0x200000
MH_ALLOW_STACK_EXECUTION = 0x20000
LC_SEGMENT, LC_SEGMENT_64 = 0x1, 0x19
LC_SYMTAB, LC_DYSYMTAB, LC_UNIXTHREAD = 0x2, 0xB, 0x5
LC_LOAD_DYLIB, LC_ID_DYLIB, LC_LOAD_DYLINKER = 0xC, 0xD, 0xE
LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB, LC_LOAD_UPWARD_DYLIB = 0x80000018, 0x8000001F, 0x20, 0x80000023
LC_RPATH, LC_CODE_SIGNATURE, LC_MAIN = 0x8000001C, 0x1D, 0x80000028
LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64 = 0x21, 0x2C
LC_DYLD_ENVIRONMENT, LC_BUILD_VERSION, LC_VERSION_MIN_MACOSX, LC_UUID = 0x27, 0x32, 0x24, 0x1B
LC_VERSION_MIN_OTHER = {0x25: "ios", 0x2F: "tvos", 0x30: "watchos"}   # IPHONEOS / TVOS / WATCHOS
DYLIB_CMDS = {LC_LOAD_DYLIB: "load", LC_LOAD_WEAK_DYLIB: "weak", LC_REEXPORT_DYLIB: "reexport",
              LC_LAZY_LOAD_DYLIB: "lazy", LC_LOAD_UPWARD_DYLIB: "upward"}
PLATFORMS = {1: "macos", 2: "ios", 3: "tvos", 4: "watchos", 5: "bridgeos", 6: "maccatalyst", 7: "ios-sim",
             8: "tvos-sim", 9: "watchos-sim", 10: "driverkit", 11: "visionos", 12: "visionos-sim"}
# Apple device operating systems: their system code is ad-hoc signed and authorised by a trust cache
# (no CMS certificate chain). Binaries built for them cannot run on a Mac (simulator / Catalyst builds can,
# so those are not listed).
DEVICE_PLATFORMS = frozenset({"ios", "tvos", "watchos", "bridgeos", "visionos"})

CS_ADHOC, CS_RUNTIME, CS_LINKER_SIGNED = 0x2, 0x10000, 0x20000
CS_FLAG_NAMES = {0x1: "host", 0x2: "adhoc", 0x4: "get-task-allow", 0x100: "hard", 0x200: "kill",
                 0x400: "check-expiration", 0x800: "restrict", 0x1000: "enforcement", 0x2000: "library-validation",
                 0x10000: "runtime", 0x20000: "linker-signed"}
MAX_CMDS = 4096
MAX_SYMS = 40000

# hardened-runtime exceptions: informational on their own (common in Electron/JIT/plugin hosts)
DANGEROUS_ENTS = {
    "com.apple.security.cs.disable-library-validation": ("DisableLibraryValidation", 1),
    "com.apple.security.cs.allow-unsigned-executable-memory": ("AllowUnsignedExecMemory", 0),
    "com.apple.security.cs.allow-dyld-environment-variables": ("AllowDyldEnv", 2),
    "com.apple.security.cs.debugger": ("Debugger", 2),
    "com.apple.security.cs.disable-executable-page-protection": ("DisableExecPageProtection", 3),
}
BAD_DYLIB_PREFIX = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/", "/dev/shm/",
                    "/Volumes/")


def arch_name(cputype: int, subtype: int) -> str:
    name = CPU.get(cputype, f"cpu{cputype:#x}")
    if cputype == 0x0100000C and (subtype & 0xFF) == 2:
        return "arm64e"
    if cputype == 0x01000007 and (subtype & 0xFF) == 8:
        return "x86_64h"
    return name


class MachO:
    """Thin Mach-O parsed at data[base:]; all file offsets are relative to base."""

    def __init__(self, d: bytes, base: int = 0):
        self.d, self.base = d, base
        magic = d[base:base + 4]
        if magic not in MH_MAGIC:
            raise ValueError("not a thin Mach-O")
        self.is64, self.be = MH_MAGIC[magic]
        e = ">" if self.be else "<"
        self.e = e
        (self.cputype, self.subtype, self.filetype, self.ncmds, self.sizeofcmds,
         self.flags) = struct.unpack_from(e + "iiIIII", d, base + 4)
        self.cputype &= 0xFFFFFFFF
        self.hdr = 32 if self.is64 else 28
        self.errors: list[str] = []
        self.segments: list[dict] = []
        self.dylibs: list[tuple[str, str]] = []
        self.rpaths: list[str] = []
        self.dyld_env: list[str] = []
        self.dylinker = None
        self.id_dylib = None
        self.codesig: tuple[int, int] | None = None
        self.encryption: list[tuple[int, int, int]] = []
        self.main = None
        self.unixthread = False
        self.symtab = None
        self.dysymtab = None
        self.build = None
        self.platforms: set[str] = set()   # every platform a LC_BUILD_VERSION / LC_VERSION_MIN_* declares
        self.uuid = None
        self._parse()

    @property
    def arch(self) -> str:
        return arch_name(self.cputype, self.subtype)

    def _lcstr(self, cmd_off: int, cmdsize: int, rel: int) -> str:
        if rel < 8 or rel >= cmdsize:
            return ""
        return cstr(self.d, cmd_off + rel, min(1024, cmdsize - rel))

    def _parse(self) -> None:
        d, e, b = self.d, self.e, self.base
        o = b + self.hdr
        end = o + self.sizeofcmds
        if end > len(d):
            self.errors.append("sizeofcmds beyond end of file")
            end = len(d)
        if self.ncmds > MAX_CMDS:
            self.errors.append(f"ncmds={self.ncmds} too large")
        for _ in range(min(self.ncmds, MAX_CMDS)):
            if o + 8 > end:
                self.errors.append("load commands truncated")
                break
            cmd, cmdsize = struct.unpack_from(e + "II", d, o)
            if cmdsize < 8 or o + cmdsize > end or cmdsize % 4:
                self.errors.append(f"bad cmdsize {cmdsize} for cmd {cmd:#x}")
                break
            try:
                self._cmd(cmd, o, cmdsize)
            except struct.error:
                self.errors.append(f"truncated load command {cmd:#x}")
            o += cmdsize

    def _cmd(self, cmd: int, o: int, size: int) -> None:
        d, e = self.d, self.e
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            if cmd == LC_SEGMENT_64:
                name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack_from(
                    e + "16sQQQQiiII", d, o + 8)
                so, ssz = o + 72, 80
            else:
                name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack_from(
                    e + "16sIIIIiiII", d, o + 8)
                so, ssz = o + 56, 68
            seg = {"name": name.rstrip(b"\x00").decode("latin-1"), "vmaddr": vmaddr, "vmsize": vmsize,
                   "fileoff": fileoff, "filesize": filesize, "maxprot": maxprot & 7, "initprot": initprot & 7,
                   "flags": flags, "sections": []}
            for i in range(min(nsects, 256)):
                p = so + i * ssz
                if p + ssz > o + size:
                    self.errors.append("section headers beyond segment command")
                    break
                if cmd == LC_SEGMENT_64:
                    sn, sg, addr, sz, off, _al, _ro, _nr, sfl = struct.unpack_from(e + "16s16sQQIIIII", d, p)
                else:
                    sn, sg, addr, sz, off, _al, _ro, _nr, sfl = struct.unpack_from(e + "16s16sIIIIIII", d, p)
                seg["sections"].append({"name": sn.rstrip(b"\x00").decode("latin-1"), "addr": addr, "size": sz,
                                        "offset": off, "flags": sfl})
            self.segments.append(seg)
        elif cmd in DYLIB_CMDS:
            rel = struct.unpack_from(e + "I", d, o + 8)[0]
            self.dylibs.append((DYLIB_CMDS[cmd], self._lcstr(o, size, rel)))
        elif cmd == LC_ID_DYLIB:
            self.id_dylib = self._lcstr(o, size, struct.unpack_from(e + "I", d, o + 8)[0])
        elif cmd == LC_LOAD_DYLINKER:
            self.dylinker = self._lcstr(o, size, struct.unpack_from(e + "I", d, o + 8)[0])
        elif cmd == LC_RPATH:
            self.rpaths.append(self._lcstr(o, size, struct.unpack_from(e + "I", d, o + 8)[0]))
        elif cmd == LC_DYLD_ENVIRONMENT:
            self.dyld_env.append(self._lcstr(o, size, struct.unpack_from(e + "I", d, o + 8)[0]))
        elif cmd == LC_CODE_SIGNATURE:
            self.codesig = struct.unpack_from(e + "II", d, o + 8)
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            self.encryption.append(struct.unpack_from(e + "III", d, o + 8))
        elif cmd == LC_MAIN:
            self.main = struct.unpack_from(e + "Q", d, o + 8)[0]
        elif cmd == LC_UNIXTHREAD:
            self.unixthread = True
        elif cmd == LC_SYMTAB:
            self.symtab = struct.unpack_from(e + "IIII", d, o + 8)
        elif cmd == LC_DYSYMTAB:
            self.dysymtab = struct.unpack_from(e + "IIIIII", d, o + 8)
        elif cmd == LC_BUILD_VERSION:
            plat, minos, sdk = struct.unpack_from(e + "III", d, o + 8)
            self.build = (PLATFORMS.get(plat, str(plat)), _ver(minos), _ver(sdk))
            self.platforms.add(self.build[0])
        elif cmd == LC_VERSION_MIN_MACOSX or cmd in LC_VERSION_MIN_OTHER:
            minos, sdk = struct.unpack_from(e + "II", d, o + 8)
            self.platforms.add(LC_VERSION_MIN_OTHER.get(cmd, "macos"))
            if self.build is None:
                self.build = (LC_VERSION_MIN_OTHER.get(cmd, "macos"), _ver(minos), _ver(sdk))
        elif cmd == LC_UUID:
            self.uuid = d[o + 8:o + 24].hex()

    # -- derived ---------------------------------------------------------------------
    def extent(self) -> int:
        end = self.hdr + self.sizeofcmds
        for s in self.segments:
            if s["filesize"]:
                end = max(end, s["fileoff"] + s["filesize"])
        if self.codesig:
            end = max(end, self.codesig[0] + self.codesig[1])
        if self.symtab:
            end = max(end, self.symtab[2] + self.symtab[3])
        return end

    def section(self, seg: str, sect: str) -> dict | None:
        for s in self.segments:
            if s["name"] == seg:
                for x in s["sections"]:
                    if x["name"] == sect:
                        return x
        return None

    def undefined_symbols(self) -> set[str]:
        out: set[str] = set()
        if not self.symtab:
            return out
        symoff, nsyms, stroff, strsize = self.symtab
        ent = 16 if self.is64 else 12
        if self.dysymtab:
            _il, _nl, _ie, _ne, iu, nu = self.dysymtab
            first, count = iu, nu
        else:
            first, count = 0, nsyms
        count = min(count, MAX_SYMS, max(0, nsyms - first))
        b = self.base + symoff + first * ent
        if b + count * ent > len(self.d) or count <= 0:
            return out
        fmt = self.e + ("IBBHQ" if self.is64 else "IBBHI")
        sb = self.base + stroff
        for i in range(count):
            strx, ntype, _sect, _desc, _val = struct.unpack_from(fmt, self.d, b + i * ent)
            if not self.dysymtab and ((ntype & 0x0E) != 0 or not (ntype & 0x01) or ntype & 0xE0):
                continue
            if 0 < strx < strsize:
                nm = cstr(self.d, sb + strx, 256)
                if nm:
                    out.add(nm)
        return out


def _ver(v: int) -> str:
    return f"{v >> 16}.{(v >> 8) & 0xFF}.{v & 0xFF}"


def macho_valid_at(d: bytes, off: int) -> bool:
    """Plausibility check for carving an embedded thin Mach-O."""
    magic = d[off:off + 4]
    if magic not in MH_MAGIC or len(d) - off < 64:
        return False
    is64, be = MH_MAGIC[magic]
    e = ">" if be else "<"
    cpu, _sub, ft, ncmds, sizeofcmds, _fl = struct.unpack_from(e + "iiIIII", d, off + 4)
    if (cpu & 0xFFFFFFFF) not in CPU or ft not in FILETYPES or not 1 <= ncmds <= 512:
        return False
    hdr = 32 if is64 else 28
    if sizeofcmds < 8 * ncmds or off + hdr + sizeofcmds > len(d) or sizeofcmds > (1 << 20):
        return False
    cmd, cmdsize = struct.unpack_from(e + "II", d, off + hdr)
    return cmdsize >= 8 and cmdsize % 4 == 0 and cmdsize <= sizeofcmds


def macho_extent(d: bytes, off: int = 0) -> int:
    try:
        return MachO(d, off).extent()
    except Exception:  # noqa: BLE001
        return 0


# ---------------------------------------------------------------------------
# code signature
# ---------------------------------------------------------------------------
def parse_codesig(d: bytes, off: int, size: int) -> dict:
    sig: dict = {"state": "invalid"}
    end = min(len(d), off + size)
    if off + 12 > end:
        sig["error"] = "signature outside file"
        return sig
    magic, length, count = struct.unpack_from(">III", d, off)
    if magic != 0xFADE0CC0:
        sig["error"] = f"bad superblob magic {magic:#x}"
        return sig
    cds, ents_xml, cms = [], None, None
    for i in range(min(count, 64)):
        p = off + 12 + i * 8
        if p + 8 > end:
            break
        typ, boff = struct.unpack_from(">II", d, p)
        bo = off + boff
        if bo + 8 > end:
            continue
        bmagic, blen = struct.unpack_from(">II", d, bo)
        blob = d[bo:min(end, bo + blen)]
        if bmagic == 0xFADE0C02:
            cds.append(blob)
        elif bmagic == 0xFADE7171:
            ents_xml = blob[8:]
        elif bmagic == 0xFADE0B01:
            cms = blob[8:]
    if not cds:
        sig["error"] = "no CodeDirectory"
        return sig
    cd = cds[0]
    ver, flags = struct.unpack_from(">II", cd, 8)
    ident_off = struct.unpack_from(">I", cd, 20)[0]
    platform = cd[38] if len(cd) > 38 else 0
    team = None
    if ver >= 0x20200 and len(cd) >= 52:
        toff = struct.unpack_from(">I", cd, 48)[0]
        if toff:
            team = cstr(cd, toff, 64) or None
    exec_flags = None
    if ver >= 0x20400 and len(cd) >= 88:
        exec_flags = struct.unpack_from(">Q", cd, 80)[0]
    sig.update({"state": "signed", "cd_version": hex(ver), "flags": flags,
                "flag_names": [n for b, n in CS_FLAG_NAMES.items() if flags & b],
                "identifier": cstr(cd, ident_off, 256) if ident_off else None, "team_id": team,
                "platform": platform, "exec_seg_flags": exec_flags, "code_directories": len(cds)})
    ents: dict = {}
    if ents_xml:
        try:
            ents = plistlib.loads(ents_xml)
            if not isinstance(ents, dict):
                ents = {}
        except Exception:  # noqa: BLE001
            ents = {k: True for k in re.findall(r"<key>([^<]{3,200})</key>", ents_xml.decode("utf-8", "replace"))}
    sig["entitlements"] = sorted(ents)[:64]
    sig["_ents"] = ents
    auth = cert_common_names(cms) if cms and len(cms) > 16 else []
    # CMS stores the chain in arbitrary order: leaf certificates first, CAs/timestamping last
    ca_words = ("Certification Authority", "Root CA", "Timestamp")
    auth = [a for a in auth if not any(w in a for w in ca_words)] + [a for a in auth if any(w in a for w in ca_words)]
    sig["authorities"] = auth
    if flags & CS_ADHOC or not auth:
        sig["state"] = "linker-signed" if flags & CS_LINKER_SIGNED else "adhoc"
    else:
        def has(*prefixes: str) -> bool:
            return any(a.startswith(prefixes) for a in auth)
        if has("Developer ID Application"):
            sig["state"] = "developer-id"
        elif "Software Signing" in auth and "Apple Code Signing Certification Authority" in auth:
            sig["state"] = "apple"
        elif has("Apple Mac OS Application Signing", "Apple iPhone OS Application Signing"):
            sig["state"] = "app-store"
        elif has("Apple Development", "Mac Developer", "iPhone Developer"):
            sig["state"] = "development"
        elif has("Apple Distribution", "3rd Party Mac Developer", "iPhone Distribution"):
            sig["state"] = "distribution"
        else:
            sig["state"] = "other-certificate"
    return sig


def apple_origin(sig: dict, platforms: set[str] | frozenset[str] = frozenset()) -> str | None:
    """Recognise Apple's own code statically from the embedded signature (works for Mach-Os nested in disk
    images / packages, where codesign cannot run):

    "apple"       CMS chain "Software Signing" <- "Apple Code Signing Certification Authority" (macOS system
                  code, Xcode, Apple tools), or a CodeDirectory platform-binary identifier.
    "trustcache"  ad-hoc signature, CodeDirectory identifier com.apple.*, no team id, built only for Apple device
                  OSes (iOS/tvOS/watchOS/visionOS/bridgeOS). This is how Apple ships device system code
                  (Xcode DeveloperDiskImage.dmg, personalized DDIs, IPSW cryptexes): authorised by the device's
                  trust cache instead of a certificate. Every declared platform must be a device OS, so a Mac
                  binary cannot claim it by adding an extra iOS build-version command; such code cannot run on macOS.
    """
    state = sig.get("state")
    if state == "apple" or sig.get("platform"):
        return "apple"
    ident = sig.get("identifier") or ""
    if state == "adhoc" and ident.startswith("com.apple.") and not sig.get("team_id") and platforms \
            and set(platforms) <= DEVICE_PLATFORMS:
        return "trustcache"
    return None


@register
class MachOAnalyzer(Analyzer):
    name = "exe_macho"
    order = 40

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype == "macho"

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        d = obj.data
        try:
            m = MachO(d)
        except Exception as exc:  # noqa: BLE001
            ctx.detect(obj, det("Heur:MachO.Malformed", Confidence.MEDIUM, 15, f"Mach-O header unparseable: {exc}"))
            return
        ft = m.filetype
        meta: dict = obj.meta.setdefault("macho", {})
        meta.update({"arch": m.arch, "filetype": FILETYPES.get(ft, str(ft)), "flags": hex(m.flags),
                     "ncmds": m.ncmds, "pie": bool(m.flags & MH_PIE), "uuid": m.uuid,
                     "build": list(m.build) if m.build else None, "platforms": sorted(m.platforms),
                     "segments": [{k: s[k] for k in ("name", "fileoff", "filesize", "vmsize", "initprot", "maxprot")}
                                  for s in m.segments[:32]],
                     "dylibs": [p for _, p in m.dylibs][:80], "rpaths": m.rpaths[:20],
                     "id_dylib": m.id_dylib})
        carved = bool(obj.meta.get("carved"))   # extent derived from headers: integrity checks unreliable
        for er in m.errors:
            obj.errors.append(f"macho: {er}")
        if m.errors and not carved:
            ctx.detect(obj, det("Heur:MachO.Malformed", Confidence.MEDIUM, 15,
                                "Inconsistent Mach-O load commands (corrupt or anti-analysis)", m.errors[:3]))
        linkable = ft in (MH_EXECUTE, MH_DYLIB, MH_BUNDLE, 7) and not carved
        is_exec = ft == MH_EXECUTE
        arm = m.cputype in (0x0100000C, 0x0200000C)
        rootmeta = obj.root().meta

        # ---- code signature ------------------------------------------------------------
        sig: dict = {"state": "unsigned"}
        if m.codesig:
            off, size = m.codesig
            sig = parse_codesig(d, off, size)
        ents = sig.pop("_ents", {}) if isinstance(sig.get("_ents"), dict) else {}
        meta["signature"] = sig
        state = sig["state"]
        origin = apple_origin(sig, m.platforms)
        if origin:
            sig["apple_origin"] = origin
        apple = origin is not None
        if linkable and state == "unsigned":
            sc = (5 if is_exec else 2) + (5 if arm else 0)
            ctx.detect(obj, det("Heur:MachO.Unsigned", Confidence.LOW, sc,
                                "Mach-O without a code signature" + (" (cannot run on Apple Silicon as is)" if arm else "")))
        elif linkable and state in ("adhoc", "linker-signed") and origin != "trustcache":
            ctx.detect(obj, det("Heur:MachO.AdhocSigned", Confidence.LOW, 1 if state == "linker-signed" else 3,
                                "Ad-hoc signature (no developer identity)",
                                [f"identifier={sig.get('identifier')}", f"flags={sig.get('flags', 0):#x}"]))
        elif state == "invalid" and m.codesig and not carved:
            ctx.detect(obj, det("Heur:MachO.Malformed", Confidence.MEDIUM, 15, "Corrupt code-signature blob",
                                [sig.get("error", "")]))
        if ents:
            self._entitlements(obj, ctx, ents, sig, apple)
        # Apple masquerade: the code-signing identifier claims Apple ownership (com.apple.*) but the code is
        # not Apple-signed and is not a Mac App Store app (Apple's own App Store titles). Stealers/adware name
        # their binaries com.apple.* to blend in. Not applied to Apple's own code / trust-cache device code.
        ident = sig.get("identifier") or ""
        if ident.startswith("com.apple.") and not apple and state != "app-store":
            strong = state in ("unsigned", "adhoc", "linker-signed", "invalid")
            ctx.detect(obj, det("Heur:MachO.AppleCodeMasquerade", Confidence.MEDIUM, 25 if strong else 15,
                                "Code-signing identifier claims Apple (com.apple.*) but the binary is not Apple-signed",
                                [f"identifier={ident}", f"state={state}", f"team_id={sig.get('team_id')}"]))

        # ---- dylibs / rpaths / dyld env ----------------------------------------------------
        bad = []
        for kind, p in m.dylibs:
            if p.startswith(BAD_DYLIB_PREFIX) or "/." in p.replace("/..", "") and not p.startswith("@"):
                bad.append((20, p))
            elif re.match(r"^/Users/[^/]+/", p):
                bad.append((3, p))
        if bad:
            sc = max(s for s, _ in bad)
            ctx.detect(obj, det("Heur:MachO.Dylib.SuspiciousPath", Confidence.MEDIUM if sc >= 20 else Confidence.LOW, sc,
                                "Loads a dylib from a world-writable / hidden / user directory", [p for _, p in bad]))
        brp = [r for r in m.rpaths if r.startswith(BAD_DYLIB_PREFIX)]
        rel = [r for r in m.rpaths if not r.startswith(("/", "@"))]
        if brp or (rel and not apple):
            ctx.detect(obj, det("Heur:MachO.RPath.Suspicious", Confidence.LOW, 10 if brp else 5,
                                "World-writable or relative LC_RPATH (dylib hijacking)", brp + rel))
        env = [x for x in m.dyld_env if not x.startswith(("DYLD_VERSIONED_FRAMEWORK_PATH=", "DYLD_VERSIONED_LIBRARY_PATH="))]
        if env:
            ins = any("DYLD_INSERT_LIBRARIES" in x for x in env)
            ctx.detect(obj, det("Heur:MachO.DyldEnvironment", Confidence.MEDIUM if ins else Confidence.LOW,
                                20 if ins else 3, "Binary embeds dyld environment variables", env[:5]))

        # ---- header flags / segments ------------------------------------------------------
        if is_exec and not m.flags & MH_PIE and m.cputype in (7, 0x01000007):
            ctx.detect(obj, det("Heur:MachO.NoPIE", Confidence.LOW, 2 if m.cputype == 7 else 5,
                                "Executable without ASLR (MH_PIE not set)"))
        if m.flags & MH_ALLOW_STACK_EXECUTION:
            ctx.detect(obj, det("Heur:MachO.ExecutableStack", Confidence.MEDIUM, 10, "Executable stack allowed"))
        rwx = [s["name"] for s in m.segments if s["initprot"] == 7 and ft != 1
               and not (m.cputype == 7 and s["name"] == "__IMPORT")]
        if rwx:
            ctx.detect(obj, det("Heur:MachO.Segment.RWX", Confidence.MEDIUM, 20,
                                "Segment mapped read+write+execute at load (packer / self-modifying code)", rwx))
        prot = [s["name"] for s in m.segments if s["flags"] & 0x8]
        if prot and not apple:
            ctx.detect(obj, det("Heur:MachO.ProtectedSegment", Confidence.LOW, 5, "SG_PROTECTED_VERSION_1 segment", prot))
        enc = [x for x in m.encryption if x[2] != 0]
        meta["encrypted"] = bool(enc)
        wrapped = any(t in obj.display_path for t in ("/Wrapper/", "WrappedBundle", ".app/Wrapper"))
        if enc and not wrapped:
            ctx.detect(obj, det("Heur:MachO.EncryptedSegment", Confidence.MEDIUM, 25,
                                "Encrypted segment (LC_ENCRYPTION_INFO cryptid != 0) outside an App Store wrapper",
                                [f"cryptoff={x[0]:#x} size={x[1]:#x} id={x[2]}" for x in enc]))
        text = m.section("__TEXT", "__text")
        if text and text["size"] >= 16384 and not enc and not prot and text["offset"] < len(d):
            ent = sampled_entropy(d, text["offset"], text["offset"] + text["size"])
            meta["text_entropy"] = round(ent, 3)
            if ent >= (7.6 if m.cputype == 12 else 7.4):
                ctx.detect(obj, det("Heur:MachO.Packed.HighEntropyText", Confidence.MEDIUM, 20,
                                    "__TEXT,__text is near-random (packed or encrypted code)", [f"H={ent:.2f}"]))
        if is_exec and m.main is None and not m.unixthread:
            ctx.detect(obj, det("Heur:MachO.NoEntryPoint", Confidence.LOW, 10, "Executable without LC_MAIN/LC_UNIXTHREAD"))
        elif is_exec and m.main is None and m.unixthread and m.cputype in (0x0100000C, 0x01000007):
            ctx.detect(obj, det("Heur:MachO.LCUnixThread", Confidence.LOW, 3,
                                "64-bit executable started via legacy LC_UNIXTHREAD (static/packed)"))

        # ---- imports ---------------------------------------------------------------------
        imps = m.undefined_symbols()
        meta["imports"] = len(imps)
        debugger_ent = "com.apple.security.cs.debugger" in ents
        is_go = bool(go_buildinfo(d)) or "_runtime.main" in imps or any(s.startswith("_go:") for s in list(imps)[:50])
        if "_ptrace" in imps and not debugger_ent and not apple and not is_go:
            ctx.detect(obj, det("Heur:MachO.API.PtraceDenyAttach", Confidence.LOW, 5,
                                "Imports ptrace (PT_DENY_ATTACH anti-debugging)", ["_ptrace"]))
        inj = [s for s in ("_task_for_pid", "_mach_vm_write", "_vm_write", "_thread_create_running",
                           "_mach_vm_allocate", "_thread_create") if s in imps]
        if "_task_for_pid" in inj and ({"_mach_vm_write", "_vm_write"} & set(inj)) and \
                ({"_thread_create_running", "_thread_create"} & set(inj)) and not apple:
            ctx.detect(obj, det("Heur:MachO.API.TaskInjection", Confidence.LOW, 5 if debugger_ent else 15,
                                "task_for_pid + remote memory write + remote thread (code injection)", inj))
        if "_CGEventTapCreate" in imps and "_CGEventKeyboardGetUnicodeString" in imps and not apple:
            ctx.detect(obj, det("Heur:MachO.API.EventTapKeylogger", Confidence.LOW, 5,
                                "Global keyboard event tap reading typed characters",
                                ["_CGEventTapCreate", "_CGEventKeyboardGetUnicodeString"]))

        # ---- strings ---------------------------------------------------------------------
        hits, txt = string_hits(d, "macho")
        tool = hits.labels("toolchain")
        gb = go_buildinfo(d)
        if gb:
            meta["go"] = gb
            if "Go" not in tool:
                tool.append("Go")
        if any("Python.framework" in p or "libpython" in p for _, p in m.dylibs):
            tool.append("Python-embedded")
        meta["toolchain"] = sorted(set(tool))
        for t in meta["toolchain"]:
            ctx.detect(obj, det(f"Heur:MachO.Toolchain.{t}", Confidence.INFO, 0, f"Built with / packaged by {t}"))
        cap = runtime_cap(meta["toolchain"])
        if apple:
            # Apple's own tools legitimately implement keychain/dscl/launchctl functionality
            cap = {s: 0 for s in ("Stealer.Keychain", "Persistence.LaunchAgent", "Stealer.UserData",
                                  "Downloader", "GatekeeperBypass", "AntiVM", "Stealer.PasswordValidation")}
        apply_rules(obj, ctx, "MachO", hits, cap=cap)
        onion_rule(obj, ctx, "MachO", txt, hits)
        if rootmeta.get("trusted_signer"):
            meta["trusted_signer"] = rootmeta["trusted_signer"]

    @staticmethod
    def _entitlements(obj, ctx, ents: dict, sig: dict, apple: bool) -> None:
        state = sig.get("state")
        injection_friendly = ents.get("com.apple.security.cs.allow-dyld-environment-variables") is True and \
            ents.get("com.apple.security.cs.disable-library-validation") is True and \
            state in ("adhoc", "linker-signed", "other-certificate") and bool(sig.get("flags", 0) & CS_RUNTIME)
        for key, (label, score) in DANGEROUS_ENTS.items():
            if injection_friendly and label in ("AllowDyldEnv", "DisableLibraryValidation"):
                continue  # reported together below
            if ents.get(key) is True:
                ctx.detect(obj, det(f"Heur:MachO.Entitlement.{label}", Confidence.LOW if score else Confidence.INFO,
                                    score, f"Entitlement {key}", [key]))
        if ents.get("com.apple.security.get-task-allow") is True:
            rel = state == "developer-id"
            ctx.detect(obj, det("Heur:MachO.Entitlement.GetTaskAllow", Confidence.LOW, 3 if rel else 1,
                                "get-task-allow (debuggable)" + (" on a Developer ID release build – not notarizable"
                                                                 if rel else ""), ["com.apple.security.get-task-allow"]))
        priv = [k for k in ents if k.startswith("com.apple.private.")]
        if priv and not apple and state != "app-store":
            ctx.detect(obj, det("Heur:MachO.Entitlement.PrivateApple", Confidence.MEDIUM, 20,
                                "Apple-private entitlements on a non-Apple binary", priv[:6]))
        if injection_friendly:
            ctx.detect(obj, det("Heur:MachO.Entitlement.InjectionFriendly", Confidence.LOW, 5,
                                "Allows DYLD_* injection of unvalidated libraries on an unidentified binary",
                                ["allow-dyld-environment-variables", "disable-library-validation"]))
