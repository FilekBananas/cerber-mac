"""Linux/Android ELF heuristics (own struct parser – fast and tolerant of broken headers).

Analyzer "exe_elf" (order 40) for ftype "elf". Info goes to obj.meta["elf"].

Detections (engine "heuristic"):
    Heur:ELF.Malformed                    15  impossible header values / program headers outside the file
    Heur:ELF.SectionHeadersStripped       10  e_shnum == 0 with valid program headers (sstrip/UPX/IoT malware)
    Heur:ELF.SectionTable.Invalid         10  section header table points outside the file
    Heur:ELF.Segment.RWX                  15  PT_LOAD segment readable+writable+executable
    Heur:ELF.ExecutableStack               5  PT_GNU_STACK with PF_X
    Heur:ELF.EntryPoint.OutsideCode       20  entry point not inside an executable PT_LOAD segment
    Heur:ELF.Packed.HighEntropy           20  executable segment with near-random content
    Heur:ELF.Interpreter.Unusual          10  PT_INTERP not a standard dynamic loader
    Heur:ELF.RPath.Suspicious             10  DT_RPATH/RUNPATH in /tmp, /dev/shm or relative
    Heur:ELF.Rootkit.LibcHook          30/40  shared object that exports readdir/getdents/... and calls dlsym
    Heur:ELF.Rootkit.PreloadHijack        25  writes /etc/ld.so.preload (not the dynamic loader itself)
    Heur:ELF.LKM.Rootkit                  40  kernel module hooking sys_call_table/kallsyms + hiding strings
    Heur:ELF.Botnet.BusyboxProbe          30  "/bin/busybox RANDOM" applet probes (Mirai family)
    Heur:ELF.BruteForce.CredentialList    25  large default-credential wordlist + ssh/telnet
    Heur:ELF.Toolchain.<Name>              0  info: Go / Rust / Nim / PyInstaller ...
    + shared string rules from exe_misc (Heur:ELF.CoinMiner, Heur:ELF.ReverseShell, Heur:ELF.Mirai.Credentials,
      Heur:ELF.Botnet.DDoS, Heur:ELF.DefenseEvasion, Heur:ELF.Persistence, ...)
"""
from __future__ import annotations

import re
import struct

from ..core import Analyzer, Confidence, ScanContext, ScanObject
from . import register
from .exe_misc import apply_rules, det, go_buildinfo, onion_rule, runtime_cap, sampled_entropy, string_hits

PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_GNU_STACK = 1, 2, 3, 0x6474E551
PF_X, PF_W, PF_R = 1, 2, 4
SHT_SYMTAB, SHT_STRTAB, SHT_DYNSYM, SHT_NOBITS = 2, 3, 11, 8
ET_NAMES = {0: "none", 1: "rel", 2: "exec", 3: "dyn", 4: "core"}
MACHINES = {3: "x86", 0x3E: "x86_64", 0x28: "arm", 0xB7: "aarch64", 8: "mips", 0x14: "ppc", 0x15: "ppc64",
            0x2B: "sparcv9", 2: "sparc", 0x16: "s390", 0xF3: "riscv", 0x2A: "superh", 0x32: "ia64", 0x5C: "openrisc",
            0x102: "loongarch", 0xA4: "hexagon", 0x53: "avr", 0x9026: "alpha", 4: "m68k", 0x5D: "arc",
            0xBD: "microblaze", 0x8C: "tic6x", 0x59: "mn10300", 0x5E: "xtensa", 0xDC: "z80", 0x13: "i960",
            0x0A: "mips_rs3_le", 0x06: "i486", 0x07: "i860", 0x12: "sparc32plus", 0x24: "v850", 0x25: "m32r",
            0x2E: "h8_300", 0x3C: "st100", 0x57: "v850", 0x71: "arcompact", 0xAF: "tile64", 0xF7: "bpf",
            0xFC: "csky", 0x92: "aarch64be"}
STD_INTERP = re.compile(r"^(/lib(64|32|x32)?/|/usr/lib(64)?/|/system/bin/linker|/apex/|/libexec/ld-elf|"
                        r"/usr/libexec/ld\.so|/nix/store/|/lib/ld-musl|/usr/glibc-compat/|/gnu/store/|/opt/)")
LIBC_HOOKS = {"readdir", "readdir64", "readdir_r", "readdir64_r", "getdents", "getdents64", "opendir",
              "fopen", "fopen64", "open", "open64", "stat", "stat64", "lstat", "lstat64", "__xstat", "__lxstat",
              "__xstat64", "__lxstat64", "access", "unlink", "unlinkat", "accept", "pcap_loop", "kill", "rmdir",
              "fstatat", "__fxstatat"}
HIDE_HOOKS = {"readdir", "readdir64", "readdir_r", "readdir64_r", "getdents", "getdents64"}
INTERCEPTOR_SONAMES = re.compile(r"(?i)^(libc[.\-]|libc\.musl|ld-|libdl|libpthread|librt|libuclibc|ld64|"
                                 r".*clang_rt|.*asan|.*tsan|.*msan|.*lsan|.*ubsan|.*hwasan|libfakeroot|libfakechroot|"
                                 r"libproot|libtrash|libvalgrind|vgpreload|libgcc|libstdc|libc\+\+|libbionic|libsigsegv|"
                                 r"libtcmalloc|libjemalloc|libmimalloc|libeatmydata|libfaketime|libgtk3-nocsd|"
                                 r"libdmtcp|libwrap|libsandbox|libsnoopy|libstrace|libltrace|libheaptrack)")
COMMON_CREDS = {b"root", b"admin", b"123456", b"password", b"12345", b"1234", b"default", b"support", b"user",
                b"guest", b"ubnt", b"toor", b"raspberry", b"666666", b"888888", b"54321", b"pass", b"admin1234",
                b"1111", b"smcadmin", b"service", b"supervisor", b"administrator", b"12345678", b"123456789",
                b"qwerty", b"oracle", b"postgres", b"ftp", b"changeme", b"letmein", b"111111", b"000000",
                b"password1", b"abc123", b"1q2w3e4r", b"passw0rd", b"system", b"manager", b"tech", b"mother",
                b"realtek", b"vizxv", b"xc3511", b"juantech", b"anko", b"klv123", b"hi3518", b"7ujMko0admin"}
_BUSYBOX_RE = re.compile(rb"/bin/busybox [A-Z]{4,12}(?![A-Za-z])")
_CSTR_RE = re.compile(rb"(?<=\x00)[\x21-\x7e]{3,16}(?=\x00)")


class ELF:
    """Minimal ELF view: header, program/section headers, dynamic info, dynamic symbols."""

    def __init__(self, d: bytes, base: int = 0):
        self.d = d
        self.base = base
        self.errors: list[str] = []
        if d[base:base + 4] != b"\x7fELF" or len(d) - base < 52:
            raise ValueError("not ELF")
        self.cls = d[base + 4]
        self.le = d[base + 5] != 2
        e = "<" if self.le else ">"
        self.e = e
        if self.cls == 2:
            if len(d) - base < 64:
                raise ValueError("truncated ELF64 header")
            (self.type, self.machine, self.version, self.entry, self.phoff, self.shoff, self.flags, self.ehsize,
             self.phentsize, self.phnum, self.shentsize, self.shnum, self.shstrndx) = struct.unpack_from(
                e + "HHIQQQIHHHHHH", d, base + 16)
        elif self.cls == 1:
            (self.type, self.machine, self.version, self.entry, self.phoff, self.shoff, self.flags, self.ehsize,
             self.phentsize, self.phnum, self.shentsize, self.shnum, self.shstrndx) = struct.unpack_from(
                e + "HHIIIIIHHHHHH", d, base + 16)
        else:
            raise ValueError(f"bad EI_CLASS {self.cls}")
        self.phdrs: list[tuple[int, int, int, int, int, int]] = []  # type, flags, offset, vaddr, filesz, memsz
        self.shdrs: list[tuple[int, int, int, int, int, int, int]] = []  # name, type, flags, addr, offset, size, link
        self.sections: dict[str, tuple[int, int, int, int, int, int, int]] = {}
        self._parse_ph()
        self._parse_sh()

    # -- headers ---------------------------------------------------------------------
    def _parse_ph(self) -> None:
        d, b, e = self.d, self.base, self.e
        ent = 56 if self.cls == 2 else 32
        if self.phnum == 0:
            return
        if self.phentsize != ent:
            self.errors.append(f"e_phentsize {self.phentsize} != {ent}")
            return
        for i in range(min(self.phnum, 512)):
            o = b + self.phoff + i * ent
            if o + ent > len(d) or self.phoff <= 0:
                self.errors.append("program headers outside the file")
                break
            if self.cls == 2:
                t, fl, off, va, _pa, fsz, msz, _al = struct.unpack_from(e + "IIQQQQQQ", d, o)
            else:
                t, off, va, _pa, fsz, msz, fl, _al = struct.unpack_from(e + "IIIIIIII", d, o)
            self.phdrs.append((t, fl, off, va, fsz, msz))

    def _parse_sh(self) -> None:
        d, b, e = self.d, self.base, self.e
        ent = 64 if self.cls == 2 else 40
        if self.shnum == 0 or self.shoff == 0:
            return
        if self.shentsize != ent:
            self.errors.append(f"e_shentsize {self.shentsize} != {ent}")
            return
        if b + self.shoff + self.shnum * ent > len(d):
            self.errors.append("section header table outside the file")
            return
        for i in range(min(self.shnum, 8192)):
            o = b + self.shoff + i * ent
            if self.cls == 2:
                nm, t, fl, addr, off, sz, link, _info, _al, _es = struct.unpack_from(e + "IIQQQQIIQQ", d, o)
            else:
                nm, t, fl, addr, off, sz, link, _info, _al, _es = struct.unpack_from(e + "IIIIIIIIII", d, o)
            self.shdrs.append((nm, t, fl, addr, off, sz, link))
        if 0 < self.shstrndx < len(self.shdrs):
            _, _, _, _, stroff, strsz, _ = self.shdrs[self.shstrndx]
            for sh in self.shdrs:
                name = self.cstr(stroff, sh[0], strsz)
                if name and name not in self.sections:
                    self.sections[name] = sh

    def cstr(self, tab_off: int, idx: int, tab_size: int | None = None) -> str:
        o = self.base + tab_off + idx
        if o < 0 or o >= len(self.d) or (tab_size is not None and idx >= tab_size):
            return ""
        end = self.d.find(b"\x00", o, o + 512)
        if end < 0:
            return ""
        return self.d[o:end].decode("utf-8", "replace")

    def vaddr_to_off(self, va: int) -> int | None:
        for t, _fl, off, v, fsz, _m in self.phdrs:
            if t == PT_LOAD and v <= va < v + fsz:
                return off + (va - v)
        return None

    def extent(self) -> int:
        """Size of the image described by the headers (from base)."""
        ent_sh = 64 if self.cls == 2 else 40
        end = self.phoff + len(self.phdrs) * (56 if self.cls == 2 else 32)
        for t, _fl, off, _v, fsz, _m in self.phdrs:
            end = max(end, off + fsz)
        for _n, t, _f, _a, off, sz, _l in self.shdrs:
            if t != SHT_NOBITS:
                end = max(end, off + sz)
        if self.shnum and self.shoff:
            end = max(end, self.shoff + self.shnum * ent_sh)
        return end

    # -- dynamic -----------------------------------------------------------------------
    def dynamic(self) -> dict:
        info: dict = {"needed": [], "soname": None, "rpath": [], "runpath": []}
        dyn = next((p for p in self.phdrs if p[0] == PT_DYNAMIC), None)
        if not dyn:
            return info
        e = self.e
        ent = 16 if self.cls == 2 else 8
        fmt = e + ("qQ" if self.cls == 2 else "iI")
        entries = []
        o = self.base + dyn[2]
        for i in range(min(dyn[4] // ent, 4096)):
            if o + ent > len(self.d):
                break
            tag, val = struct.unpack_from(fmt, self.d, o)
            o += ent
            if tag == 0:
                break
            entries.append((tag, val))
        strtab = next((v for t, v in entries if t == 5), None)
        stroff = self.vaddr_to_off(strtab) if strtab is not None else None
        if stroff is None and ".dynstr" in self.sections:
            stroff = self.sections[".dynstr"][4]
        if stroff is None:
            return info
        for t, v in entries:
            if t == 1:
                info["needed"].append(self.cstr(stroff, v))
            elif t == 14:
                info["soname"] = self.cstr(stroff, v)
            elif t == 15:
                info["rpath"].append(self.cstr(stroff, v))
            elif t == 29:
                info["runpath"].append(self.cstr(stroff, v))
        info["needed"] = info["needed"][:128]
        return info

    def dynsyms(self, limit: int = 60000) -> tuple[set[str], set[str]]:
        """(exported function names, imported names) from .dynsym."""
        exp: set[str] = set()
        imp: set[str] = set()
        sh = self.sections.get(".dynsym")
        if sh is None:
            sh = next((s for s in self.shdrs if s[1] == SHT_DYNSYM), None)
        if sh is None or sh[6] >= len(self.shdrs):
            return exp, imp
        strsh = self.shdrs[sh[6]]
        ent = 24 if self.cls == 2 else 16
        off, size = self.base + sh[4], sh[5]
        n = min(size // ent, limit)
        if off + n * ent > len(self.d):
            n = max(0, (len(self.d) - off) // ent)
        fmt = self.e + ("IBBHQQ" if self.cls == 2 else "IIIBBH")
        for i in range(n):
            vals = struct.unpack_from(fmt, self.d, off + i * ent)
            if self.cls == 2:
                name, info, shndx = vals[0], vals[1], vals[3]
            else:
                name, info, shndx = vals[0], vals[3], vals[5]
            if not name:
                continue
            nm = self.cstr(strsh[4], name, strsh[5])
            if not nm:
                continue
            bind, typ = info >> 4, info & 0xF
            if shndx == 0:
                imp.add(nm)
            elif bind in (1, 2) and typ in (2, 10):
                exp.add(nm)
        return exp, imp


def elf_valid_at(d: bytes, off: int) -> bool:
    """Plausibility check for carving an embedded ELF."""
    if d[off:off + 4] != b"\x7fELF" or len(d) - off < 64:
        return False
    cls, enc, ver = d[off + 4], d[off + 5], d[off + 6]
    if cls not in (1, 2) or enc not in (1, 2) or ver != 1:
        return False
    e = "<" if enc == 1 else ">"
    et, mach, ver2 = struct.unpack_from(e + "HHI", d, off + 16)
    if et not in (1, 2, 3, 4) or ver2 != 1 or mach not in MACHINES:
        return False
    ehsize = struct.unpack_from(e + "H", d, off + (52 if cls == 2 else 40))[0]
    return ehsize == (64 if cls == 2 else 52)


def elf_extent(d: bytes, off: int = 0) -> int:
    try:
        return ELF(d, off).extent()
    except Exception:  # noqa: BLE001
        return 0


@register
class ELFAnalyzer(Analyzer):
    name = "exe_elf"
    order = 40

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype == "elf"

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        d = obj.data
        try:
            elf = ELF(d)
        except Exception as exc:  # noqa: BLE001
            ctx.detect(obj, det("Heur:ELF.Malformed", Confidence.MEDIUM, 15, f"ELF header unparseable: {exc}"))
            return
        meta: dict = obj.meta.setdefault("elf", {})
        meta.update({"class": 64 if elf.cls == 2 else 32, "endian": "le" if elf.le else "be",
                     "type": ET_NAMES.get(elf.type, str(elf.type)), "machine": MACHINES.get(elf.machine, hex(elf.machine)),
                     "entry": hex(elf.entry), "phnum": elf.phnum, "shnum": elf.shnum})
        for e in elf.errors:
            obj.errors.append(f"elf: {e}")
        is_prog = elf.type in (2, 3)
        loads = [p for p in elf.phdrs if p[0] == PT_LOAD]

        if elf.ehsize not in (52, 64) or (is_prog and not elf.phdrs) or \
                any("program headers outside" in e for e in elf.errors):
            ctx.detect(obj, det("Heur:ELF.Malformed", Confidence.MEDIUM, 15, "Inconsistent ELF headers",
                                elf.errors[:3] or [f"e_ehsize={elf.ehsize}"]))
        if is_prog and loads and (elf.shnum == 0 or elf.shoff == 0):
            ctx.detect(obj, det("Heur:ELF.SectionHeadersStripped", Confidence.LOW, 10,
                                "Section header table removed (sstrip/UPX – common in IoT malware)"))
        elif any("section header table outside" in e for e in elf.errors):
            ctx.detect(obj, det("Heur:ELF.SectionTable.Invalid", Confidence.LOW, 10,
                                "Section header table points outside the file (anti-analysis)"))

        # segments
        rwx = [p for p in loads if p[1] & 7 == 7]
        if rwx:
            ctx.detect(obj, det("Heur:ELF.Segment.RWX", Confidence.MEDIUM, 15,
                                "Loadable segment is readable, writable and executable (self-modifying/packed)",
                                [f"off={p[2]:#x} size={p[4]:#x}" for p in rwx[:3]]))
        stack = next((p for p in elf.phdrs if p[0] == PT_GNU_STACK), None)
        if stack and stack[1] & PF_X:
            ctx.detect(obj, det("Heur:ELF.ExecutableStack", Confidence.LOW, 5, "Executable stack requested"))
        if is_prog and elf.entry and loads:
            ep_seg = next((p for p in loads if p[3] <= elf.entry < p[3] + max(p[5], p[4])), None)
            if ep_seg is None or not ep_seg[1] & PF_X:
                ctx.detect(obj, det("Heur:ELF.EntryPoint.OutsideCode", Confidence.MEDIUM, 20,
                                    "Entry point is not inside an executable segment", [hex(elf.entry)]))
        hi = []
        # compressed instruction sets (Thumb-2, RISC-V C, MIPS16) reach ~7.3 bits/byte unpacked
        thr = 7.6 if elf.machine in (0x28, 0xF3, 8, 0x0A) else 7.4
        text = elf.sections.get(".text")
        if text and text[1] != SHT_NOBITS and text[5] >= 16384:
            ent = sampled_entropy(d, text[4], text[4] + text[5])
            meta["text_entropy"] = round(ent, 3)
            if ent >= thr:
                hi.append(f".text H={ent:.2f}")
        elif not elf.sections:
            for p in loads:
                if p[1] & PF_X and p[4] >= 16384 and p[2] < len(d):
                    ent = sampled_entropy(d, p[2], p[2] + p[4])
                    if ent >= thr:
                        hi.append(f"off={p[2]:#x} H={ent:.2f}")
        if hi:
            ctx.detect(obj, det("Heur:ELF.Packed.HighEntropy", Confidence.MEDIUM, 20,
                                "Executable segment with near-random content (packed/encrypted)", hi))

        # interpreter / dynamic
        interp = next((p for p in elf.phdrs if p[0] == PT_INTERP), None)
        interp_path = ""
        if interp:
            e = d.find(b"\x00", interp[2], interp[2] + 256)
            interp_path = d[interp[2]:e if e > 0 else interp[2] + 64].decode("latin-1", "replace")
            meta["interpreter"] = interp_path
            if interp_path and not STD_INTERP.match(interp_path):
                ctx.detect(obj, det("Heur:ELF.Interpreter.Unusual", Confidence.LOW, 10,
                                    "Non-standard program interpreter", [interp_path]))
        dyn = elf.dynamic()
        meta["static"] = interp is None and not any(p[0] == PT_DYNAMIC for p in elf.phdrs)
        meta["stripped"] = ".symtab" not in elf.sections and not any(s[1] == SHT_SYMTAB for s in elf.shdrs)
        meta["needed"] = dyn["needed"][:40]
        meta["soname"] = dyn["soname"]
        bad_rp = [r for rp in dyn["rpath"] + dyn["runpath"] for r in rp.split(":")
                  if r.startswith(("/tmp", "/dev/shm", "/var/tmp")) or (r and not r.startswith(("/", "$")))]
        if bad_rp:
            ctx.detect(obj, det("Heur:ELF.RPath.Suspicious", Confidence.LOW, 10,
                                "Library search path in a world-writable or relative directory", bad_rp[:5]))

        exp, imp = elf.dynsyms()
        soname = dyn["soname"] or obj.name
        is_loader = bool(re.match(r"(?i)^ld[-.]", soname or "")) or elf.type == 3 and interp is None and \
            "_dl_start" in exp
        interceptor = bool(INTERCEPTOR_SONAMES.match(soname or "")) or bool(INTERCEPTOR_SONAMES.match(obj.name))
        hooks = sorted(exp & LIBC_HOOKS)
        if hooks and "dlsym" in imp and not interceptor and (exp & HIDE_HOOKS):
            sc = 40 if len(hooks) >= 2 else 30
            ctx.detect(obj, det("Heur:ELF.Rootkit.LibcHook", Confidence.HIGH, sc,
                                "Preloadable library overrides directory-listing libc functions and chains via dlsym "
                                "(userland rootkit hiding files/processes)", hooks))

        # kernel module rootkits
        if elf.type == 1 and ".modinfo" in elf.sections:
            meta["kernel_module"] = True
            low = d[:32 << 20].lower()
            hook = [w for w in (b"sys_call_table", b"kallsyms_lookup_name", b"ftrace_set_filter_ip",
                                b"register_kprobe") if w in low]
            hide = [w for w in (b"hide_pid", b"hidden_pid", b"unhide", b"invisible", b"hide_module", b"rootkit",
                                b"getdents", b"hide_file", b"hidden_file") if w in low]
            if hook and len(hide) >= 2:
                ctx.detect(obj, det("Heur:ELF.LKM.Rootkit", Confidence.HIGH, 40,
                                    "Kernel module hooks syscalls/kallsyms and contains hiding logic",
                                    [x.decode() for x in hook + hide]))

        # strings
        hits, text = string_hits(d, "elf")
        tool = hits.labels("toolchain")
        gb = go_buildinfo(d)
        if gb:
            meta["go"] = gb
            if "Go" not in tool:
                tool.append("Go")
        meta["toolchain"] = tool
        for t in tool:
            ctx.detect(obj, det(f"Heur:ELF.Toolchain.{t}", Confidence.INFO, 0, f"Built with / packaged by {t}"))
        if hits.has("preload_file") and not is_loader and elf.type in (2, 3):
            ctx.detect(obj, det("Heur:ELF.Rootkit.PreloadHijack", Confidence.MEDIUM, 25,
                                "References /etc/ld.so.preload (global library injection / rootkit install)",
                                ["/etc/ld.so.preload"]))
        if hits.has("botnet_env", "/bin/busybox"):
            m = _BUSYBOX_RE.findall(d, 0, min(len(d), 16 << 20))
            if m:
                ctx.detect(obj, det("Heur:ELF.Botnet.BusyboxProbe", Confidence.MEDIUM, 30,
                                    "Probes /bin/busybox with a random applet name (Mirai-family scanner)",
                                    sorted({x.decode() for x in m})[:5]))
        if len(d) <= (24 << 20):
            creds = {m for m in _CSTR_RE.findall(d)} & COMMON_CREDS
            if len(creds) >= 15 and (b"ssh" in d or b"telnet" in d.lower()[:16 << 20]):
                ctx.detect(obj, det("Heur:ELF.BruteForce.CredentialList", Confidence.MEDIUM, 25,
                                    "Embedded default-credential wordlist (SSH/Telnet brute forcing)",
                                    sorted(c.decode() for c in creds)[:15]))
        apply_rules(obj, ctx, "ELF", hits, cap=runtime_cap(tool))
        onion_rule(obj, ctx, "ELF", text, hits)
