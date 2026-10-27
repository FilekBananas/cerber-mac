"""Minimal, fast executable structure parser (PE / ELF / Mach-O thin).

Only what signature offsets need: entry point *file offset* and the section
table (raw file offset + raw size). Never raises; returns None for garbage.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field


@dataclass
class Section:
    name: str
    raw_off: int
    raw_size: int
    vaddr: int
    vsize: int


@dataclass
class ExeInfo:
    kind: str                     # pe | elf | macho
    ep: int | None                # entry point file offset
    sections: list[Section] = field(default_factory=list)
    is_64: bool = False
    machine: int = 0
    extra: dict = field(default_factory=dict)

    @property
    def nsections(self) -> int:
        return len(self.sections)


def parse(data: bytes, ftype: str | None = None) -> ExeInfo | None:
    try:
        if data[:2] == b"MZ":
            return _pe(data)
        if data[:4] == b"\x7fELF":
            return _elf(data)
        if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
            return _macho(data)
    except (struct.error, IndexError, ValueError):
        return None
    return None


def _rva_to_off(rva: int, sections: list[Section], headers_size: int) -> int | None:
    for s in sections:
        span = max(s.vsize, s.raw_size)
        if s.vaddr <= rva < s.vaddr + span:
            off = rva - s.vaddr + s.raw_off
            return off if rva - s.vaddr < s.raw_size else None
    if rva < headers_size:
        return rva
    return None


def _pe(d: bytes) -> ExeInfo | None:
    lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    if d[lfanew:lfanew + 4] != b"PE\x00\x00":
        return None
    machine, nsec, _ts, _sym, _nsym, opt_size, _chars = struct.unpack_from("<HHIIIHH", d, lfanew + 4)
    opt = lfanew + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    is64 = magic == 0x20B
    ep_rva = struct.unpack_from("<I", d, opt + 16)[0]
    file_align = struct.unpack_from("<I", d, opt + 36)[0]
    headers_size = struct.unpack_from("<I", d, opt + 60)[0]
    sec_off = opt + opt_size
    sections = []
    for i in range(min(nsec, 96)):
        o = sec_off + i * 40
        if o + 40 > len(d):
            break
        name = d[o:o + 8].split(b"\x00", 1)[0].decode("latin-1")
        vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", d, o + 8)
        # the loader rounds PointerToRawData down to 0x200 when FileAlignment >= 0x200
        if file_align >= 0x200:
            roff &= ~0x1FF
        sections.append(Section(name, roff, rsize, vaddr, vsize))
    ep = _rva_to_off(ep_rva, sections, headers_size)
    overlay = max((s.raw_off + s.raw_size for s in sections), default=0)
    return ExeInfo("pe", ep, sections, is64, machine, {"ep_rva": ep_rva, "overlay_off": overlay})


def _elf(d: bytes) -> ExeInfo | None:
    ei_class, ei_data = d[4], d[5]
    end = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    if is64:
        e_type, e_machine, _v, e_entry, e_phoff, e_shoff, _f, _eh, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
            struct.unpack_from(end + "HHIQQQIHHHHHH", d, 16)
    else:
        e_type, e_machine, _v, e_entry, e_phoff, e_shoff, _f, _eh, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
            struct.unpack_from(end + "HHIIIIIHHHHHH", d, 16)
    # entry point via PT_LOAD program headers
    ep = None
    for i in range(min(e_phnum, 256)):
        o = e_phoff + i * e_phentsize
        if o + e_phentsize > len(d):
            break
        if is64:
            p_type, _pf, p_offset, p_vaddr, _pa, p_filesz, _pm, _al = struct.unpack_from(end + "IIQQQQQQ", d, o)
        else:
            p_type, p_offset, p_vaddr, _pa, p_filesz, _pm, _pf, _al = struct.unpack_from(end + "IIIIIIII", d, o)
        if p_type == 1 and p_vaddr <= e_entry < p_vaddr + p_filesz:
            ep = e_entry - p_vaddr + p_offset
            break
    sections = []
    if e_shoff and e_shnum and e_shoff < len(d):
        for i in range(min(e_shnum, 512)):
            o = e_shoff + i * e_shentsize
            if o + e_shentsize > len(d):
                break
            if is64:
                _n, sh_type, _fl, sh_addr, sh_offset, sh_size = struct.unpack_from(end + "IIQQQQ", d, o)
            else:
                _n, sh_type, _fl, sh_addr, sh_offset, sh_size = struct.unpack_from(end + "IIIIII", d, o)
            if sh_type == 0:
                continue
            raw = 0 if sh_type == 8 else sh_size  # SHT_NOBITS
            sections.append(Section(str(i), sh_offset, raw, sh_addr, sh_size))
    return ExeInfo("elf", ep, sections, is64, e_machine, {"e_type": e_type})


def _macho(d: bytes) -> ExeInfo | None:
    magic = d[:4]
    end = "<" if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") else ">"
    is64 = magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
    cputype, _sub, filetype, ncmds, sizeofcmds = struct.unpack_from(end + "iiIII", d, 4)
    off = 32 if is64 else 28
    sections: list[Section] = []
    ep = None
    text_vmaddr = None
    thread_pc = None
    for _ in range(min(ncmds, 4096)):
        if off + 8 > len(d):
            break
        cmd, cmdsize = struct.unpack_from(end + "II", d, off)
        if cmdsize < 8:
            break
        if cmd in (0x19, 0x1):  # LC_SEGMENT_64 / LC_SEGMENT
            if cmd == 0x19:
                segname = d[off + 8:off + 24].split(b"\x00", 1)[0].decode("latin-1")
                vmaddr, _vms, fileoff, _fs, _mp, _ip, nsects, _fl = struct.unpack_from(end + "QQQQiiII", d, off + 24)
                so, ssize = off + 72, 80
            else:
                segname = d[off + 8:off + 24].split(b"\x00", 1)[0].decode("latin-1")
                vmaddr, _vms, fileoff, _fs, _mp, _ip, nsects, _fl = struct.unpack_from(end + "IIIIiiII", d, off + 24)
                so, ssize = off + 56, 68
            if segname == "__TEXT":
                text_vmaddr = vmaddr - fileoff
            for j in range(min(nsects, 256)):
                s = so + j * ssize
                if s + ssize > len(d):
                    break
                sname = d[s:s + 16].split(b"\x00", 1)[0].decode("latin-1")
                if cmd == 0x19:
                    addr, size, soff = struct.unpack_from(end + "QQI", d, s + 32)
                else:
                    addr, size, soff = struct.unpack_from(end + "III", d, s + 32)
                sections.append(Section(f"{segname},{sname}", soff, size if soff else 0, addr, size))
        elif cmd == 0x80000028:  # LC_MAIN
            ep = struct.unpack_from(end + "Q", d, off + 8)[0]
        elif cmd in (0x5, 0x4) and thread_pc is None:  # LC_UNIXTHREAD / LC_THREAD
            flavor = struct.unpack_from(end + "I", d, off + 8)[0]
            regs = off + 16
            if cputype == 0x01000007 and flavor == 4:      # x86_64 rip = reg 16
                thread_pc = struct.unpack_from(end + "Q", d, regs + 16 * 8)[0]
            elif cputype == 7 and flavor == 1:             # i386 eip = reg 10
                thread_pc = struct.unpack_from(end + "I", d, regs + 10 * 4)[0]
            elif cputype == 0x0100000C and flavor == 6:    # arm64 pc = x0..x28, fp, lr, sp, pc
                thread_pc = struct.unpack_from(end + "Q", d, regs + 32 * 8)[0]
        off += cmdsize
    if ep is None and thread_pc is not None and text_vmaddr is not None:
        ep = thread_pc - text_vmaddr
    return ExeInfo("macho", ep, sections, is64, cputype, {"filetype": filetype})
