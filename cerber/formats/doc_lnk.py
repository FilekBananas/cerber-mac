"""Windows Shell Link (.lnk) parser, MS-SHLLINK."""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")

F_HAS_IDLIST = 1 << 0
F_HAS_LINKINFO = 1 << 1
F_HAS_NAME = 1 << 2
F_HAS_RELPATH = 1 << 3
F_HAS_WORKDIR = 1 << 4
F_HAS_ARGS = 1 << 5
F_HAS_ICON = 1 << 6
F_UNICODE = 1 << 7
F_HAS_EXP_STRING = 1 << 9
F_RUN_AS_USER = 1 << 13
F_HAS_EXP_ICON = 1 << 14

FLAG_NAMES = {
    0: "HasLinkTargetIDList", 1: "HasLinkInfo", 2: "HasName", 3: "HasRelativePath", 4: "HasWorkingDir",
    5: "HasArguments", 6: "HasIconLocation", 7: "IsUnicode", 8: "ForceNoLinkInfo", 9: "HasExpString",
    10: "RunInSeparateProcess", 12: "HasDarwinID", 13: "RunAsUser", 14: "HasExpIcon", 15: "NoPidlAlias",
    17: "RunWithShimLayer", 18: "ForceNoLinkTrack", 19: "EnableTargetMetadata",
}
SHOW = {1: "normal", 3: "maximized", 7: "minimized"}


@dataclass
class ShellLink:
    flags: int = 0
    attributes: int = 0
    file_size: int = 0
    icon_index: int = 0
    show_command: int = 1
    hotkey: int = 0
    idlist_path: str = ""
    idlist_strings: list[str] = field(default_factory=list)
    local_base_path: str = ""
    common_path_suffix: str = ""
    net_name: str = ""
    device_name: str = ""
    name: str = ""
    relative_path: str = ""
    working_dir: str = ""
    arguments: str = ""
    icon_location: str = ""
    env_target: str = ""
    icon_env: str = ""
    machine_id: str = ""
    darwin_id: str = ""
    known_folder: str = ""
    extra_blocks: list[str] = field(default_factory=list)
    end_offset: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def flag_names(self) -> list[str]:
        return [n for b, n in FLAG_NAMES.items() if self.flags & (1 << b)]

    @property
    def target(self) -> str:
        """Best guess of what the shortcut launches."""
        if self.env_target:
            return self.env_target
        if self.local_base_path:
            return self.local_base_path + self.common_path_suffix
        if self.net_name:
            return self.net_name.rstrip("\\") + "\\" + self.common_path_suffix
        if self.idlist_path:
            return self.idlist_path
        return self.relative_path

    @property
    def command_line(self) -> str:
        t = self.target
        q = f'"{t}"' if " " in t else t
        return (q + " " + self.arguments).strip() if self.arguments else q


def _zstr(data: bytes, off: int, unicode: bool = False, limit: int = 32768) -> str:
    if off <= 0 or off >= len(data):
        return ""
    if unicode:
        end = off
        while end + 1 < len(data) and end - off < limit:
            if data[end] == 0 and data[end + 1] == 0:
                break
            end += 2
        return data[off:end].decode("utf-16-le", "replace")
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = min(len(data), off + limit)
    return data[off:end].decode("cp1252", "replace")


def _idlist(data: bytes, lnk: ShellLink) -> None:
    parts: list[str] = []
    pos = 0
    items = 0
    while pos + 2 <= len(data) and items < 256:
        size = struct.unpack_from("<H", data, pos)[0]
        if size == 0:
            break
        if size < 3 or pos + size > len(data):
            lnk.errors.append("truncated IDList item")
            break
        item = data[pos + 2:pos + size]
        pos += size
        items += 1
        typ = item[0] if item else 0
        if typ == 0x1F and len(item) >= 18:
            continue  # root folder (CLSID)
        if typ & 0x70 == 0x20 and len(item) > 2:      # volume "C:\"
            vol = item[1:].split(b"\x00", 1)[0].decode("latin-1", "replace")
            if re.match(r"^[A-Za-z]:\\?$", vol):
                parts.append(vol.rstrip("\\"))
                continue
        if typ & 0x70 == 0x30 and len(item) > 12:     # file entry
            short = item[12:].split(b"\x00", 1)[0].decode("cp1252", "replace")
            longs = [m.decode("utf-16-le", "replace") for m in re.findall(rb"(?:[\x20-\x7e]\x00){2,}", item[12:])]
            name = max(longs, key=len) if longs else short
            if short and longs and not any(short.lower() == l.lower() for l in longs) and "~" not in short:
                name = short if len(short) >= len(name) else name
            parts.append(name)
            lnk.idlist_strings.append(name)
            continue
        # anything else (URI items, delegate items, control panel...): keep readable strings
        for m in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", item):
            lnk.idlist_strings.append(m.decode("utf-16-le", "replace"))
        for m in re.findall(rb"[\x20-\x7e]{6,}", item):
            lnk.idlist_strings.append(m.decode("latin-1"))
    if parts:
        lnk.idlist_path = "\\".join(p for p in parts if p)
        if re.match(r"^[A-Za-z]:[^\\]", lnk.idlist_path):
            lnk.idlist_path = lnk.idlist_path[:2] + "\\" + lnk.idlist_path[2:]


def _linkinfo(data: bytes, lnk: ShellLink) -> None:
    if len(data) < 0x1C:
        lnk.errors.append("truncated LinkInfo")
        return
    size, hsize, lflags, vol_off, lbp_off, cnrl_off, cps_off = struct.unpack_from("<7I", data, 0)
    lbp_u = cps_u = 0
    if hsize >= 0x24 and len(data) >= 0x24:
        lbp_u, cps_u = struct.unpack_from("<2I", data, 0x1C)
    if lflags & 1:
        lnk.local_base_path = _zstr(data, lbp_u, True) if lbp_u else _zstr(data, lbp_off)
    if lflags & 2 and cnrl_off and cnrl_off + 20 <= len(data):
        c = data[cnrl_off:]
        _csize, cflags, net_off, dev_off, _ptype = struct.unpack_from("<5I", c, 0)
        net_u = dev_u = 0
        if net_off > 0x14 and len(c) >= 0x1C:
            net_u, dev_u = struct.unpack_from("<2I", c, 0x14)
        lnk.net_name = _zstr(c, net_u, True) if net_u else _zstr(c, net_off)
        if cflags & 1:
            lnk.device_name = _zstr(c, dev_u, True) if dev_u else _zstr(c, dev_off)
    lnk.common_path_suffix = _zstr(data, cps_u, True) if cps_u else _zstr(data, cps_off)


def parse(data: bytes) -> ShellLink:
    lnk = ShellLink()
    if len(data) < 0x4C or struct.unpack_from("<I", data, 0)[0] != 0x4C or data[4:20] != LNK_CLSID:
        raise ValueError("not a shell link")
    (lnk.flags, lnk.attributes) = struct.unpack_from("<II", data, 20)
    lnk.file_size, lnk.icon_index, lnk.show_command, lnk.hotkey = struct.unpack_from("<IiIH", data, 52)
    pos = 0x4C
    if lnk.flags & F_HAS_IDLIST:
        if pos + 2 > len(data):
            lnk.errors.append("truncated IDList size")
            lnk.end_offset = len(data)
            return lnk
        n = struct.unpack_from("<H", data, pos)[0]
        try:
            _idlist(data[pos + 2:pos + 2 + n], lnk)
        except Exception as exc:  # noqa: BLE001
            lnk.errors.append(f"IDList: {exc}")
        pos += 2 + n
    if lnk.flags & F_HAS_LINKINFO and pos + 4 <= len(data):
        n = struct.unpack_from("<I", data, pos)[0]
        try:
            _linkinfo(data[pos:pos + n], lnk)
        except Exception as exc:  # noqa: BLE001
            lnk.errors.append(f"LinkInfo: {exc}")
        pos += max(n, 4)
    uni = bool(lnk.flags & F_UNICODE)
    for flag, attr in ((F_HAS_NAME, "name"), (F_HAS_RELPATH, "relative_path"), (F_HAS_WORKDIR, "working_dir"),
                       (F_HAS_ARGS, "arguments"), (F_HAS_ICON, "icon_location")):
        if not lnk.flags & flag:
            continue
        if pos + 2 > len(data):
            lnk.errors.append(f"truncated StringData ({attr})")
            break
        count = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        nbytes = count * 2 if uni else count
        raw = data[pos:pos + nbytes]
        if len(raw) < nbytes:
            lnk.errors.append(f"truncated StringData ({attr})")
        setattr(lnk, attr, raw.decode("utf-16-le" if uni else "cp1252", "replace"))
        pos += nbytes
    # ExtraData blocks
    blocks = 0
    while pos + 4 <= len(data) and blocks < 64:
        bsize = struct.unpack_from("<I", data, pos)[0]
        if bsize < 4:
            pos += 4
            break
        if bsize < 8 or pos + bsize > len(data):
            lnk.errors.append("truncated ExtraData block")
            pos = len(data)
            break
        sig = struct.unpack_from("<I", data, pos + 4)[0]
        blk = data[pos:pos + bsize]
        lnk.extra_blocks.append(f"{sig:#010x}")
        if sig in (0xA0000001, 0xA0000007, 0xA0000006) and bsize >= 0x314:
            ansi = blk[8:268].split(b"\x00", 1)[0].decode("cp1252", "replace")
            wide = blk[268:788].decode("utf-16-le", "replace").split("\x00", 1)[0]
            val = wide or ansi
            if sig == 0xA0000001:
                lnk.env_target = val
            elif sig == 0xA0000007:
                lnk.icon_env = val
            else:
                lnk.darwin_id = val
        elif sig == 0xA0000003 and bsize >= 0x60:
            lnk.machine_id = blk[16:32].split(b"\x00", 1)[0].decode("latin-1", "replace")
        elif sig == 0xA000000B and bsize >= 0x1C:
            lnk.known_folder = blk[8:24].hex()
        pos += bsize
        blocks += 1
    lnk.end_offset = min(pos, len(data))
    return lnk
