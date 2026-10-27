"""Microsoft Script Encoder (screnc) decoder: VBScript.Encode (.vbe) / JScript.Encode (.jse).

Encoded blocks look like  #@~^XXXXXX== <data> XXXXXX==^#~@
"""
from __future__ import annotations

import re

from .primitives import Budget, Layer, excerpt

# encoded char -> 3 candidate plain chars; the column is chosen by a fixed 64-entry sequence
_RAW = {
    9: "\x57\x6E\x7B", 10: "\x4A\x4C\x41", 11: "\x0B\x0B\x0B", 12: "\x0C\x0C\x0C", 13: "\x4A\x4C\x41",
    14: "\x0E\x0E\x0E", 15: "\x0F\x0F\x0F", 16: "\x10\x10\x10", 17: "\x11\x11\x11", 18: "\x12\x12\x12",
    19: "\x13\x13\x13", 20: "\x14\x14\x14", 21: "\x15\x15\x15", 22: "\x16\x16\x16", 23: "\x17\x17\x17",
    24: "\x18\x18\x18", 25: "\x19\x19\x19", 26: "\x1A\x1A\x1A", 27: "\x1B\x1B\x1B", 28: "\x1C\x1C\x1C",
    29: "\x1D\x1D\x1D", 30: "\x1E\x1E\x1E", 31: "\x1F\x1F\x1F", 32: "\x2E\x2D\x32", 33: "\x47\x75\x30",
    34: "\x7A\x52\x21", 35: "\x56\x60\x29", 36: "\x42\x71\x5B", 37: "\x6A\x5E\x38", 38: "\x2F\x49\x33",
    39: "\x26\x5C\x3D", 40: "\x49\x62\x58", 41: "\x41\x7D\x3A", 42: "\x34\x29\x35", 43: "\x32\x36\x65",
    44: "\x5B\x20\x39", 45: "\x76\x7C\x5C", 46: "\x72\x7A\x56", 47: "\x43\x7F\x73", 48: "\x38\x6B\x66",
    49: "\x39\x63\x4E", 50: "\x70\x33\x45", 51: "\x45\x2B\x6B", 52: "\x68\x68\x62", 53: "\x71\x51\x59",
    54: "\x4F\x66\x78", 55: "\x09\x76\x5E", 56: "\x62\x31\x7D", 57: "\x44\x64\x4A", 58: "\x23\x54\x6D",
    59: "\x75\x43\x71", 60: "\x4A\x4C\x41", 61: "\x7E\x3A\x60", 62: "\x4A\x4C\x41", 63: "\x5E\x7E\x53",
    64: "\x40\x4C\x40", 65: "\x77\x45\x42", 66: "\x4A\x2C\x27", 67: "\x61\x2A\x48", 68: "\x5D\x74\x72",
    69: "\x22\x27\x75", 70: "\x4B\x37\x31", 71: "\x6F\x44\x37", 72: "\x4E\x79\x4D", 73: "\x3B\x59\x52",
    74: "\x4C\x2F\x22", 75: "\x50\x6F\x54", 76: "\x67\x26\x6A", 77: "\x2A\x72\x47", 78: "\x7D\x6A\x64",
    79: "\x74\x39\x2D", 80: "\x54\x7B\x20", 81: "\x2B\x3F\x7F", 82: "\x2D\x38\x2E", 83: "\x2C\x77\x4C",
    84: "\x30\x67\x5D", 85: "\x6E\x53\x7E", 86: "\x6B\x47\x6C", 87: "\x66\x34\x6F", 88: "\x35\x78\x79",
    89: "\x25\x5D\x74", 90: "\x21\x30\x43", 91: "\x64\x23\x26", 92: "\x4D\x5A\x76", 93: "\x52\x5B\x25",
    94: "\x63\x6C\x24", 95: "\x3F\x48\x2B", 96: "\x7B\x55\x28", 97: "\x78\x70\x23", 98: "\x29\x69\x41",
    99: "\x28\x2E\x34", 100: "\x73\x4C\x09", 101: "\x59\x21\x2A", 102: "\x33\x24\x44", 103: "\x7F\x4E\x3F",
    104: "\x6D\x50\x77", 105: "\x55\x09\x3B", 106: "\x53\x56\x55", 107: "\x7C\x73\x69", 108: "\x3A\x35\x61",
    109: "\x5F\x61\x63", 110: "\x65\x4B\x50", 111: "\x46\x58\x67", 112: "\x58\x3B\x51", 113: "\x31\x57\x49",
    114: "\x69\x22\x4F", 115: "\x6C\x6D\x46", 116: "\x5A\x4D\x68", 117: "\x48\x25\x7C", 118: "\x27\x28\x36",
    119: "\x5C\x46\x70", 120: "\x3D\x4A\x6E", 121: "\x24\x32\x7A", 122: "\x79\x41\x2F", 123: "\x37\x3D\x5F",
    124: "\x60\x5F\x4B", 125: "\x51\x4F\x5A", 126: "\x20\x42\x2C", 127: "\x36\x65\x57",
}
_PICK = [1, 2, 0, 1, 2, 0, 2, 0, 0, 2, 0, 2, 1, 0, 2, 0, 1, 0, 2, 0, 1, 1, 2, 0, 0, 2, 1, 0, 2, 0, 0, 2,
         1, 1, 0, 2, 0, 2, 0, 1, 0, 1, 1, 2, 0, 1, 0, 2, 1, 0, 2, 0, 1, 1, 2, 0, 0, 1, 1, 2, 0, 1, 0, 2]
_TABLES = [{k: v[c] for k, v in _RAW.items()} for c in range(3)]

_BLOCK = re.compile(r"#@~\^[A-Za-z0-9+/]{6}==")
_END = re.compile(r"[A-Za-z0-9+/]{6}==\^#~@")


def decode_block(data: str) -> str:
    data = (data.replace("@&", "\n").replace("@#", "\r").replace("@*", ">")
            .replace("@!", "<").replace("@$", "@"))
    out = []
    idx = -1
    for ch in data:
        b = ord(ch)
        if b < 128:
            idx += 1
        if (b == 9 or 31 < b < 128) and b not in (60, 62, 64):
            ch = _TABLES[_PICK[idx % 64]][b]
        out.append(ch)
    return "".join(out)


def decode_encoded_blocks(text: str, budget: Budget, lang: str, limit: int = 16) -> list[Layer]:
    out: list[Layer] = []
    if "#@~^" not in text:
        return out
    pos = 0
    while len(out) < limit and not budget.expired():
        m = _BLOCK.search(text, pos)
        if not m:
            break
        e = _END.search(text, m.end())
        if not e:
            break
        body = text[m.end():e.start()]
        if len(body) > 16 << 20:
            break
        plain = decode_block(body)
        out.append(Layer("script-encoder", plain.encode("utf-8", "replace"), lang, "text", lang,
                         excerpt(text[m.start():m.start() + 60])))
        pos = e.end()
    return out
