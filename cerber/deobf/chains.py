"""Nested decoder-call chains around a string literal, e.g.

    exec(zlib.decompress(base64.b64decode(b'...')))          # python
    eval(gzinflate(base64_decode('...')))                     # php
    eval(Zlib::Inflate.inflate(Base64.decode64("...")))       # ruby
    eval(pack("H*", "..."))                                   # perl / php

The chain is resolved statically: only pure decoding transforms are applied; the outermost
"sink" (exec/eval/assert/system...) only determines the language hint of the result.
"""
from __future__ import annotations

import binascii
import base64
import bz2
import codecs
import lzma
import re
import urllib.parse

from .primitives import MAX_INFLATE, b64decode_loose, decompress_any, hexdecode, inflate

_OPENER = re.compile(r"([A-Za-z_\\@][\w.:\\>$@-]{0,80})\s*\(\s*(?:(['\"])([^'\"]{0,12})\2\s*,\s*)?$")
_STRIP_OPEN = re.compile(r"(?:\(\s*|\[\s*|['\"]\?>['\"]\s*\.\s*)$")

SINKS = {
    "exec": "python", "eval": None, "compile": "python", "execfile": "python", "assert": "php",
    "create_function": "php", "system": "shell", "passthru": "shell", "shell_exec": "shell",
    "popen": "shell", "proc_open": "shell", "os.system": "shell", "subprocess.call": "shell",
    "instance_eval": "ruby", "class_eval": "ruby", "module_eval": "ruby", "preg_replace": "php",
    "exec_command": "shell", "run": None,
}
_B64 = {"b64decode", "decodebytes", "decodestring", "standard_b64decode", "urlsafe_b64decode", "a2b_base64",
        "base64_decode", "decode_base64", "decode64", "strict_decode64", "urlsafe_decode64", "atob",
        "frombase64string", "decode_base64url"}
_HEX = {"unhexlify", "a2b_hex", "fromhex", "hex2bin", "b16decode"}


def _last(name: str) -> str:
    n = name.lower().lstrip("@\\")
    for sep in ("::", "->", "."):
        if sep in n:
            n = n.rsplit(sep, 1)[-1]
    return n


def _transform(name: str, arg: str | None, data: bytes) -> tuple[str, bytes | None] | None:
    """Return (step_name, output) for a decoding function, None when `name` is not a decoder."""
    full = name.lower().lstrip("@\\")
    n = _last(name)
    if n in _B64:
        return "b64", b64decode_loose(data)
    if n == "b32decode":
        try:
            return "b32", base64.b32decode(data + b"=" * (-len(data) % 8), casefold=True)
        except (binascii.Error, ValueError):
            return "b32", None
    if n in ("b85decode", "a85decode"):
        try:
            return n[:3], (base64.b85decode(data) if n == "b85decode" else base64.a85decode(data))
        except (binascii.Error, ValueError):
            return n[:3], None
    if n in _HEX:
        return "hex", hexdecode(data)
    if n == "pack" and arg and arg.upper().startswith("H"):
        return "hex", hexdecode(data)
    if n in ("unpack", "unpack1") and arg and arg.lower().startswith("m"):
        return "b64", b64decode_loose(data)
    if n in ("unpack", "convert_uudecode") and (arg is None or arg.lower().startswith("u")):
        out = bytearray()
        try:
            for line in data.splitlines():
                if line.strip():
                    out += binascii.a2b_uu(line)
            return "uu", bytes(out)
        except binascii.Error:
            return "uu", None
    if n == "gzinflate":
        return "deflate", inflate(data, -15)
    if n in ("gzuncompress", "inflate", "zlib_decode"):
        return "zlib", inflate(data, 15) or inflate(data, -15)
    if n == "gzdecode":
        return "gzip", inflate(data, 31)
    if n == "bzdecompress":
        try:
            return "bzip2", bz2.BZ2Decompressor().decompress(data, MAX_INFLATE)
        except (OSError, ValueError, EOFError):
            return "bzip2", None
    if n == "decompress":
        if full.startswith("bz2"):
            try:
                return "bzip2", bz2.BZ2Decompressor().decompress(data, MAX_INFLATE)
            except (OSError, ValueError, EOFError):
                return "bzip2", None
        if full.startswith("lzma"):
            try:
                return "lzma", lzma.LZMADecompressor().decompress(data, MAX_INFLATE)
            except (lzma.LZMAError, ValueError, EOFError):
                return "lzma", None
        r = decompress_any(data, raw_deflate=True)
        return (r[0], r[1]) if r else ("decompress", None)
    if n == "str_rot13":
        return "rot13", codecs.encode(data.decode("latin-1"), "rot13").encode("latin-1")
    if n == "strrev":
        return "rev", data[::-1]
    if n in ("urldecode", "rawurldecode", "unquote", "unquote_plus"):
        return "url", urllib.parse.unquote_to_bytes(data.decode("latin-1").replace("+", " ") if "plus" in n or n == "urldecode" else data.decode("latin-1"))
    if n == "loads" and ("marshal" in full):
        return "marshal", None
    if n == "loads" and "pickle" in full:
        return "pickle", None
    if n == "decode" and arg is not None:
        a = arg.lower().replace("-", "_")
        if a in ("rot13", "rot_13"):
            return "rot13", codecs.encode(data.decode("latin-1"), "rot13").encode("latin-1")
        if a in ("hex", "hex_codec"):
            return "hex", hexdecode(data)
        if a in ("base64", "base64_codec"):
            return "b64", b64decode_loose(data)
        if a in ("zlib", "zlib_codec"):
            return "zlib", inflate(data, 15)
        return None
    return None


def chain_before(text: str, pos: int, max_levels: int = 8) -> list[tuple[str, str | None]]:
    """Function names wrapped around the value at `pos`, innermost first."""
    out: list[tuple[str, str | None]] = []
    p = pos
    for _ in range(max_levels):
        seg = text[max(0, p - 140):p]
        m = _OPENER.search(seg)
        if not m:
            # allow `eval("?>".gzinflate(...))` and `exec (` spacing / bare parens
            m2 = _STRIP_OPEN.search(seg)
            if m2 and m2.group(0):
                p -= len(m2.group(0))
                continue
            break
        out.append((m.group(1), m.group(3)))
        p -= len(seg) - m.start()
    return out


_POSTFIX = [
    (re.compile(r"\s*\[\s*::\s*-1\s*\]"), "rev"),
    (re.compile(r"\s*\.\s*unpack1?\s*\(\s*['\"]m0?['\"]\s*\)"), "b64"),
    (re.compile(r"\s*\]\s*\.\s*pack\s*\(\s*['\"]H\*?['\"]\s*\)"), "hex"),
    (re.compile(r"\s*\.\s*decode\s*\(\s*['\"](base64|hex|rot13|rot_13|zlib)['\"]\s*\)"), "decode"),
]
_ARG_AFTER = re.compile(r"\s*,\s*['\"]([\w-]{1,20})['\"]\s*\)")


def resolve(text: str, start: int, end: int, value: bytes, max_steps: int = 10
            ) -> tuple[list[str], bytes, str | None, bool] | None:
    """Apply the decoder chain around text[start:end] (a literal or variable whose value is
    `value`). Returns (steps, data, sink_lang_or_None, has_sink) or None if nothing applies."""
    data = value
    steps: list[str] = []
    # postfix operators directly after the literal ('...'[::-1], "...".unpack('m'))
    tail = text[end:end + 60]
    for rx, how in _POSTFIX:
        m = rx.match(tail)
        if m:
            if how == "rev":
                data = data[::-1]
            elif how == "b64":
                data = b64decode_loose(data) or b""
            elif how == "hex":
                data = hexdecode(data) or b""
            else:
                r = _transform("decode", m.group(1), data)
                data = r[1] if r and r[1] else b""
            if not data:
                return None
            steps.append(how)
            break
    chain = chain_before(text, start)
    sink = None
    has_sink = False
    for name, arg in chain:
        if len(steps) >= max_steps:
            break
        n = _last(name)
        if arg is None and n in ("decode",):
            am = _ARG_AFTER.match(text, end)
            arg = am.group(1) if am else None
        if n in SINKS or name.lower() in SINKS:
            has_sink = True
            sink = SINKS.get(name.lower(), SINKS.get(n))
            break
        r = _transform(name, arg, data)
        if r is None:
            # unknown wrapper (e.g. str(), bytes(), print()) - keep walking outward
            if n in ("str", "bytes", "bytearray", "decode", "encode", "strval", "trim", "to_s", "chomp",
                     "utf8_decode", "stripslashes", "html_entity_decode", "join", "loads"):
                continue
            break
        how, out = r
        if how in ("marshal", "pickle"):
            steps.append(how)
            return steps, data, None, True
        if not out:
            break
        data = out
        steps.append(how)
    if not steps:
        return None
    return steps, data, sink, has_sink
