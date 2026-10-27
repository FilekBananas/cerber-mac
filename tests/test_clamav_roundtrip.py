"""Signature round-trip test for the ClamAV engine.

For a deterministic random sample of compiled signatures, synthesize a byte
buffer that satisfies the signature (literals, wildcards, nibbles, jumps,
alternatives, EP/section/EOF offsets inside a minimal PE, normalized text for
text targets) and check that the engine reports it. The buffers are inert
byte patterns, not malware. Any miss points at a matcher bug.

    python tests/test_clamav_roundtrip.py [--n 3000] [--seed 7] [-v]
"""
from __future__ import annotations

import argparse
import os
import random
import re
import struct
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cerber import config  # noqa: E402
from cerber.engines.clamav import ClamAVEngine  # noqa: E402
from cerber.engines.clamav_sig import INF, SigError, parse_offset, tokenize, widen  # noqa: E402
from cerber.pipeline import Pipeline  # noqa: E402

TEXT_FILL = 0x61  # 'a' – survives text normalization


class Skip(Exception):
    pass


def synth(toks, rnd: random.Random, text: bool) -> bytes:
    out = bytearray()
    for t in toks:
        k = t[0]
        if k == "lit":
            out += t[1]
        elif k == "any":
            out += bytes(TEXT_FILL if text else rnd.randrange(256) for _ in range(t[1]))
        elif k == "nib_hi":
            out.append((t[1] << 4) | (1 if text else rnd.randrange(16)))
        elif k == "nib_lo":
            out.append(((6 if text else rnd.randrange(16)) << 4) | t[1])
        elif k == "gap":
            n = t[1] if t[2] >= INF else t[1] + (rnd.randrange(t[2] - t[1] + 1) if t[2] - t[1] < 64 else 0)
            out += bytes(TEXT_FILL if text else rnd.randrange(256) for _ in range(n))
        elif k == "alt":
            alts, neg = t[1], t[2]
            if not neg:
                out += synth(alts[0], rnd, text)
            else:
                banned = set()
                ln = None
                for a in alts:
                    if len(a) != 1 or a[0][0] != "lit":
                        raise Skip("complex negation")
                    banned.add(a[0][1])
                    ln = len(a[0][1])
                for _ in range(200):
                    cand = bytes(rnd.randrange(256) for _ in range(ln or 1))
                    if text:
                        cand = bytes([TEXT_FILL + rnd.randrange(20)]) * (ln or 1)
                    if cand not in banned:
                        out += cand
                        break
                else:
                    raise Skip("cannot satisfy negation")
        elif k == "bound":
            if out and (chr(out[-1]).isalnum()):
                out += b" "
        else:
            raise Skip(k)
    return bytes(out)


def build_pe(body_at: dict[int, bytes], size: int = 0x2000) -> bytes:
    """Minimal PE32 with one section at raw 0x200 / rva 0x1000; EP = section start."""
    sec_raw = 0x200
    data = bytearray(sec_raw + size)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x44, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    opt = 0x58
    struct.pack_into("<H", data, opt, 0x10B)
    struct.pack_into("<I", data, opt + 16, 0x1000)       # AddressOfEntryPoint
    struct.pack_into("<I", data, opt + 32, 0x1000)       # SectionAlignment
    struct.pack_into("<I", data, opt + 36, 0x200)        # FileAlignment
    struct.pack_into("<I", data, opt + 56, 0x1000 + size)  # SizeOfImage
    struct.pack_into("<I", data, opt + 60, 0x200)        # SizeOfHeaders
    sec = opt + 0xE0
    data[sec:sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", data, sec + 8, size, 0x1000, size, sec_raw)
    for off, b in body_at.items():
        end = off + len(b)
        if end > len(data):
            data += bytes(end - len(data))
        data[off:end] = b
    return bytes(data)


def container(target: int, payload: bytes, offset: str) -> bytes:
    off = parse_offset(offset)
    if target in (3, 7):
        if off.kind != "any":
            raise Skip("text offset")
        pre = b"<html><body> " if target == 3 else b"note: "
        return pre + payload + b" end"
    if target == 1:
        if off.kind == "any":
            return build_pe({0x200 + 16: payload})
        if off.kind in ("ep", "sec", "last") and (off.kind != "sec" or off.sec == 0):
            if off.base < 0:
                raise Skip("negative EP offset")
            return build_pe({0x200 + off.base: payload}, size=max(0x2000, off.base + len(payload) + 64))
        if off.kind == "se" and off.sec == 0:
            return build_pe({0x200 + 8: payload}, size=max(0x2000, len(payload) + 64))
        if off.kind == "abs" and off.base >= 0x400:
            return build_pe({off.base: payload}, size=off.base + len(payload))
        raise Skip(f"pe offset {off.kind}")
    prefix = {0: b"", 4: b"Received: x\nMessage-ID: <y>\n\n", 5: b"\x89PNG\r\n\x1a\n" + bytes(24),
              10: b"%PDF-1.4\n", 11: b"FWS\x0a" + bytes(4), 12: b"\xca\xfe\xba\xbe\x00\x00\x00\x34"}.get(target)
    if prefix is None:
        raise Skip(f"target {target}")
    pad = b"\n" * 32 if target == 4 else b"\x00" * 32
    if off.kind == "any":
        return prefix + pad + payload + pad
    if off.kind == "abs" and off.base >= len(prefix):
        return prefix + b"\x00" * (off.base - len(prefix)) + payload + b"\x00" * 16
    if off.kind == "eof":
        body = prefix + b"\x00" * 64
        if len(payload) > off.base:
            raise Skip("eof shorter than pattern")
        return body + payload + b"\x00" * (off.base - len(payload))
    raise Skip(f"offset {off.kind}")


_AND_ONLY = re.compile(r"^\(?\d+(?:&\d+)*\)?$")


def make_sample(eng: ClamAVEngine, sid: int, rnd: random.Random) -> bytes:
    name, target, _pua, kind, expr, subs, cons = eng.sigs[sid]
    if cons:
        raise Skip("constraints")
    text = target in (3, 7)
    parts = []
    offsets = set()
    if kind == 0:
        pid = subs[0][1][0]
        hexsig, offset, nocase, wide, fullword = eng.pat_spec[pid]
        toks = tokenize(hexsig)
        parts.append(synth(widen(toks) if wide else toks, rnd, text))
        offsets.add(offset)
    else:
        if not _AND_ONLY.match(expr):
            raise Skip("expression")
        for i in (int(x) for x in re.findall(r"\d+", expr)):
            if i >= len(subs) or subs[i][0] != "hex":
                raise Skip("non-hex subsig")
            pid = subs[i][1][0]
            hexsig, offset, nocase, wide, fullword = eng.pat_spec[pid]
            if offset not in ("*", ""):
                raise Skip("subsig offset")
            toks = tokenize(hexsig)
            if wide:
                toks = widen(toks)
            if fullword:
                toks = [("bound", "B")] + toks + [("bound", "B")]
            sep = b" " if (text or fullword) else b"\x00\x00"
            parts.append(sep + synth(toks, rnd, text) + sep)
        offsets.add("*")
    return container(target, b"".join(parts), offsets.pop())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("-v", action="store_true")
    a = ap.parse_args()
    eng = ClamAVEngine(config.CLAMAV_COMPILED)
    pipe = Pipeline(engines=[eng], analyzers=[])
    rnd = random.Random(a.seed)
    sids = rnd.sample(range(len(eng.sigs)), min(a.n * 3, len(eng.sigs)))
    tested = hit = 0
    skips = Counter()
    misses = []
    per_kind = Counter()
    per_kind_hit = Counter()
    t0 = time.time()
    for sid in sids:
        if tested >= a.n:
            break
        name, target, _p, kind, *_ = eng.sigs[sid]
        try:
            data = make_sample(eng, sid, rnd)
        except (Skip, SigError, ValueError, IndexError) as exc:
            skips[str(exc).split(":")[0][:30]] += 1
            continue
        tested += 1
        key = f"{'ndb' if kind == 0 else 'ldb'}/t{target}"
        per_kind[key] += 1
        root = pipe.scan_bytes(data, f"synthetic/{name}")
        names = {d.name for o in root.iter_tree() for d in o.detections}
        if f"ClamAV:{name}" in names:
            hit += 1
            per_kind_hit[key] += 1
        else:
            misses.append((sid, name, root.ftype, root.errors[:2]))
    dt = time.time() - t0
    print(f"tested {tested} signatures in {dt:.1f}s: detected {hit} ({hit * 100 / max(1, tested):.2f}%)")
    for k in sorted(per_kind):
        print(f"  {k:10} {per_kind_hit[k]}/{per_kind[k]}")
    print("skipped:", dict(skips.most_common(10)))
    for sid, name, ft, errs in misses[: (40 if a.v else 10)]:
        n, t, _p, kind, expr, subs, cons = eng.sigs[sid]
        specs = []
        for s in subs[:4]:
            if s[0] == "hex":
                specs.append(eng.pat_spec[s[1][0]][:2] + tuple(x for x in eng.pat_spec[s[1][0]][2:]))
        print(f"MISS {name} target={t} ftype={ft} expr={expr} {errs}\n     {str(specs)[:300]}")
    return 0 if hit == tested else 1


if __name__ == "__main__":
    sys.exit(main())
