"""Static, bounded de-obfuscation library for script analyzers.

    from cerber.deobf import deobfuscate, Budget
    res = deobfuscate(text, "powershell")
    res.normalized   # comment-free code with folded literals / decoded char codes
    res.layers       # decoded payloads (Layer objects) to hand back via ctx.add_child
    res.ops          # Counter of transformations performed (obfuscation evidence)

Nothing here executes, imports, unpickles or unmarshals attacker content. Every entry
point is bounded by a Budget (time, bytes, layers, depth). Recursion across layers is
left to the scan pipeline: each decoded layer becomes a child object that is analysed
(and de-obfuscated) again, up to the pipeline's max depth; the core dedupes by sha256.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from . import applescript, batch, javascript, misc, powershell, python, shell, vbscript
from .generic import numeric_arrays, ps_encoded_commands
from .primitives import Budget, Layer, bytes_to_text, classify
from .textops import strip_comments

__all__ = ["Budget", "Layer", "Result", "deobfuscate", "strip_comments", "bytes_to_text", "classify"]

MAX_TEXT = 8 << 20


@dataclass
class Result:
    code: str                                   # comment-stripped source
    normalized: str                             # code after literal folding / decoding
    layers: list[Layer] = field(default_factory=list)
    ops: Counter = field(default_factory=Counter)
    errors: list[str] = field(default_factory=list)


def deobfuscate(text: str, lang: str, budget: Budget | None = None, strip: bool = True) -> Result:
    budget = budget or Budget()
    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT]
    code = strip_comments(text, lang) if strip else text
    ops: Counter = Counter()
    res = Result(code=code, normalized=code, ops=ops)
    try:
        if lang == "powershell":
            res.normalized = powershell.normalize(code, ops, budget)
            res.layers = powershell.extract(code, res.normalized, budget)
        elif lang in ("javascript", "jscript"):
            folded, res.normalized = javascript.normalize_views(code, ops, budget)
            res.layers = javascript.extract(code, res.normalized, budget, folded)
        elif lang == "vbs":
            res.normalized = vbscript.normalize(code, ops, budget)
            res.layers = vbscript.extract(code, res.normalized, budget)
        elif lang == "batch":
            res.normalized = batch.normalize(code, ops, budget)
            res.layers = batch.extract(code, res.normalized, budget)
        elif lang == "shell":
            res.normalized = shell.normalize(code, ops, budget)
            res.layers = shell.extract(code, res.normalized, budget)
        elif lang == "python":
            res.normalized = python.normalize(code, ops, budget)
            res.layers = python.extract(code, res.normalized, budget)
        elif lang in ("php", "perl", "ruby"):
            res.normalized = misc.normalize(code, lang, ops, budget)
            res.layers = misc.extract(code, res.normalized, lang, budget)
        elif lang == "applescript":
            res.normalized = applescript.normalize(code, ops, budget)
            res.layers = applescript.extract(code, res.normalized, budget)
        else:
            res.layers = ps_encoded_commands(code, budget) + numeric_arrays(code, budget, None)
    except RecursionError:
        res.errors.append(f"deobf[{lang}]: recursion limit")
    except MemoryError:
        res.errors.append(f"deobf[{lang}]: out of memory")
    except Exception as exc:  # noqa: BLE001 - a decoder bug must never kill the analyzer
        res.errors.append(f"deobf[{lang}]: {exc!r}")
    if budget.expired():
        res.ops["budget_exhausted"] += 1
    # de-duplicate layers by payload
    seen: set[bytes] = set()
    uniq = []
    for lay in res.layers:
        key = lay.data[:4096] + len(lay.data).to_bytes(8, "little")
        if key in seen or not lay.data:
            continue
        seen.add(key)
        uniq.append(lay)
    res.layers = uniq
    return res
