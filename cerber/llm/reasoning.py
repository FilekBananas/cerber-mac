"""Reasoning ("think"-tag) stripping for chat output.

Small extract of ``localcode.runtime.toolcalls`` (marker table ``_REASONING_PAIRS``
copied verbatim); the rest of that 2800-line module is tool-call parsing, which
Cerber does not use. Reasoning models wrap their scratch work in tags such as
``<think>...</think>``; callers of ``LocalLLM.chat`` only want the answer.

Cases handled (same semantics as ``parse_output`` in the original):

* a complete block anywhere in the text        -> removed, text around it is kept
* an orphan closer (the chat template already opened the block in the prompt,
  e.g. Qwen3 ``<think>\\n`` prefill)            -> everything before the closer is reasoning
* an unclosed opener (generation was cut off)  -> everything from the opener on is reasoning
"""

from __future__ import annotations

__all__ = ["REASONING_PAIRS", "split_reasoning", "strip_reasoning"]

REASONING_PAIRS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("<think>", ("</think>",)),
    ("<thinking>", ("</thinking>",)),
    ("<seed:think>", ("</seed:think>",)),
    ("[THINK]", ("[/THINK]",)),
    ("<|begin_of_thought|>", ("<|end_of_thought|>",)),
    ("<|START_THINKING|>", ("<|END_THINKING|>",)),
    ("<longcat_think>", ("</longcat_think>",)),
    ("◁think▷", ("◁/think▷",)),
    ("<|channel>thought", ("<channel|>",)),
)
# gpt-oss "harmony": reasoning is the analysis channel, the answer is the final channel.
_HARMONY_ANALYSIS = "<|channel|>analysis<|message|>"
_HARMONY_FINAL = "<|channel|>final<|message|>"
_HARMONY_ENDS = ("<|end|>", "<|return|>", "<|start|>assistant")

_CLOSERS = tuple(dict.fromkeys(c for _, cs in REASONING_PAIRS for c in cs))


def split_reasoning(text: str) -> tuple[str, str]:
    """``(answer, reasoning)`` for a raw model output."""
    if not text:
        return "", ""
    reasoning: list[str] = []

    # harmony (gpt-oss)
    if _HARMONY_ANALYSIS in text or _HARMONY_FINAL in text:
        head, _, tail = text.partition(_HARMONY_FINAL)
        if _HARMONY_FINAL in text:
            r = head.replace(_HARMONY_ANALYSIS, "")
            for end in _HARMONY_ENDS:
                r = r.replace(end, "")
            for end in _HARMONY_ENDS:
                tail = tail.split(end, 1)[0]
            return tail.strip(), r.strip()
        return "", head.split(_HARMONY_ANALYSIS, 1)[-1].strip()

    out: list[str] = []
    rest = text
    while rest:
        # earliest opener
        hits = [(rest.find(o), o, cs) for o, cs in REASONING_PAIRS if o in rest]
        # earliest orphan closer that comes before any opener
        closer_hits = [(rest.find(c), c) for c in _CLOSERS if c in rest]
        first_open = min(hits, key=lambda h: h[0]) if hits else None
        first_close = min(closer_hits, key=lambda h: h[0]) if closer_hits else None
        if first_close and (first_open is None or first_close[0] < first_open[0]):
            # orphan closer: prompt opened the block, text before it is reasoning
            i, c = first_close
            reasoning.append(rest[:i])
            rest = rest[i + len(c):]
            out.clear()
            continue
        if first_open is None:
            out.append(rest)
            break
        i, opener, closers = first_open
        out.append(rest[:i])
        body = rest[i + len(opener):]
        ends = [(body.find(c), c) for c in closers if c in body]
        if not ends:                       # unclosed: everything after is reasoning
            reasoning.append(body)
            break
        j, c = min(ends, key=lambda h: h[0])
        reasoning.append(body[:j])
        rest = body[j + len(c):]
    return "".join(out).strip(), "\n".join(r.strip() for r in reasoning if r.strip())


def strip_reasoning(text: str) -> str:
    """The answer part of ``text`` (reasoning blocks removed)."""
    return split_reasoning(text)[0]
