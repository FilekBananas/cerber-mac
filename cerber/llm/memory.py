"""Tiny excerpt of ``localcode.runtime.memory`` (only what ``mlx_engine`` needs).

The full module estimates model RAM for LocalCode's multi-model budget manager;
Cerber runs one model, so only the KV-cache vocabulary mapper is kept.
"""

from __future__ import annotations

_KV_ELEMENT_BYTES = {
    "f32": 4.0, "f16": 2.0, "bf16": 2.0, "q8_0": 34 / 32, "q5_1": 24 / 32,
    "q5_0": 22 / 32, "q4_1": 20 / 32, "q4_0": 18 / 32, "iq4_nl": 18 / 32,
}


def normalize_kv_type(kv_cache_type: str | None, fmt: str) -> str:
    """Map the global setting onto the engine's vocabulary (verbatim copy).

    GGUF understands ``f16|bf16|q8_0|q4_0|...``, MLX ``f16|8bit|4bit``; the
    setting may hold either spelling, so ``q8_0 <-> 8bit`` and ``q4_0 <-> 4bit``
    are translated for the target format.
    """
    kv = (kv_cache_type or "f16").strip().lower()
    if fmt == "mlx":
        mapping = {"q8_0": "8bit", "q4_0": "4bit", "q4_1": "4bit", "iq4_nl": "4bit",
                   "q5_0": "8bit", "q5_1": "8bit", "q6_k": "8bit",
                   "bf16": "f16", "fp16": "f16", "float16": "f16", "bfloat16": "f16"}
        kv = mapping.get(kv, kv)
        return kv if kv in ("f16", "8bit", "4bit") else "f16"
    mapping = {"8bit": "q8_0", "4bit": "q4_0", "6bit": "q8_0", "5bit": "q8_0",
               "fp16": "f16", "float16": "f16", "bfloat16": "bf16"}
    kv = mapping.get(kv, kv)
    return kv if kv in _KV_ELEMENT_BYTES else "f16"
