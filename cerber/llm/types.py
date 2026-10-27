"""Shim for ``localcode.hub.types`` - only what the engines read.

``LocalModel`` is a description of a model that exists on disk. LocalCode fills
it from its model library (GGUF metadata, HF cache, ...); Cerber just needs a
path, so ``model_from_path`` builds one from a ``.gguf`` file (llama-server) or
an MLX model directory. Every ``ModelMeta`` field is optional - unknown values
fall back to conservative defaults inside the engines.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

__all__ = ["ModelFormat", "ModelMeta", "LocalModel", "model_from_path"]

ModelFormat = Literal["gguf", "mlx"]


@dataclass
class ModelMeta:
    arch: str | None = None
    params_b: float | None = None
    active_params_b: float | None = None
    context_length: int | None = None     # native max context, when known
    n_layers: int | None = None
    n_heads: int | None = None
    n_kv_heads: int | None = None
    head_dim: int | None = None
    hidden_size: int | None = None
    sliding_window: int | None = None
    n_full_attn_layers: int | None = None
    vocab_size: int | None = None
    chat_template: str | None = None
    bos_token: str | None = None
    eos_token: str | None = None
    quant: str | None = None
    is_embedding: bool = False


@dataclass
class LocalModel:
    key: str
    format: ModelFormat
    path: str                               # gguf: the .gguf file; mlx: model directory
    display_name: str
    size_bytes: int = 0
    repo_id: str | None = None
    quant: str | None = None
    source: str = "cerber"
    mmproj_path: str | None = None
    capabilities: list[str] = field(default_factory=list)
    meta: ModelMeta = field(default_factory=ModelMeta)
    modified_at: float = 0.0
    scan: dict[str, Any] | None = None

    @property
    def is_embedding(self) -> bool:
        return "embedding" in self.capabilities or self.meta.is_embedding


def model_from_path(path: str | os.PathLike[str]) -> LocalModel:
    """Build a ``LocalModel`` for a ``.gguf`` file or an MLX model directory."""
    p = Path(path).expanduser()
    if p.is_dir():
        fmt: ModelFormat = "mlx"
        name = p.name
        size = sum(f.stat().st_size for f in p.iterdir()
                   if f.is_file() and f.suffix.lower() in (".safetensors", ".npz"))
    else:
        fmt = "gguf"
        name = p.stem
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
    try:
        mtime = p.stat().st_mtime
    except OSError:
        mtime = 0.0
    return LocalModel(key=f"local/{name}", format=fmt, path=str(p), display_name=name,
                      size_bytes=size, modified_at=mtime)
