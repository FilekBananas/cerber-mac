"""Shim for the parts of ``localcode.config`` that the vendored engines use.

The original module owns the whole LocalCode settings tree (agent, chat,
server, ...). The runtime only ever reads ``logs_dir()`` and a handful of
``settings.runtime.*`` values, so this file provides exactly those, backed by
environment variables instead of a settings file:

* ``CERBER_LLM_HOME``     - root dir for engine logs (default ``~/Library/Caches/cerber/llm``)
* ``CERBER_LLAMA_SERVER`` - path to ``llama-server`` (file or directory)
* ``CERBER_LLM_PYTHON``   - interpreter for the MLX worker (default: ``sys.executable``)
* ``CERBER_LLM_RAM_LIMIT_GB`` - optional ``mx.set_memory_limit`` guard for the MLX worker
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["RuntimeSettings", "Settings", "home", "load_settings", "logs_dir"]


def home() -> Path:
    override = os.environ.get("CERBER_LLM_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / "Library" / "Caches" / "cerber" / "llm"


def logs_dir() -> Path:
    return home() / "logs"


@dataclass
class RuntimeSettings:
    llama_server_path: str | None = None
    python_path: str | None = None
    ram_limit_gb: float | None = None


@dataclass
class Settings:
    runtime: RuntimeSettings = field(default_factory=RuntimeSettings)


def load_settings() -> Settings:
    ram = os.environ.get("CERBER_LLM_RAM_LIMIT_GB")
    try:
        ram_f = float(ram) if ram else None
    except ValueError:
        ram_f = None
    return Settings(
        runtime=RuntimeSettings(
            llama_server_path=os.environ.get("CERBER_LLAMA_SERVER") or None,
            python_path=os.environ.get("CERBER_LLM_PYTHON") or None,
            ram_limit_gb=ram_f,
        )
    )
