"""No-op stand-in for ``localcode.security.sandbox``.

LocalCode can wrap the engine subprocess in macOS ``sandbox-exec`` (no outbound
network, no reads of the user's files). Cerber does not vendor that machinery
(it is ~300 lines of SBPL generation); the engines only ever call the four names
below, so this module keeps their code unchanged while never sandboxing.
The engine still binds 127.0.0.1 only and requires a random bearer key.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

__all__ = ["SandboxPlan", "wrap", "cleanup", "mode"]


@dataclass
class SandboxPlan:
    read: list[Path] = field(default_factory=list)
    write: list[Path] = field(default_factory=list)
    local_network: bool = True


def wrap(argv: Sequence[str], plan: SandboxPlan, settings: Any = None) -> tuple[list[str], bool, Path | None]:
    """Return ``(argv, sandboxed, profile_path)`` - always unsandboxed here."""
    return list(argv), False, None


def cleanup(profile: Path | None) -> None:
    return None


def mode(settings: Any = None) -> str:
    return "off"
