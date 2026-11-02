"""macOS Seatbelt wrapper for the local AI engine processes (``llama-server``, the MLX worker).

Why: the engine is a native program parsing a model file (GGUF: tensors, tokenizer, a Jinja chat template) that
lives in a folder every program of the user can write – Cerber's ``models/``, ``~/.lmstudio/models`` … – and it
reads prompts built from scanned, untrusted files. Started by Cerber.app it would inherit Full Disk Access, so a
crafted model or a parser bug would hand the whole disk to whoever planted the file.

The profile (``sandbox-exec -p``) keeps the engine working (Metal/GPU, its own libraries, the system) but:

* no reading anything in the user's home, /Users/Shared or external volumes – except the folders the engine's
  plan names (the model's folder, its interpreter for the parent-guard shim),
* no writing there either (the log is an inherited file descriptor; caches go to the per-user temp folders),
* no network except 127.0.0.1 (it only serves the local HTTP API, protected by a random bearer key),
* no starting other programs (only the engine binary and the guard interpreter),
* no AppleEvents, permission prompts (tccd), clipboard, keychain or authorization dialogs.

``mode()`` is ``strict``: when the sandboxed start fails the engine does NOT fall back to running unsandboxed
(that fallback would let a model that crashes on purpose inside the sandbox get a second, unconfined try).
``CERBER_LLM_SANDBOX=off`` disables it for debugging from a terminal (Cerber.app never passes that variable).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

__all__ = ["SandboxPlan", "wrap", "cleanup", "mode", "build_profile"]

SANDBOX_EXEC = "/usr/bin/sandbox-exec"
DENY_MACH_PREFIXES = ("com.apple.tccd", "com.apple.pasteboard", "com.apple.coreservices.appleevents",
                      "com.apple.authd", "com.apple.security.authhost", "com.apple.SecurityAgent",
                      "com.apple.securityd.xpc", "com.apple.security.keychain", "com.apple.screencapture",
                      "com.apple.accessibility", "com.apple.AddressBook", "com.apple.contactsd",
                      "com.apple.CalendarAgent", "com.apple.photos", "com.apple.locationd", "com.apple.lsd.open")
PRIVATE_ROOTS = ("/Volumes", "/Users/Shared", "/Library/Keychains")


class SandboxError(RuntimeError):
    pass


@dataclass
class SandboxPlan:
    read: list[Path] = field(default_factory=list)
    write: list[Path] = field(default_factory=list)
    local_network: bool = True


def mode(settings: Any = None) -> str:
    if os.environ.get("CERBER_LLM_SANDBOX", "").strip().lower() in ("off", "0", "no"):
        return "off"
    return "strict"


def _q(path: str) -> str:
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _real(p) -> str:
    return os.path.realpath(os.path.expanduser(str(p)))


def build_profile(argv: Sequence[str], plan: SandboxPlan) -> str:
    home = _real("~")
    reads, writes, execs = [], [], set()
    for p in plan.read:
        r = _real(p)
        if os.path.exists(r):
            reads.append(r)
            if r != os.path.abspath(os.path.expanduser(str(p))):
                reads.append(os.path.abspath(os.path.expanduser(str(p))))
    for p in plan.write:
        if os.path.exists(_real(p)):
            writes.append(_real(p))
    # programs it may start: the engine binary and the guard interpreter (absolute argv items that are executables)
    for a in argv:
        if isinstance(a, str) and a.startswith("/") and os.path.isfile(a) and os.access(a, os.X_OK):
            execs.update({a, _real(a)})
    py_app = os.path.join(_real(sys.base_prefix), "Resources/Python.app/Contents/MacOS/Python")
    if os.path.exists(py_app) and any("python" in os.path.basename(e).lower() or e.endswith("/Python") for e in execs):
        execs.add(py_app)               # a framework build re-executes its Python.app stub
    if not execs:
        raise SandboxError("brak programu do uruchomienia w sandboksie")
    deny_roots = [home, *[r for r in PRIVATE_ROOTS if os.path.exists(r)]]
    lines = [
        "(version 1)",
        "(allow default)",
        "(deny file-read-data " + " ".join(f"(subpath {_q(r)})" for r in deny_roots) + ")",
    ]
    if reads:
        lines.append("(allow file-read-data " + " ".join(f"(subpath {_q(r)})" for r in sorted(set(reads))) + ")")
    lines.append("(deny file-write* " + " ".join(f"(subpath {_q(r)})" for r in deny_roots) +
                 ' (subpath "/Applications") (subpath "/Library") (subpath "/opt") (subpath "/usr/local"))')
    if writes:
        lines.append("(allow file-write* " + " ".join(f"(subpath {_q(r)})" for r in sorted(set(writes))) + ")")
    lines += [
        "(deny process-exec*)",
        "(allow process-exec " + " ".join(f"(literal {_q(e)})" for e in sorted(execs)) + ")",
        "(deny network-outbound (remote ip))",
        "(deny network-bind)",
        "(deny network-inbound)",
    ]
    if plan.local_network:
        lines += ['(allow network-outbound (remote ip "localhost:*"))',
                  '(allow network-bind (local ip "localhost:*"))',
                  '(allow network-inbound (local ip "localhost:*"))']
    lines += [
        "(deny appleevent-send)",
        "(deny mach-lookup " + " ".join(f'(global-name-prefix "{m}")' for m in DENY_MACH_PREFIXES) + ")",
    ]
    return "\n".join(lines) + "\n"


def wrap(argv: Sequence[str], plan: SandboxPlan, settings: Any = None) -> tuple[list[str], bool, Path | None]:
    """Return ``(argv, sandboxed, profile_path)``; the profile travels inline (``-p``), so there is no file."""
    if mode(settings) == "off":
        return list(argv), False, None
    if not os.access(SANDBOX_EXEC, os.X_OK):
        raise SandboxError("brak /usr/bin/sandbox-exec – silnik AI nie zostanie uruchomiony bez izolacji")
    return [SANDBOX_EXEC, "-p", build_profile(argv, plan), *argv], True, None


def cleanup(profile: Path | None) -> None:
    if profile is not None:
        try:
            profile.unlink()
        except OSError:
            pass
