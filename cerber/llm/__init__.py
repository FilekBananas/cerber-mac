"""Cerber local LLM runtime: a small synchronous API over a vendored engine.

The heavy lifting (spawning ``llama-server``, health checks, process-group
supervision, SSE streaming, ``/apply-template``, cancellation, parent-death
guard) is the engine of the LocalCode project, vendored verbatim-ish in this
package (``base``, ``http_engine``, ``llama_engine``, ``mlx_engine``,
``mlx_worker``, ``degenerate``; see the ``# cerber:`` comments for the few
edits). Small shims stand in for the rest of LocalCode (``config``, ``types``,
``sandbox``, ``memory``, ``reasoning``).

Public API::

    from cerber.llm import LocalLLM, find_default_model

    with LocalLLM(find_default_model()) as llm:
        print(llm.chat([{"role": "user", "content": "2+2?"}]))
        verdict = llm.chat_json(messages, schema)   # dict, schema-constrained

Structured output uses llama-server's native constrained decoding
(``json_schema`` -> GBNF grammar): a small model physically cannot emit text
that violates the schema's structure. Value constraints a grammar cannot express
(``minimum``/``maximum``, ...) are checked afterwards; one retry on failure.

Safety: the server binds 127.0.0.1 only and needs a random bearer key; it runs
in its own process group under a parent-death supervisor, so it is cleaned up on
normal exit (atexit), on SIGTERM/SIGHUP (default handler replaced by a cleanup
one) and even on ``kill -9`` of the Python process (the supervisor notices
within ~1 s and terminates the server).
"""

from __future__ import annotations

import asyncio
import atexit
import concurrent.futures
import contextlib
import fnmatch
import json
import logging
import os
import re
import signal
import threading
import time
import weakref
from pathlib import Path
from typing import Any, Coroutine, Iterable, TypeVar

from cerber.llm.base import Engine, EngineError, GenStats, LoadConfig, SamplingParams
from cerber.llm.degenerate import LoopGuard
from cerber.llm.http_engine import EngineStartError, kill_all_engine_processes
from cerber.llm.llama_engine import LlamaServerEngine, find_llama_server
from cerber.llm.reasoning import split_reasoning, strip_reasoning
from cerber.llm.types import LocalModel, model_from_path

__all__ = [
    "LocalLLM",
    "find_default_model",
    "find_llama_server",
    "LLMError",
    "LLMTimeoutError",
    "LLMJSONError",
    "EngineStartError",
    "GenStats",
    "kill_all_engine_processes",
    "strip_reasoning",
    "validate_schema",
]

log = logging.getLogger("cerber.llm")

T = TypeVar("T")

# preferred first: the accusation verifier's model (cerber.ai_install), then the older Granite 4.0 H Tiny
DEFAULT_MODEL_GLOBS = ("foundation-sec-1.1-8b-instruct*.gguf", "granite-4.0-h-tiny*.gguf")
DEFAULT_MODEL_GLOB = DEFAULT_MODEL_GLOBS[-1]
DEFAULT_MODEL_ROOTS = (os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                    "models"),            # Cerber's own copy (cerber.ai_install)
                       "~/.lmstudio/models", "~/.localcode/models")


class LLMError(EngineError):
    """Any failure of the local LLM (engine, timeout, bad output). ``log_tail``
    holds the last engine log lines when the engine failed to start."""

    log_tail: str = ""


class LLMTimeoutError(LLMError):
    """A request did not finish within its timeout (generation was cancelled)."""


class LLMJSONError(LLMError):
    """The model did not produce JSON valid for the schema (after one retry)."""

    def __init__(self, message: str, raw: str = "") -> None:
        super().__init__(message)
        self.raw = raw


# --------------------------------------------------------------------------- #
# Model discovery
# --------------------------------------------------------------------------- #

_QUANT_RANK = ("q4_k_m", "q4_k_s", "q4_0", "q4", "q5", "q6", "q8")


def _is_gguf(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"GGUF" and path.stat().st_size > 1 << 20
    except OSError:
        return False


def _walk_files(root: Path, max_depth: int = 6) -> Iterable[Path]:
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        if len(Path(dirpath).parts) - root_depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for name in filenames:
            yield Path(dirpath) / name


def find_default_model() -> str | None:
    """Path of the default model, or ``None``.

    ``$CERBER_LLM_MODEL`` wins when it points at an existing file/dir; otherwise
    ``DEFAULT_MODEL_GLOBS`` (in order of preference) are searched under Cerber's
    ``models/``, ``~/.lmstudio/models`` and ``~/.localcode/models`` (Q4_K_M
    preferred; partial downloads and projector files are ignored)."""
    env = os.environ.get("CERBER_LLM_MODEL")
    if env and Path(env).expanduser().exists():
        return str(Path(env).expanduser())
    found: list[Path] = []
    for root in DEFAULT_MODEL_ROOTS:
        base = Path(root).expanduser()
        if not base.is_dir():
            continue
        for p in _walk_files(base):
            n = p.name.lower()
            if any(fnmatch.fnmatch(n, g) for g in DEFAULT_MODEL_GLOBS) and "mmproj" not in n and _is_gguf(p):
                found.append(p)
    if not found:
        return None

    def rank(p: Path) -> tuple[int, int, int]:
        n = p.name.lower()
        family = next(i for i, g in enumerate(DEFAULT_MODEL_GLOBS) if fnmatch.fnmatch(n, g))
        for i, q in enumerate(_QUANT_RANK):
            if q in n:
                return (family, i, p.stat().st_size)
        return (family, len(_QUANT_RANK), p.stat().st_size)

    return str(min(found, key=rank))


# --------------------------------------------------------------------------- #
# JSON helpers (lenient parsing + a small JSON-Schema validator)
# --------------------------------------------------------------------------- #

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL | re.IGNORECASE)


def _parse_json(text: str) -> Any:
    """``json.loads`` that also copes with code fences and prose around the value."""
    s = (text or "").strip()
    if not s:
        raise ValueError("empty output")
    m = _FENCE_RE.match(s)
    if m:
        s = m.group(1).strip()
    try:
        return json.loads(s)
    except ValueError:
        pass
    dec = json.JSONDecoder()
    for i, ch in enumerate(s):
        if ch in "{[":
            try:
                obj, _ = dec.raw_decode(s[i:])
                return obj
            except ValueError:
                continue
    raise ValueError("no JSON value found in output")


_TYPE_CHECKS = {
    "string": lambda v: isinstance(v, str),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool)
    or (isinstance(v, float) and v.is_integer()),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
    "null": lambda v: v is None,
}


def validate_schema(value: Any, schema: dict[str, Any], path: str = "$") -> None:
    """Raise ``ValueError`` if ``value`` violates ``schema``.

    Covers the JSON-Schema subset used for structured verdicts: ``type``,
    ``enum``, ``const``, ``required``, ``properties``, ``additionalProperties: false``,
    ``items``, ``minItems``/``maxItems``, ``minLength``/``maxLength``,
    ``minimum``/``maximum``, ``anyOf``/``oneOf``. Unknown keywords are ignored."""
    if not isinstance(schema, dict):
        return
    if "anyOf" in schema or "oneOf" in schema:
        alts = schema.get("anyOf") or schema.get("oneOf") or []
        errors = []
        for alt in alts:
            try:
                validate_schema(value, alt, path)
                break
            except ValueError as exc:
                errors.append(str(exc))
        else:
            raise ValueError(f"{path}: matches none of the alternatives ({'; '.join(errors)[:200]})")
    t = schema.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(_TYPE_CHECKS.get(x, lambda v: True)(value) for x in types):
            raise ValueError(f"{path}: expected {'|'.join(types)}, got {type(value).__name__}")
    if "const" in schema and value != schema["const"]:
        raise ValueError(f"{path}: expected {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path}: {value!r} not in {schema['enum']!r}")
    if isinstance(value, bool):
        return
    if isinstance(value, (int, float)):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValueError(f"{path}: {value} < minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise ValueError(f"{path}: {value} > maximum {schema['maximum']}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise ValueError(f"{path}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ValueError(f"{path}: longer than {schema['maxLength']}")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise ValueError(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise ValueError(f"{path}: more than {schema['maxItems']} items")
        items = schema.get("items")
        if isinstance(items, dict):
            for i, v in enumerate(value):
                validate_schema(v, items, f"{path}[{i}]")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                raise ValueError(f"{path}: missing required property {key!r}")
        props = schema.get("properties", {})
        for key, sub in props.items():
            if key in value:
                validate_schema(value[key], sub, f"{path}.{key}")
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(props)
            if extra:
                raise ValueError(f"{path}: unexpected properties {sorted(extra)}")


def _with_schema_hint(messages: list[dict[str, Any]], schema: dict[str, Any]) -> list[dict[str, Any]]:
    """Copy of ``messages`` whose system prompt also describes the schema.

    The grammar constrains *what can be emitted*, but a small model answers
    better when it also *knows* the shape (field names are otherwise only
    implied by the constraint)."""
    hint = (
        "Respond with a single JSON object and nothing else. It must conform to this JSON Schema:\n"
        + json.dumps(schema, ensure_ascii=False)
    )
    msgs = [dict(m) for m in messages]
    if msgs and msgs[0].get("role") == "system":
        msgs[0]["content"] = f"{msgs[0].get('content') or ''}\n\n{hint}".strip()
    else:
        msgs.insert(0, {"role": "system", "content": hint})
    return msgs


# --------------------------------------------------------------------------- #
# Process cleanup hooks
# --------------------------------------------------------------------------- #

_HOOKS_INSTALLED = False
_HOOKS_LOCK = threading.Lock()


def _install_cleanup_hooks() -> None:
    """atexit is registered by ``http_engine`` on the first spawn. Here: make
    SIGTERM/SIGHUP (whose default action kills Python without running atexit)
    kill the engine groups first. Only replaces the *default* disposition - an
    application's own handler is left alone (it then owns the shutdown path and
    atexit + the parent-death supervisor still cover us). Main thread only."""
    global _HOOKS_INSTALLED
    with _HOOKS_LOCK:
        if _HOOKS_INSTALLED or threading.current_thread() is not threading.main_thread():
            return
        _HOOKS_INSTALLED = True
        for name in ("SIGTERM", "SIGHUP"):
            sig = getattr(signal, name, None)
            if sig is None:
                continue
            try:
                if signal.getsignal(sig) is not signal.SIG_DFL:
                    continue

                def handler(signum: int, frame: Any, _sig: int = sig) -> None:
                    kill_all_engine_processes(0.2)
                    signal.signal(_sig, signal.SIG_DFL)
                    os.kill(os.getpid(), _sig)

                signal.signal(sig, handler)
            except (ValueError, OSError):  # pragma: no cover - not settable here
                continue


class _LoopThread:
    """A private asyncio loop in a daemon thread; sync code calls into it."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self.thread = threading.Thread(target=self._run, name="cerber-llm-loop", daemon=True)
        self.thread.start()
        self._ready.wait(5)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.call_soon(self._ready.set)
        self.loop.run_forever()

    def call(self, coro: Coroutine[Any, Any, T], timeout: float | None) -> T:
        fut = asyncio.run_coroutine_threadsafe(coro, self.loop)
        try:
            return fut.result(timeout)
        except BaseException:          # incl. KeyboardInterrupt / timeout: stop the work
            fut.cancel()
            raise

    def stop_nowait(self) -> None:
        if not self.loop.is_closed():
            with contextlib.suppress(RuntimeError):
                self.loop.call_soon_threadsafe(self.loop.stop)

    def close(self) -> None:
        self.stop_nowait()
        self.thread.join(5)
        if not self.thread.is_alive() and not self.loop.is_closed():
            self.loop.close()


def _emergency_stop(engine: Engine, loop_thread: _LoopThread) -> None:
    """Finalizer for a LocalLLM dropped without ``stop()``."""
    kill = getattr(engine, "kill_now", None)
    if callable(kill):
        with contextlib.suppress(Exception):
            kill()
    loop_thread.stop_nowait()


# --------------------------------------------------------------------------- #
# LocalLLM
# --------------------------------------------------------------------------- #


class LocalLLM:
    """One local model behind a synchronous chat API.

    ``model_path``: a ``.gguf`` file (llama-server) or an MLX model directory.
    ``ctx_size``: context tokens (per slot; capped by the model's training
    context). ``threads``: CPU threads for llama-server (``-t``; default: its
    own). ``port``: fixed local port (default: a free one).

    Thread-safe: concurrent ``chat`` calls are queued by the server
    (``n_parallel`` slots)."""

    def __init__(
        self,
        model_path: str,
        ctx_size: int = 16384,
        threads: int | None = None,
        port: int | None = None,
        *,
        n_parallel: int = 1,
        gpu_layers: int = -1,
        kv_cache_type: str = "f16",
        flash_attn: str = "auto",
        llama_server: str | None = None,
        extra_args: list[str] | None = None,
    ) -> None:
        self.model_path = str(Path(model_path).expanduser())
        self.ctx_size = int(ctx_size)
        self.threads = threads
        self.port = port
        self.n_parallel = max(1, int(n_parallel))
        self.gpu_layers = gpu_layers
        self.kv_cache_type = kv_cache_type
        self.flash_attn = flash_attn
        self.llama_server = llama_server
        self.extra_args = list(extra_args or [])

        self._lock = threading.RLock()
        self._loop_thread: _LoopThread | None = None
        self._engine: Engine | None = None
        self._finalizer: weakref.finalize | None = None

        #: statistics of the last generation (``GenStats``: prompt/gen tokens, tokens/s)
        self.last_stats: GenStats | None = None
        #: ``stop`` | ``length`` | ``loop`` (repetition guard tripped) | None
        self.last_finish_reason: str | None = None
        #: reasoning text stripped from the last answer (think tags), if any
        self.last_reasoning: str = ""
        #: seconds ``start()`` took (process spawn + model load + probes)
        self.load_seconds: float | None = None

    # ------------------------------------------------------------- lifecycle
    @property
    def running(self) -> bool:
        eng = self._engine
        return eng is not None and eng.running

    @property
    def pid(self) -> int | None:
        return self._engine.pid if self._engine is not None else None

    @property
    def base_url(self) -> str | None:
        eng = self._engine
        return getattr(eng, "base_url", None) if eng is not None else None

    @property
    def n_ctx(self) -> int:
        """Context per slot the server really provides (may be < ``ctx_size``)."""
        return self._engine.n_ctx if self._engine is not None else self.ctx_size

    @property
    def log_path(self) -> str | None:
        eng = self._engine
        p = getattr(eng, "log_path", None) if eng is not None else None
        return str(p) if p else None

    def _build_engine(self, model: LocalModel) -> Engine:
        extra = list(self.extra_args)
        if self.threads:
            extra = ["-t", str(int(self.threads)), *extra]
        cfg = LoadConfig(
            n_ctx=self.ctx_size,
            n_parallel=self.n_parallel,
            gpu_layers=self.gpu_layers,
            flash_attn=self.flash_attn,
            kv_cache_type=self.kv_cache_type,
            extra_args=extra if model.format == "gguf" else list(self.extra_args),
        )
        instance = f"cerber-{model.display_name}"
        if model.format == "mlx":
            from cerber.llm.mlx_engine import MlxEngine  # heavy deps only when used

            return MlxEngine(instance, model, cfg)
        return LlamaServerEngine(instance, model, cfg, binary=self.llama_server)

    def start(self, timeout: float = 120) -> None:
        """Spawn the engine and wait until it is healthy (idempotent)."""
        with self._lock:
            if self.running:
                return
            path = Path(self.model_path)
            if not path.exists():
                part = list(path.parent.glob(f"*{path.stem}*.part")) if path.parent.is_dir() else []
                hint = " (an unfinished download .part file is next to it)" if part else ""
                raise FileNotFoundError(f"model not found: {self.model_path}{hint}")
            self._teardown()                       # leftovers of a failed/dead previous start
            _install_cleanup_hooks()
            model = model_from_path(path)
            engine = self._build_engine(model)
            engine.startup_timeout_base_s = float(timeout)     # type: ignore[attr-defined]
            engine.startup_timeout_per_gb_s = 0.0              # type: ignore[attr-defined]
            if self.port:
                engine.fixed_port = int(self.port)             # type: ignore[attr-defined]
            loop_thread = _LoopThread()
            self._loop_thread, self._engine = loop_thread, engine
            t0 = time.monotonic()
            try:
                loop_thread.call(engine.start(), timeout * getattr(engine, "max_start_attempts", 3) + 30)
            except BaseException as exc:
                self._teardown()
                if isinstance(exc, EngineError) and not isinstance(exc, LLMError):
                    err = LLMError(str(exc))
                    err.log_tail = getattr(exc, "log_tail", "")
                    raise err from exc
                raise
            self.load_seconds = time.monotonic() - t0
            self._finalizer = weakref.finalize(self, _emergency_stop, engine, loop_thread)
            log.info("cerber.llm: %s ready on %s in %.1fs", model.display_name, self.base_url, self.load_seconds)

    def _teardown(self) -> None:
        """Stop engine + loop thread (idempotent, never raises)."""
        engine, loop_thread = self._engine, self._loop_thread
        self._engine = self._loop_thread = None
        if self._finalizer is not None:
            self._finalizer.detach()
            self._finalizer = None
        if engine is None or loop_thread is None:
            if loop_thread is not None:
                loop_thread.close()
            return
        try:
            grace = float(getattr(engine, "stop_grace_s", 5.0))
            loop_thread.call(engine.stop(), grace + 20)
        except BaseException:  # noqa: BLE001 - fall back to the hard kill, then re-raise interrupts
            log.debug("graceful engine stop failed", exc_info=True)
            kill = getattr(engine, "kill_now", None)
            if callable(kill):
                with contextlib.suppress(Exception):
                    kill()
        finally:
            loop_thread.close()

    def stop(self) -> None:
        """Terminate the engine process (SIGTERM, then SIGKILL). Idempotent."""
        with self._lock:
            self._teardown()

    def __enter__(self) -> "LocalLLM":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # ------------------------------------------------------------------ info
    def memory_bytes(self) -> int | None:
        """Resident memory (RSS) of the engine process tree."""
        eng, lt = self._engine, self._loop_thread
        if eng is None or lt is None:
            return None
        try:
            return lt.call(eng.memory_bytes(), 15)
        except Exception:  # noqa: BLE001
            return None

    # ------------------------------------------------------------------ chat
    def _template_kwargs(self, thinking: bool) -> dict[str, Any] | None:
        """Chat-template switch for reasoning, when the model's template has one
        (Qwen3 ``enable_thinking``, gpt-oss ``reasoning_effort`` ...). Off by default:
        short answers, no scratch-work tokens."""
        info = self._engine.template_info if self._engine is not None else None
        kw = (info.effort_kwarg or info.thinking_kwarg) if info is not None else None
        if not kw:
            return None
        if info is not None and "low" in info.effort_levels:
            return {kw: "medium" if thinking else "low"}
        return {kw: bool(thinking)}

    async def _chat_async(
        self,
        messages: list[dict[str, Any]],
        max_tokens: int,
        temperature: float,
        json_schema: dict[str, Any] | None,
        timeout: float,
        thinking: bool,
    ) -> tuple[str, str | None, GenStats | None]:
        eng = self._engine
        if eng is None:
            raise LLMError("LocalLLM is not started (call start() or use it as a context manager)")
        parts: list[str] = []
        finish: str | None = None
        stats: GenStats | None = None
        try:
            async with asyncio.timeout(timeout):
                prompt = await eng.apply_template(messages, template_kwargs=self._template_kwargs(thinking))
                params = SamplingParams(
                    max_tokens=max_tokens,
                    temperature=temperature,
                    top_p=1.0 if temperature <= 0 else 0.95,
                    top_k=1 if temperature <= 0 else 40,
                    min_p=0.0 if temperature <= 0 else 0.05,
                    repeat_penalty=1.0,       # penalties distort JSON (repeated keys/quotes)
                    json_schema=json_schema,
                )
                guard = LoopGuard()
                async with contextlib.aclosing(eng.complete(prompt, params)) as gen:
                    async for chunk in gen:
                        if chunk.text:
                            parts.append(chunk.text)
                            if guard.feed(chunk.text):
                                finish = "loop"
                                break
                        if chunk.done:
                            finish, stats = chunk.finish_reason, chunk.stats
        except TimeoutError as exc:
            raise LLMTimeoutError(f"no answer within {timeout:.0f}s (generation cancelled)") from exc
        except LLMError:
            raise
        except EngineError as exc:
            raise LLMError(str(exc)) from exc
        return "".join(parts), finish, stats

    def chat(
        self,
        messages: list[dict],
        *,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        json_schema: dict | None = None,
        timeout: float = 300,
        thinking: bool = False,
    ) -> str:
        """Assistant text for OpenAI-style ``messages`` (reasoning tags removed).

        ``json_schema``: constrain decoding to this JSON Schema (output is then
        JSON text). ``thinking``: enable the model's reasoning mode when its
        template has a switch. Raises ``LLMError`` / ``LLMTimeoutError``."""
        lt = self._loop_thread
        if lt is None or self._engine is None:
            raise LLMError("LocalLLM is not started (call start() or use it as a context manager)")
        raw, finish, stats = lt.call(
            self._chat_async(messages, max_tokens, temperature, json_schema, timeout, thinking),
            timeout + 15,
        )
        answer, reasoning = split_reasoning(raw)
        self.last_finish_reason, self.last_stats, self.last_reasoning = finish, stats, reasoning
        return answer

    def chat_json(self, messages: list[dict], schema: dict, *, describe_schema: bool = True, **kw: Any) -> dict:
        """Structured answer: parsed and validated against ``schema``.

        Decoding is grammar-constrained, so the JSON is syntactically valid;
        value constraints (``minimum`` ...) and truncation by ``max_tokens`` are
        caught by validation and retried once (larger budget / different
        sample). ``describe_schema`` also puts the schema into the system prompt.
        Raises ``LLMJSONError`` (with ``.raw``) if the retry fails as well."""
        kw.pop("json_schema", None)
        msgs = _with_schema_hint(messages, schema) if describe_schema else [dict(m) for m in messages]
        raw, err = "", ""
        for attempt in range(2):
            raw = self.chat(msgs, json_schema=schema, **kw)
            try:
                obj = _parse_json(raw)
                validate_schema(obj, schema)
                return obj
            except ValueError as exc:
                err = str(exc)
                log.warning("cerber.llm: chat_json attempt %d invalid (%s); finish=%s",
                            attempt + 1, err, self.last_finish_reason)
                if attempt == 0:
                    if self.last_finish_reason in ("length", "loop"):
                        kw["max_tokens"] = min(int(kw.get("max_tokens", 1024)) * 2, max(256, self.n_ctx // 2))
                    kw["temperature"] = max(float(kw.get("temperature", 0.0)), 0.3)
                    if raw.strip():
                        msgs = msgs + [
                            {"role": "assistant", "content": raw[:1500]},
                            {"role": "user", "content": f"That reply was invalid ({err}). "
                                                        "Reply again with ONLY a valid JSON object for the schema."},
                        ]
        raise LLMJSONError(f"model output is not valid for the schema: {err}", raw)
