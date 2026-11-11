"""The "normal behaviour" model of THIS Mac: a small autoencoder (~200 k parameters) over running programs.

Idea: it is trained only on this Mac (`./cerber.sh baseline learn`): every few seconds it records how each running
program looks – where it runs from, who signed it, who started it, its network activity, its command line – as
139 numbers. The autoencoder learns to squeeze those numbers through a 24-number bottleneck and rebuild them. What
it has seen often (Safari, Finder, Homebrew tools, the user's apps …) it rebuilds well; a program that behaves
unlike anything on this Mac (new unsigned binary in a hidden folder, a script talking to odd ports, a shell started
by a document app …) comes back with a large error. No malware samples are needed – nothing leaves the Mac.

It is NOT reinforcement learning: there is no reward signal for "this was a virus", only "this is unusual here".

Owner's AI policy – the model only influences, it never decides:
    * Heur:Env.Baseline.Anomaly is LOW confidence and at most BASELINE_CAP (15) points: on its own it is "info";
    * it is positive-only (nothing is ever lowered because it "looks normal");
    * its details carry no "confidence": "high", so the active defense never acts on it.

The model file (db/baseline/mac_baseline.json, git-ignored, rewritten by every learning run) is plain JSON with
weights, the feature scaling and the threshold – no program names or paths (names enter only as hash buckets).
It is not part of the integrity seal because it changes whenever the user re-learns; editing it can only hide
this weak hint, never raise a verdict above "info" or trigger an action.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import time
import zlib

from ..core import Confidence
from .model import Signal
from .patterns import analyze_command, classify_path, interpreter_of

BASELINE_CAP = 15
MODEL_FORMAT = "cerber-baseline-ae"
MAX_MODEL_BYTES = 32 << 20
MAX_LAYER = 1024

LOC_TAGS = ("apple", "pkgmgr", "app_bundle", "user_docs", "tmp", "varfolders", "translocated", "shared", "hidden",
            "random_appsupport", "random_library", "volume", "trash")
LOC_EXTRA = ("home_library", "home_other", "opt_local", "other")
SIGN = ("apple", "appstore", "devid", "development", "adhoc", "unsigned", "other")
INTERP = ("none", "shell", "python", "node", "other")
TERMINALS = {"Terminal", "iTerm2", "Warp", "ghostty", "Ghostty", "Alacritty", "alacritty", "kitty", "WezTerm",
             "wezterm-gui", "Hyper", "Code", "Cursor", "tmux"}
N_EXE, N_APP, N_PAR = 48, 16, 16
PORT_CLASSES = ("web", "dns", "ssh", "remote_ui", "low_other", "high")

GROUPS: list[tuple[str, int]] = [
    ("lokalizacja programu", len(LOC_TAGS) + len(LOC_EXTRA)),
    ("podpis", len(SIGN)),
    ("interpreter", len(INTERP)),
    ("rodzic", 8),
    ("użytkownik", 3),
    ("nazwa programu", N_EXE),
    ("aplikacja", N_APP),
    ("nazwa rodzica", N_PAR),
    ("sieć", 6 + len(PORT_CLASSES)),
    ("polecenie", 6),
    ("wiek procesu", 1),
]
DIM = sum(n for _, n in GROUPS)          # 139


# ------------------------------------------------------------------ features (shared by learning and scanning)

def _bucket(s: str, n: int) -> int:
    return zlib.crc32(s.encode("utf-8", "replace")) % n


def _norm_name(path: str) -> str:
    b = os.path.basename(path or "")
    return re.sub(r"[\d._-]+$", "", b).lower() or b.lower()


def _app_of(path: str) -> str:
    m = re.search(r"/([^/]+)\.app/", path or "")
    return m.group(1).lower() if m else ""


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    return a.is_global


def _port_class(port: int) -> str:
    if port in (80, 443, 8080, 8443):
        return "web"
    if port in (53, 853, 5353):
        return "dns"
    if port == 22:
        return "ssh"
    if port in (5900, 3389, 5938, 6568, 7070, 21115, 21116, 21117, 21118, 21119):
        return "remote_ui"
    return "low_other" if port < 1024 else "high"


def _loc(path: str, home: str) -> list[float]:
    pi = classify_path(path, home)
    v = [1.0 if pi.has(t) else 0.0 for t in LOC_TAGS]
    extra = dict.fromkeys(LOC_EXTRA, 0.0)
    if not any(v):
        if path.startswith(home + "/Library/"):
            extra["home_library"] = 1.0
        elif path.startswith(home + "/"):
            extra["home_other"] = 1.0
        elif path.startswith(("/opt/", "/usr/local/")):
            extra["opt_local"] = 1.0
        else:
            extra["other"] = 1.0
    return v + list(extra.values())


def _sign(status: str | None) -> list[float]:
    s = status if status in SIGN else "other"
    return [1.0 if s == x else 0.0 for x in SIGN]


def _interp(exe: str) -> list[float]:
    i = interpreter_of(exe or "")
    k = "none" if not i else "shell" if i in ("sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish") else \
        i if i in ("python", "node") else "other"
    return [1.0 if k == x else 0.0 for x in INTERP]


def _onehot(n: int, i: int | None) -> list[float]:
    v = [0.0] * n
    if i is not None:
        v[i] = 1.0
    return v


def features(info: dict, conns: list[dict] | None, sign_status: str | None, parent: dict | None,
             home: str, my_uid: int, now: float | None = None) -> list[float]:
    """139 numbers describing one running program. `info`: psutil-style dict (pid, ppid, name, exe, cmdline, uids or
    username, create_time); `conns`: live.probe-style sockets; `parent`: the parent's info dict (or None)."""
    exe = info.get("exe") or ""
    cmd = [str(a) for a in info.get("cmdline") or []]
    pexe = (parent or {}).get("exe") or ""
    pname = (parent or {}).get("name") or os.path.basename(pexe)
    v: list[float] = []
    v += _loc(exe, home) if exe else [0.0] * (len(LOC_TAGS) + len(LOC_EXTRA) - 1) + [1.0]
    v += _sign(sign_status)
    v += _interp(exe)
    ppi = classify_path(pexe, home) if pexe else None
    v += [1.0 if ppi and ppi.has("apple") else 0.0, 1.0 if ppi and ppi.has("pkgmgr") else 0.0,
          1.0 if ppi and ppi.has("app_bundle") else 0.0,
          1.0 if pexe.startswith(home + "/") else 0.0, 1.0 if not pexe else 0.0,
          1.0 if (info.get("ppid") or 0) == 1 else 0.0,
          1.0 if interpreter_of(pexe) in ("sh", "bash", "zsh", "dash", "fish") else 0.0,
          1.0 if pname in TERMINALS or _app_of(pexe) in {t.lower() for t in TERMINALS} else 0.0]
    uid = info.get("uid")
    v += [1.0 if uid == 0 else 0.0, 1.0 if uid == my_uid else 0.0, 1.0 if uid not in (0, my_uid) else 0.0]
    v += _onehot(N_EXE, _bucket(_norm_name(exe or info.get("name") or ""), N_EXE))
    app = _app_of(exe)
    v += _onehot(N_APP, _bucket(app, N_APP) if app else None)
    v += _onehot(N_PAR, _bucket(_norm_name(pexe or pname or ""), N_PAR) if (pexe or pname) else None)
    est = listen = udp = pub = 0
    peers: set[str] = set()
    ports = dict.fromkeys(PORT_CLASSES, 0)
    loop_only = 1.0
    for c in conns or []:
        st = str(c.get("status") or "")
        r = c.get("raddr")
        if st == "LISTEN":
            listen += 1
        if c.get("type") == 2:
            udp += 1
        if r and r[0] not in ("", "*", "0.0.0.0", "::"):
            ip, port = str(r[0]), int(r[1] or 0)
            if st == "ESTABLISHED":
                est += 1
            peers.add(ip)
            if _public(ip):
                pub += 1
                loop_only = 0.0
            ports[_port_class(port)] += 1
    v += [math.log1p(est), math.log1p(listen), math.log1p(udp), math.log1p(len(peers)), math.log1p(pub),
          loop_only if conns else 0.0]
    v += [math.log1p(ports[k]) for k in PORT_CLASSES]
    joined = " ".join(cmd)
    toks = joined.split()
    v += [math.log1p(len(cmd)), math.log1p(len(joined)) / 4,
          max((_entropy(t) for t in toks if len(t) >= 16), default=0.0) / 6,
          1.0 if re.search(r"https?://", joined) else 0.0,
          1.0 if re.search(r"[A-Za-z0-9+/]{60,}={0,2}", joined) else 0.0,
          1.0 if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", joined) else 0.0]
    ct = info.get("create_time")
    age = max(0.0, (now or time.time()) - float(ct)) if isinstance(ct, (int, float)) else 0.0
    v += [min(math.log1p(age) / 14, 1.0)]
    assert len(v) == DIM, len(v)
    return v


def explain(diff: list[float]) -> list[str]:
    """Feature groups with the largest reconstruction error, most unusual first (Polish labels)."""
    out, i = [], 0
    per = []
    for name, n in GROUPS:
        per.append((sum(d * d for d in diff[i:i + n]), name))
        i += n
    total = sum(e for e, _ in per) or 1.0
    for e, name in sorted(per, reverse=True)[:3]:
        if e / total >= 0.15:
            out.append(name)
    return out


# ------------------------------------------------------------------ the model (pure-Python inference)

class Model:
    """Dense autoencoder: tanh hidden layers, linear output; inputs standardised with the stored mean/std."""

    def __init__(self, spec: dict):
        if not isinstance(spec, dict) or spec.get("format") != MODEL_FORMAT or spec.get("dim") != DIM:
            raise ValueError("nieprawidłowy model normalności")
        self.mean = [float(x) for x in spec["mean"]]
        self.std = [max(float(x), 1e-3) for x in spec["std"]]
        self.weight = [float(x) for x in spec.get("feature_weight") or [1.0] * DIM]
        if not (len(self.mean) == len(self.std) == len(self.weight) == DIM):
            raise ValueError("model normalności: zła długość skalowania")
        self.layers = []
        width = DIM
        for L in spec["layers"]:
            W, b = L["W"], L["b"]
            if not (isinstance(W, list) and 0 < len(W) <= MAX_LAYER and len(b) == len(W)):
                raise ValueError("model normalności: zła warstwa")
            rows = [[float(x) for x in row] for row in W]
            if any(len(r) != width for r in rows):
                raise ValueError("model normalności: niezgodne wymiary")
            self.layers.append((rows, [float(x) for x in b]))
            width = len(rows)
        if width != DIM:
            raise ValueError("model normalności: wyjście ≠ wejście")
        self.threshold = float(spec["threshold"])
        self.scale = float(spec.get("scale") or self.threshold)
        self.meta = spec.get("meta") or {}
        self.params = sum(len(r) * len(r[0]) + len(b) for r, b in self.layers)

    @classmethod
    def load(cls, path: str) -> "Model | None":
        try:
            if os.path.getsize(path) > MAX_MODEL_BYTES:
                return None
            with open(path, encoding="utf-8") as fh:
                return cls(json.loads(fh.read()))
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def reconstruct(self, x: list[float]) -> tuple[float, list[float]]:
        z = [(a - m) / s for a, m, s in zip(x, self.mean, self.std)]
        h = z
        last = len(self.layers) - 1
        for i, (W, b) in enumerate(self.layers):
            out = [sum(map(float.__mul__, row, h)) + bb for row, bb in zip(W, b)]
            h = out if i == last else [math.tanh(o) for o in out]
        diff = [(hh - zz) * w for hh, zz, w in zip(h, z, self.weight)]
        return sum(d * d for d in diff) / DIM, diff


def model_path() -> str:
    from .. import config
    return os.path.join(config.HOME, "db", "baseline", "mac_baseline.json")


# ------------------------------------------------------------------ samples of this Mac (learning + scanning)

_UIDS: dict[str, int] = {}


def _uid_of(user) -> int:
    """psutil `username` (snapshot of the environment scan) -> uid; -1 when unknown."""
    if not isinstance(user, str) or not user:
        return -1
    if user not in _UIDS:
        try:
            import pwd
            _UIDS[user] = pwd.getpwnam(user).pw_uid
        except (KeyError, ImportError):
            _UIDS[user] = -1
    return _UIDS[user]


def sample_processes(sign_of, home: str, procs: dict[int, dict] | None = None,
                     skip=lambda pid: False) -> list[tuple[dict, list[float]]]:
    """(info, features) for every running program that can be inspected. `sign_of(exe)` -> sign status string."""
    from .live import probe
    if procs is None:
        import psutil
        procs = {}
        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "uids", "create_time"]):
            i = dict(p.info)
            u = i.pop("uids", None)
            i["uid"] = u.real if u else None
            if i.get("pid") is not None:
                procs[i["pid"]] = i
    my_uid = os.getuid()
    out = []
    now = time.time()
    for pid, info in procs.items():
        if not info or pid <= 1 or skip(pid) or not info.get("exe"):
            continue
        if "uid" not in info:
            info = {**info, "uid": _uid_of(info.get("username"))}
        res = probe(pid, info.get("create_time"), files=False)
        conns = res[1] if isinstance(res, tuple) else []
        try:
            out.append((info, features(info, conns, sign_of(info["exe"]), procs.get(info.get("ppid") or -1),
                                       home, my_uid, now)))
        except Exception:  # noqa: BLE001 - one odd process must not stop the sample
            continue
    return out


# ------------------------------------------------------------------ environment collector (deep / mega scans)

def collect_baseline(ctx) -> None:
    """Programs that behave unlike anything this Mac was seen doing while the baseline was learned."""
    from .live import is_cerber_process
    from .processes import _own_lineage, snapshot
    model = Model.load(model_path())
    if model is None:
        ctx.inventory["baseline"] = {"model": None}
        return
    ctx.progress("model normalności tego Maca (nietypowe zachowanie programów)")
    procs = snapshot(ctx)
    if not procs:
        return
    home = ctx.homes[0].home if ctx.homes else os.path.expanduser("~")
    skip_pids = _own_lineage()
    cache: dict[int, bool] = {}
    samples = sample_processes(lambda exe: ctx.sign(exe).status if os.path.exists(exe) else "missing", home,
                               procs, lambda pid: pid in skip_pids or is_cerber_process(pid, procs, cache))
    seen: dict[tuple, tuple[float, list[float]]] = {}
    hits = 0
    t0 = time.monotonic()
    for info, x in samples:
        key = tuple(round(a, 3) for a in x)
        if key not in seen:
            seen[key] = model.reconstruct(x)
        err, diff = seen[key]
        if err < model.threshold:
            continue
        over = (err - model.threshold) / max(model.scale - model.threshold, 1e-6)
        score = int(round(min(BASELINE_CAP, 6 + 9 * min(1.0, over))))
        why = explain(diff)
        name = info.get("name") or os.path.basename(info.get("exe") or "?")
        desc = (f"{name} (pid {info['pid']}) zachowuje się inaczej niż wszystko, co model widział na tym Macu"
                + (f" – najbardziej odstaje: {', '.join(why)}" if why else ""))
        sig = Signal("Heur:Env.Baseline.Anomaly", score, Confidence.LOW, desc,
                     [info.get("exe") or name, f"błąd odtworzenia {err:.2f} (próg {model.threshold:.2f})"])
        ctx.add_finding("process", f"Nietypowe zachowanie programu: {name}", f"pid {info['pid']}", [sig],
                        {"pid": info["pid"], "exe": info.get("exe"), "baseline_error": round(err, 3),
                         "baseline_threshold": round(model.threshold, 3), "unusual": why})
        hits += 1
    ctx.inventory["baseline"] = {"model": model.meta, "params": model.params, "processes": len(samples),
                                 "unique": len(seen), "anomalies": hits,
                                 "seconds": round(time.monotonic() - t0, 2)}
