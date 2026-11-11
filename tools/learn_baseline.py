"""Learn the "normal behaviour" autoencoder of this Mac (cerber/envscan/baseline.py) – local data only.

    # 1. watch this Mac for a while (every 10 s: features of every running program; names only as hash buckets)
    .venv/bin/python tools/learn_baseline.py collect --minutes 10
    # 2. train the ~200 k-parameter autoencoder and export db/baseline/mac_baseline.json (needs numpy: Homebrew python3)
    /opt/homebrew/bin/python3 -I tools/learn_baseline.py train
or both at once: ./cerber.sh baseline learn --minutes 10

Collection appends to db/baseline/samples.jsonl, so several sessions (different days, apps open) add up – the more
of normal life the model sees, the fewer false hints. Training holds out the newest 20 % of the snapshots: the
threshold is the 99.9th percentile of the reconstruction error on those held-out snapshots, i.e. roughly one
program in a thousand that was normal but unseen gets the (weak, ≤ 15 point) hint.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, ROOT)

DIR = os.path.join(ROOT, "db", "baseline")
SAMPLES = os.path.join(DIR, "samples.jsonl")
MODEL = os.path.join(DIR, "mac_baseline.json")
SEED = 20261103
HIDDEN = (320, 160, 24, 160, 320)          # 139-320-160-24-160-320-139 ≈ 197 k parameters


def cmd_collect(a) -> None:
    from cerber.envscan.baseline import sample_processes
    from cerber.envscan.live import is_cerber_process
    from cerber.envscan.util import EnvContext
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    ctx = EnvContext({"deep": True})
    home = ctx.homes[0].home if ctx.homes else os.path.expanduser("~")
    me = os.getpid()
    end = time.time() + a.minutes * 60
    snap = int(time.time())
    n_obs = 0
    print(f"Uczę się normalnego zachowania tego Maca przez {a.minutes} min (co {a.every} s) …", flush=True)
    while True:
        cache: dict[int, bool] = {}
        try:
            import psutil
            procs = {}
            for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "uids", "create_time"]):
                i = dict(p.info)
                u = i.pop("uids", None)
                i["uid"] = u.real if u else None
                if i.get("pid") is not None:
                    procs[i["pid"]] = i
        except Exception as exc:  # noqa: BLE001
            print(f"  błąd odczytu procesów: {exc!r}", flush=True)
            procs = {}
        samples = sample_processes(lambda exe: ctx.sign(exe).status if os.path.exists(exe) else "missing", home,
                                   procs, lambda pid: pid == me or is_cerber_process(pid, procs, cache))
        counts: dict[tuple, int] = {}
        for _info, x in samples:
            k = tuple(round(v, 4) for v in x)
            counts[k] = counts.get(k, 0) + 1
        with open(SAMPLES, "a") as fh:
            for k, n in counts.items():
                fh.write(json.dumps({"s": snap, "x": list(k), "n": n}) + "\n")
        n_obs += len(samples)
        print(f"  {time.strftime('%H:%M:%S')}  {len(samples)} programów ({len(counts)} różnych), razem {n_obs}",
              flush=True)
        snap += 1
        if time.time() + a.every > end:
            break
        time.sleep(a.every)
    print(f"Zapisano próbki → {SAMPLES}")


def cmd_train(a) -> None:
    import numpy as np
    from cerber.envscan.baseline import DIM, MODEL_FORMAT, Model
    rng = np.random.default_rng(SEED)
    rows = [json.loads(line) for line in open(SAMPLES)]
    X = np.array([r["x"] for r in rows], dtype=np.float64)
    W = np.minimum(np.array([r["n"] for r in rows], dtype=np.float64), 20.0)   # a 40-tab browser must not dominate
    S = np.array([r["s"] for r in rows])
    snaps = np.unique(S)
    if len(snaps) < 5:
        sys.exit("za mało próbek: zbierz co najmniej 5 migawek (collect --minutes 1)")
    cut = snaps[int(len(snaps) * 0.8)]
    tr, va = S < cut, S >= cut
    mean = (X[tr] * W[tr, None]).sum(0) / W[tr].sum()
    std = np.sqrt(((X[tr] - mean) ** 2 * W[tr, None]).sum(0) / W[tr].sum())
    std = np.maximum(std, 0.05)                 # a feature that never varied: deviations still count, not explode
    Z = (X - mean) / std
    dims = [DIM, *HIDDEN, DIM]
    params = [(rng.normal(0, np.sqrt(1 / i), (o, i)), np.zeros(o)) for i, o in zip(dims[:-1], dims[1:])]
    n_par = sum(w.size + b.size for w, b in params)
    print(f"próbki: {len(X)} różnych wektorów z {len(snaps)} migawek (trening {tr.sum()}, walidacja {va.sum()}); "
          f"sieć {'-'.join(map(str, dims))}: {n_par:,} parametrów", flush=True)
    m = [(np.zeros_like(w), np.zeros_like(b)) for w, b in params]
    v = [(np.zeros_like(w), np.zeros_like(b)) for w, b in params]
    lr, b1, b2, eps, step = 1e-3, 0.9, 0.999, 1e-8, 0
    Ztr, Wtr = Z[tr], W[tr] / W[tr].mean()
    noise = 0.05

    def forward(x):
        hs = [x]
        for i, (w, b) in enumerate(params):
            z = hs[-1] @ w.T + b
            hs.append(z if i == len(params) - 1 else np.tanh(z))
        return hs

    for ep in range(a.epochs):
        idx = rng.permutation(len(Ztr))
        tot = 0.0
        for s0 in range(0, len(idx), 256):
            bi = idx[s0:s0 + 256]
            x, wt = Ztr[bi], Wtr[bi]
            hs = forward(x + rng.normal(0, noise, x.shape))           # denoising: no identity shortcut
            err = hs[-1] - x
            tot += float((err ** 2).mean(1) @ wt)
            g = 2 * err * wt[:, None] / (len(bi) * DIM)
            step += 1
            for i in range(len(params) - 1, -1, -1):
                w, b = params[i]
                gw, gb = g.T @ hs[i], g.sum(0)
                if i:
                    g = (g @ w) * (1 - hs[i] ** 2)
                (mw, mb), (vw, vb) = m[i], v[i]
                mw[:] = b1 * mw + (1 - b1) * gw
                mb[:] = b1 * mb + (1 - b1) * gb
                vw[:] = b2 * vw + (1 - b2) * gw * gw
                vb[:] = b2 * vb + (1 - b2) * gb * gb
                c1, c2 = 1 - b1 ** step, 1 - b2 ** step
                w -= lr * (mw / c1) / (np.sqrt(vw / c2) + eps) + lr * 1e-4 * w
                b -= lr * (mb / c1) / (np.sqrt(vb / c2) + eps)
        if ep % 10 == 0 or ep == a.epochs - 1:
            e_va = (forward(Z[va])[-1] - Z[va]) ** 2
            print(f"  epoka {ep:3}: trening {tot / len(Ztr):.4f}, walidacja {float(e_va.mean()):.4f}", flush=True)
    err_tr = ((forward(Z[tr])[-1] - Z[tr]) ** 2).mean(1)
    err_va = ((forward(Z[va])[-1] - Z[va]) ** 2).mean(1)
    # per observation, not per unique vector: repeat each vector by how often it was seen
    rep = np.repeat(err_va, W[va].astype(int).clip(1))
    thr = float(np.quantile(rep, 0.999))
    scale = float(max(np.quantile(rep, 0.99999), thr * 3))
    frac = float((rep >= thr).mean())
    print(f"próg (99,9 percentyl walidacji): {thr:.3f}; ponad progiem w walidacji: {frac * 100:.2f}% obserwacji; "
          f"błąd trening/walidacja: {float(err_tr.mean()):.3f}/{float(err_va.mean()):.3f}")
    spec = {"format": MODEL_FORMAT, "dim": DIM, "mean": mean.tolist(), "std": std.tolist(),
            "layers": [{"W": w.tolist(), "b": b.tolist()} for w, b in params], "threshold": thr, "scale": scale,
            "meta": {"trained": time.strftime("%Y-%m-%d %H:%M"), "params": int(n_par), "vectors": int(len(X)),
                     "snapshots": int(len(snaps)), "observations": int(W.sum()), "seed": SEED,
                     "val_over_threshold": frac}}
    model = Model(json.loads(json.dumps(spec)))                  # the scan-time loader must accept it
    for i in range(0, len(X), max(1, len(X) // 40)):             # pure-Python inference == numpy
        e_py = model.reconstruct(list(map(float, X[i])))[0]
        e_np = float(((forward(Z[i:i + 1])[-1] - Z[i:i + 1]) ** 2).mean())
        assert abs(e_py - e_np) < 1e-6 + 1e-6 * e_np, (i, e_py, e_np)
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    with open(MODEL + ".tmp", "w") as fh:
        json.dump(spec, fh, separators=(",", ":"))
    os.replace(MODEL + ".tmp", MODEL)
    print(f"model → {MODEL} ({os.path.getsize(MODEL) / 1e6:.1f} MB, {n_par:,} parametrów)")


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--minutes", type=float, default=10)
    c.add_argument("--every", type=float, default=10)
    c.set_defaults(fn=cmd_collect)
    t = sub.add_parser("train")
    t.add_argument("--epochs", type=int, default=60)
    t.set_defaults(fn=cmd_train)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
