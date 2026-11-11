"""Train the TLSH machine-learning hint (cerber/analyzers/ml_tlsh.py) – reproducible, seeded, local data only.

    # 1. clean fingerprints of this Mac (read-only; needs py-tlsh -> the project venv)
    .venv/bin/python tools/train_ml_tlsh.py negatives
    # 2. macOS rows of the MalwareBazaar CSV dump (db/feeds/bazaar_full.zip; stdlib only)
    .venv/bin/python tools/train_ml_tlsh.py positives
    # 3. train + evaluate on held-out malware families, export the winner (needs numpy: Homebrew python3)
    /opt/homebrew/bin/python3 -I tools/train_ml_tlsh.py train [--export db/compiled/ml_tlsh.json]

Nothing is ever executed or downloaded: negatives are files read from disk (Mach-O magic check, then TLSH of the
bytes); positives are fingerprints from the CSV dump – no malware file ever touches the disk. Derived data goes to
db/ml/ (git-ignored): negatives.csv (tlsh, type, size, group, bench flag, path) and positives.csv (tlsh, type,
family, sha256). Files listed in tests/static_measure/clean_files.json are flagged `bench=1` and never used for
training or threshold selection, so the false-positive benchmark stays an independent check.

Evaluation: grouped 5-fold cross-validation – positives grouped by MalwareBazaar `signature` (family; unlabelled
samples grouped by TLSH similarity so near-copies stay on one side), negatives grouped by app bundle / Homebrew
keg / system folder. Every test fold therefore contains only families and apps never seen in training.
Reported per model: ROC-AUC, recall at FPR <= 0.1 % (threshold set on the training folds' negatives, applied to
the test fold), precision at that threshold, false positives among test negatives, train-vs-test gap, and the
same numbers for the existing TLSH nearest-neighbour rule (distance <= 50 to a training positive).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import sys
import time
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, ROOT)

from cerber.analyzers.ml_tlsh import (MLP_DIM, MODEL_FORMAT, N_BUCKETS, RAW_DIM, Model,  # noqa: E402
                                      mlp_dense, tlsh_raw)

ML_DIR = os.path.join(ROOT, "db", "ml")
NEG_CSV = os.path.join(ML_DIR, "negatives.csv")
POS_CSV = os.path.join(ML_DIR, "positives.csv")
BAZAAR = os.path.join(ROOT, "db", "feeds", "bazaar_full.zip")
BENCH = os.path.join(ROOT, "tests", "static_measure", "clean_files.json")
SEED = 20261103

MACHO_MAGIC = {b"\xcf\xfa\xed\xfe": "macho", b"\xce\xfa\xed\xfe": "macho", b"\xfe\xed\xfa\xcf": "macho",
               b"\xfe\xed\xfa\xce": "macho", b"\xca\xfe\xba\xbe": "macho_fat", b"\xbe\xba\xfe\xca": "macho_fat",
               b"\xca\xfe\xba\xbf": "macho_fat"}
HOME = os.path.expanduser("~")
NEG_ROOTS = ["/Applications", f"{HOME}/Applications", "/opt/homebrew", "/usr/local", "/System/Applications",
             "/usr/bin", "/usr/sbin", "/usr/libexec", "/System/Library/CoreServices",
             # extra variety: app helpers/updaters, developer toolchains, plug-ins, system frameworks
             f"{HOME}/Library/Application Support", f"{HOME}/.cargo", f"{HOME}/.rustup", f"{HOME}/.vscode",
             "/Library/Application Support", "/Library/Frameworks", "/System/Library/Frameworks",
             "/System/Library/PrivateFrameworks", "/System/Library/Extensions"]
# never ~/Documents etc. (private data, security playgrounds); plus the FP benchmark's personal exclude list
_EXCL = os.path.join(ROOT, "tests", "static_measure", "exclude.local.txt")
EXCLUDE_NAMES = {"antywirus", "Cerber.app"} | ({ln.strip() for ln in open(_EXCL, encoding="utf-8") if ln.strip()}
                                              if os.path.isfile(_EXCL) else set())
PKG_ROOTS = [f"{HOME}/Downloads", f"{HOME}/Library/Caches/Homebrew", "/opt/homebrew/Caskroom", "/Library/Caches"]
PER_GROUP = 250
MIN_SIZE, MAX_SIZE = 512, 256 << 20


# ------------------------------------------------------------------ negatives (clean files of this Mac)

def _group(path: str) -> str:
    """Vendor-level group for grouped splits: app bundle, Homebrew keg/cask, or system folder."""
    for root in ("/Applications/", f"{HOME}/Applications/", "/System/Applications/"):
        if path.startswith(root):
            return "app:" + path[len(root):].split("/", 1)[0]
    for root in ("/opt/homebrew/Cellar/", "/usr/local/Cellar/", "/opt/homebrew/Caskroom/"):
        if path.startswith(root):
            return "brew:" + path[len(root):].split("/", 1)[0]
    if path.startswith(HOME + "/"):
        parts = path[len(HOME) + 1:].split("/")
        return "home:" + "/".join(parts[:3 if parts[0] == "Library" else 2])
    return "dir:" + "/".join(path.split("/")[:4])


def _kind(path: str) -> str | None:
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return None
    k = MACHO_MAGIC.get(head[:4])
    if k == "macho_fat" and head[:4] == b"\xca\xfe\xba\xbe":
        n = int.from_bytes(head[4:8], "big")
        if not 0 < n < 30:          # Java class file shares the magic
            return None
    return k


def _walk_candidates(bench: set[str]) -> list[tuple[str, str]]:
    seen_real: set[str] = set()
    out: list[tuple[str, str]] = []
    for root in NEG_ROOTS:
        if not os.path.isdir(root):
            continue
        for d, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [x for x in dirs if not x.startswith(".") and x not in EXCLUDE_NAMES]
            for f in files:
                p = os.path.join(d, f)
                try:
                    if os.path.islink(p) or not os.path.isfile(p):
                        continue
                    sz = os.path.getsize(p)
                except OSError:
                    continue
                if not MIN_SIZE <= sz <= MAX_SIZE:
                    continue
                rp = os.path.realpath(p)
                if rp in seen_real:
                    continue
                seen_real.add(rp)
                k = _kind(p)
                if k:
                    out.append((p, k))
    for root in PKG_ROOTS:
        if not os.path.isdir(root):
            continue
        for d, dirs, files in os.walk(root, followlinks=False):
            for f in files:
                low = f.lower()
                if low.endswith((".dmg", ".pkg", ".mpkg")):
                    p = os.path.join(d, f)
                    if os.path.isfile(p) and not os.path.islink(p) and MIN_SIZE <= os.path.getsize(p) <= MAX_SIZE:
                        out.append((p, "dmg" if low.endswith(".dmg") else "pkg"))
    return out


def _hash_one(item: tuple[str, str]) -> tuple | None:
    import tlsh
    path, kind = item
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_SIZE + 1)
    except OSError:
        return None
    h = tlsh.hash(data)
    if not h or h == "TNULL":
        return None
    return (h, kind, len(data), hashlib.sha256(data).hexdigest(), path)


def cmd_negatives(a) -> None:
    import multiprocessing as mp
    import random
    bench = set()
    if os.path.isfile(BENCH):
        bench = {os.path.realpath(p) for _, p in json.load(open(BENCH))["files"]}
    t0 = time.time()
    cands = _walk_candidates(bench)
    print(f"kandydaci: {len(cands):,} ({time.time() - t0:.0f} s)")
    rng = random.Random(SEED)
    by_group: dict[str, list] = {}
    for p, k in cands:
        by_group.setdefault(_group(p), []).append((p, k))
    chosen = []
    for g, items in sorted(by_group.items()):
        items.sort()
        bench_items = [x for x in items if os.path.realpath(x[0]) in bench]
        rest = [x for x in items if os.path.realpath(x[0]) not in bench]
        rng.shuffle(rest)
        chosen += bench_items + rest[:PER_GROUP]
    print(f"wybrane: {len(chosen):,} z {len(by_group)} grup")
    os.makedirs(ML_DIR, exist_ok=True)
    seen_sha = set()
    n = 0
    with mp.Pool(a.workers) as pool, open(NEG_CSV, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["tlsh", "type", "size", "group", "bench", "sha256", "path"])
        for res in pool.imap_unordered(_hash_one, chosen, chunksize=8):
            if res is None:
                continue
            h, kind, size, sha, path = res
            if sha in seen_sha:
                continue
            seen_sha.add(sha)
            w.writerow([h, kind, size, _group(path), int(os.path.realpath(path) in bench), sha, path])
            n += 1
    print(f"zapisano {n:,} negatywów -> {NEG_CSV} ({time.time() - t0:.0f} s)")


# ------------------------------------------------------------------ positives (MalwareBazaar CSV, macOS rows)

MAC_TYPES = {"macho": "macho", "dmg": "dmg", "pkg": "pkg", "app": "app", "mach-o": "macho"}


def _mac_type(ftype: str, fname: str) -> str | None:
    f = ftype.strip().lower()
    if f in MAC_TYPES:
        return MAC_TYPES[f]
    return None


def cmd_positives(a) -> None:
    counts: dict[str, int] = {}
    n = kept = 0
    os.makedirs(ML_DIR, exist_ok=True)
    with zipfile.ZipFile(BAZAAR) as z, open(POS_CSV, "w", newline="") as out:
        w = csv.writer(out)
        w.writerow(["tlsh", "type", "family", "sha256", "first_seen", "file_name"])
        name = next(i for i in z.namelist() if i.endswith(".csv"))
        with z.open(name) as fh:
            text = io.TextIOWrapper(fh, encoding="utf-8", errors="replace", newline="")
            reader = csv.reader((ln for ln in text if not ln.startswith("#")), skipinitialspace=True)
            for row in reader:
                if len(row) < 14:
                    continue
                n += 1
                ft = row[6].strip().lower()
                counts[ft] = counts.get(ft, 0) + 1
                kind = _mac_type(ft, row[5])
                if kind is None:
                    continue
                t = row[13].strip()
                if tlsh_raw(t) is None:
                    continue
                fam = row[8].strip()
                if not fam or fam.lower() in ("n/a", "null", "none"):
                    fam = ""
                w.writerow([t, kind, fam, row[1].strip(), row[0].strip(), row[5].strip()[:120]])
                kept += 1
    mac_like = {k: v for k, v in counts.items() if any(s in k for s in ("mach", "dmg", "pkg", "app", "osx", "mac"))}
    print(f"wierszy: {n:,}; typy macOS-podobne: {mac_like}; zapisano z TLSH: {kept:,} -> {POS_CSV}")


# ------------------------------------------------------------------ training (numpy)

def _load(path: str) -> list[dict]:
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def _tlsh_np(np, digests):
    raw = np.array([tlsh_raw(d) for d in digests], dtype=np.int16)
    return raw


def tlsh_dist_matrix(np, A, B, checksum_a=None, checksum_b=None):
    """TLSH distance (same formula as tlsh.diff with length) between raw rows A (n x 131) and B (m x 131)."""
    def mod_diff(x, y, R):
        d = np.abs(x - y)
        return np.minimum(d, R - d)
    out = np.empty((len(A), len(B)), dtype=np.int32)
    Bl, Bq1, Bq2 = B[:, 0].astype(np.int32), B[:, 1].astype(np.int32), B[:, 2].astype(np.int32)
    Bb = B[:, 3:].astype(np.int8)
    table = np.array([[0, 1, 2, 6], [1, 0, 1, 2], [2, 1, 0, 1], [6, 2, 1, 0]], dtype=np.int32)
    for s in range(0, len(A), 256):
        a = A[s:s + 256]
        ld = mod_diff(a[:, None, 0].astype(np.int32), Bl[None, :], 256)
        h = np.where(ld <= 1, ld, ld * 12)
        for col, Bq in ((1, Bq1), (2, Bq2)):
            qd = mod_diff(a[:, None, col].astype(np.int32), Bq[None, :], 16)
            h = h + np.where(qd <= 1, qd, (qd - 1) * 12)
        if checksum_a is not None:
            h = h + (checksum_a[s:s + 256, None] != checksum_b[None, :])
        ab = a[:, 3:].astype(np.int8)
        body = np.zeros((len(a), len(B)), dtype=np.int32)
        for k in range(N_BUCKETS):
            body += table[ab[:, k, None], Bb[None, :, k]]
        out[s:s + 256] = h + body
    return out


def _checksums(np, digests):
    """TLSH checksum byte (first header byte after the "T1" version prefix)."""
    out = []
    for d in digests:
        t = d.strip().upper()
        t = t[2:] if t.startswith("T1") else t
        out.append(int(t[0:2], 16))
    return np.array(out, dtype=np.int32)


def _cluster_unlabelled(np, raw, cs, thr=40):
    """Greedy TLSH clustering: unlabelled samples within `thr` of each other share a group."""
    n = len(raw)
    if n == 0:
        return []
    D = tlsh_dist_matrix(np, raw, raw, cs, cs)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    ii, jj = np.where(np.triu(D <= thr, 1))
    for i, j in zip(ii.tolist(), jj.tolist()):
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[ri] = rj
    return [f"unl:{find(i)}" for i in range(n)]


def _group_folds(np, groups, k, rng):
    uniq = sorted(set(groups))
    rng.shuffle(uniq)
    sizes = {}
    for g in groups:
        sizes[g] = sizes.get(g, 0) + 1
    # greedy balance: biggest groups first into the lightest fold
    order = sorted(uniq, key=lambda g: -sizes[g])
    load = [0] * k
    fold_of = {}
    for g in order:
        f = min(range(k), key=lambda i: load[i])
        fold_of[g] = f
        load[f] += sizes[g]
    return np.array([fold_of[g] for g in groups])


def roc_auc(np, y, s):
    order = np.argsort(s, kind="mergesort")
    s_sorted = s[order]
    ranks = np.empty(len(s))
    i = 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and s_sorted[j + 1] == s_sorted[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2 + 1
        i = j + 1
    npos = y.sum()
    nneg = len(y) - npos
    return float((ranks[y == 1].sum() - npos * (npos + 1) / 2) / (npos * nneg))


def thr_at_fpr(np, neg_scores, fpr):
    """Smallest threshold with FPR <= fpr on these negatives (score >= thr counts as positive)."""
    s = np.sort(neg_scores)[::-1]
    k = int(np.floor(fpr * len(s)))          # allowed false positives
    if k >= len(s):
        return float(s[-1])
    return float(np.nextafter(s[k], np.inf))


# --- models

class LogReg:
    name = "logreg"

    def __init__(self, np, l2=1e-3, epochs=60, lr=0.05, hidden=(), seed=SEED, dropout=0.0, batch=256):
        self.np, self.l2, self.epochs, self.lr, self.hidden, self.seed = np, l2, epochs, lr, hidden, seed
        self.dropout, self.batch = dropout, batch

    def params(self):
        dims = [MLP_DIM, *self.hidden, 1]
        return sum(dims[i] * dims[i + 1] + dims[i + 1] for i in range(len(dims) - 1))

    def fit(self, X, y, w):
        np = self.np
        rng = np.random.default_rng(self.seed)
        dims = [X.shape[1], *self.hidden, 1]
        self.W = [rng.normal(0, np.sqrt(2.0 / dims[i]), (dims[i], dims[i + 1])).astype(np.float32)
                  for i in range(len(dims) - 1)]
        self.b = [np.zeros(dims[i + 1], dtype=np.float32) for i in range(len(dims) - 1)]
        mW = [np.zeros_like(x) for x in self.W]
        vW = [np.zeros_like(x) for x in self.W]
        mb = [np.zeros_like(x) for x in self.b]
        vb = [np.zeros_like(x) for x in self.b]
        t = 0
        b1, b2, eps = 0.9, 0.999, 1e-8
        n = len(X)
        w = (w / w.mean()).astype(np.float32)
        for ep in range(self.epochs):
            perm = rng.permutation(n)
            lr = self.lr * (0.5 * (1 + np.cos(np.pi * ep / self.epochs)))
            for s in range(0, n, self.batch):
                idx = perm[s:s + self.batch]
                xb, yb, wb = X[idx], y[idx].astype(np.float32), w[idx]
                acts = [xb]
                masks = []
                h = xb
                for li in range(len(self.W) - 1):
                    h = np.maximum(h @ self.W[li] + self.b[li], 0)
                    if self.dropout:
                        m = (rng.random(h.shape) >= self.dropout).astype(np.float32) / (1 - self.dropout)
                        h = h * m
                        masks.append(m)
                    else:
                        masks.append(None)
                    acts.append(h)
                z = (h @ self.W[-1] + self.b[-1])[:, 0]
                p = 1 / (1 + np.exp(-np.clip(z, -30, 30)))
                g = ((p - yb) * wb / len(idx))[:, None].astype(np.float32)
                t += 1
                for li in range(len(self.W) - 1, -1, -1):
                    gW = acts[li].T @ g + self.l2 * self.W[li]
                    gb = g.sum(0)
                    if li > 0:
                        g = (g @ self.W[li].T) * (acts[li] > 0)
                        if masks[li - 1] is not None:
                            g = g * masks[li - 1]
                    for P, G, M, V in ((self.W, gW, mW, vW), (self.b, gb, mb, vb)):
                        M[li] = b1 * M[li] + (1 - b1) * G
                        V[li] = b2 * V[li] + (1 - b2) * G * G
                        mh = M[li] / (1 - b1 ** t)
                        vh = V[li] / (1 - b2 ** t)
                        P[li] -= (lr * mh / (np.sqrt(vh) + eps)).astype(np.float32)
        return self

    def logit(self, X):
        np = self.np
        out = np.empty(len(X), dtype=np.float64)
        for s in range(0, len(X), 4096):
            h = X[s:s + 4096]
            for li in range(len(self.W) - 1):
                h = np.maximum(h @ self.W[li] + self.b[li], 0)
            out[s:s + 4096] = (h @ self.W[-1] + self.b[-1])[:, 0]
        return out

    def export(self):
        return {"kind": "mlp", "layers": [{"W": [[round(float(v), 6) for v in row] for row in W],
                                           "b": [round(float(v), 6) for v in b]} for W, b in zip(self.W, self.b)]}


class GBDT:
    """Histogram gradient boosting on the raw integer features (values are small ints, so exact splits)."""
    name = "gbdt"

    def __init__(self, np, trees=300, depth=4, lr=0.1, min_leaf=20, l2=1.0, subsample=0.8, colsample=0.5,
                 seed=SEED):
        self.np, self.n_trees, self.depth, self.lr, self.min_leaf, self.l2 = np, trees, depth, lr, min_leaf, l2
        self.subsample, self.colsample, self.seed = subsample, colsample, seed

    def params(self):
        return self.n_trees * (2 ** (self.depth + 1) - 1)

    def fit(self, R, y, w):
        np = self.np
        rng = np.random.default_rng(self.seed)
        R = R.astype(np.int32)
        self.nbins = int(R.max()) + 1
        w = w / w.mean()
        p0 = np.clip((y * w).sum() / w.sum(), 1e-4, 1 - 1e-4)
        self.base = float(np.log(p0 / (1 - p0)))
        F = np.full(len(y), self.base)
        self.trees = []
        for _ in range(self.n_trees):
            p = 1 / (1 + np.exp(-F))
            g = (p - y) * w
            h = np.maximum(p * (1 - p), 1e-6) * w
            rows = np.where(rng.random(len(y)) < self.subsample)[0]
            cols = np.sort(rng.choice(R.shape[1], max(1, int(R.shape[1] * self.colsample)), replace=False))
            nodes = []
            self._build(R, g, h, rows, cols, 0, nodes)
            self.trees.append(nodes)
            F += self._predict_tree(nodes, R)
        return self

    def _build(self, R, g, h, rows, cols, d, nodes):
        np = self.np
        idx = len(nodes)
        G, H = g[rows].sum(), h[rows].sum()
        nodes.append(None)
        if d >= self.depth or len(rows) < 2 * self.min_leaf:
            nodes[idx] = [-1, float(-G / (H + self.l2) * self.lr)]
            return idx
        best = (0.0, None, None)
        parent = G * G / (H + self.l2)
        Rs = R[rows][:, cols]
        gs, hs = g[rows], h[rows]
        nb = self.nbins
        offs = (np.arange(len(cols)) * nb)[None, :]
        flat = (Rs + offs).ravel()
        gh = np.bincount(flat, weights=np.repeat(gs, len(cols)), minlength=nb * len(cols)).reshape(len(cols), nb)
        hh = np.bincount(flat, weights=np.repeat(hs, len(cols)), minlength=nb * len(cols)).reshape(len(cols), nb)
        cnt = np.bincount(flat, minlength=nb * len(cols)).reshape(len(cols), nb)
        gl, hl, cl = np.cumsum(gh, 1), np.cumsum(hh, 1), np.cumsum(cnt, 1)
        gr, hr, cr = G - gl, H - hl, len(rows) - cl
        gain = gl ** 2 / (hl + self.l2) + gr ** 2 / (hr + self.l2) - parent
        gain[(cl < self.min_leaf) | (cr < self.min_leaf)] = -1
        k = int(np.argmax(gain))
        fi, thr = divmod(k, nb)
        if gain.flat[k] > 1e-6:
            best = (gain.flat[k], int(cols[fi]), thr)
        if best[1] is None:
            nodes[idx] = [-1, float(-G / (H + self.l2) * self.lr)]
            return idx
        f, thr = best[1], best[2]
        left = rows[R[rows, f] <= thr]
        right = rows[R[rows, f] > thr]
        li = self._build(R, g, h, left, cols, d + 1, nodes)
        ri = self._build(R, g, h, right, cols, d + 1, nodes)
        nodes[idx] = [f, float(thr) + 0.5, li, ri]
        return idx

    def _predict_tree(self, nodes, R):
        np = self.np
        feat = np.array([nd[0] for nd in nodes])
        thr = np.array([nd[1] if nd[0] != -1 else 0.0 for nd in nodes])
        val = np.array([nd[1] if nd[0] == -1 else 0.0 for nd in nodes])
        lo = np.array([nd[2] if nd[0] != -1 else i for i, nd in enumerate(nodes)])
        hi = np.array([nd[3] if nd[0] != -1 else i for i, nd in enumerate(nodes)])
        cur = np.zeros(len(R), dtype=np.int64)
        ar = np.arange(len(R))
        for _ in range(self.depth + 1):
            f = feat[cur]
            go_left = R[ar, np.maximum(f, 0)] <= thr[cur]
            cur = np.where(f == -1, cur, np.where(go_left, lo[cur], hi[cur]))
        return val[cur]

    def logit(self, R):
        R = R.astype(self.np.int32)
        return self.base + sum(self._predict_tree(t, R) for t in self.trees)

    def export(self):
        return {"kind": "gbdt", "base": self.base,
                "trees": [[[nd[0], round(nd[1], 6)] if nd[0] == -1 else nd for nd in t] for t in self.trees]}


# one family under several MalwareBazaar names must stay on one side of every split
FAMILY_ALIAS = {"amosstealer": "amos", "atomicstealer": "amos", "atomic": "amos", "odysseystealer": "poseidon",
                "poseidonstealer": "poseidon"}

# MalwareBazaar's file_type_guess does not tell thin from universal Mach-O: one weighting group
WEIGHT_TYPE = {"macho_fat": "macho"}


def _weights(np, y, types, pos_types):
    """Balance classes, and give negatives of each file type the positives' type share (so 'type' is no cue)."""
    w = np.ones(len(y), dtype=np.float64)
    pos = y == 1
    w[pos] = 1.0 / pos.sum()
    neg_idx = np.where(~pos)[0]
    types = [WEIGHT_TYPE.get(t, t) for t in types]
    pos_types = {}
    for i in np.where(pos)[0]:
        pos_types[types[i]] = pos_types.get(types[i], 0) + 1
    tn = {}
    for i in neg_idx:
        tn[types[i]] = tn.get(types[i], 0) + 1
    total_pt = sum(pos_types.values())
    for i in neg_idx:
        share = pos_types.get(types[i], 0) / total_pt if total_pt else 0
        w[i] = share / tn[types[i]] if share else 1e-3 / tn[types[i]]
    w[~pos] *= 1.0 / w[~pos].sum()
    return w * len(y) / 2


def cmd_train(a) -> None:
    import numpy as np
    rng_py = __import__("random").Random(SEED)
    neg = [r for r in _load(NEG_CSV) if r["type"] in a.types]
    pos = [r for r in _load(POS_CSV) if r["type"] in a.types]
    bench = [r for r in neg if r["bench"] == "1"]
    neg = [r for r in neg if r["bench"] != "1"]
    # drop clean files whose exact TLSH is also a MalwareBazaar fingerprint (trojanized copies / shared libs)
    pos_set = {r["tlsh"].upper() for r in pos}
    clash = [r for r in neg if r["tlsh"].upper() in pos_set]
    neg = [r for r in neg if r["tlsh"].upper() not in pos_set]
    # dedupe exact positive fingerprints (same sample under several hashes / re-uploads)
    seen, upos = set(), []
    for r in pos:
        k = r["tlsh"].upper()
        if k not in seen:
            seen.add(k)
            upos.append(r)
    pos = upos
    print(f"pozytywy {len(pos):,} (rodzin z nazwą: {len({r['family'] for r in pos if r['family']})}, "
          f"bez nazwy: {sum(1 for r in pos if not r['family'])}), negatywy {len(neg):,} "
          f"({len({r['group'] for r in neg})} grup), benchmark wyłączony: {len(bench)}, "
          f"usunięte kolizje TLSH: {len(clash)}")
    tp = {}
    for r in pos:
        tp[r["type"]] = tp.get(r["type"], 0) + 1
    tn = {}
    for r in neg:
        tn[r["type"]] = tn.get(r["type"], 0) + 1
    print(f"typy: pozytywy {tp}, negatywy {tn}")
    fams = {}
    for r in pos:
        fams[r["family"] or "(brak)"] = fams.get(r["family"] or "(brak)", 0) + 1
    print("rodziny (top 15):", sorted(fams.items(), key=lambda x: -x[1])[:15])

    digests = [r["tlsh"] for r in pos] + [r["tlsh"] for r in neg]
    R = _tlsh_np(np, digests)
    CS = _checksums(np, digests)
    y = np.array([1] * len(pos) + [0] * len(neg))
    types = [r["type"] for r in pos] + [r["type"] for r in neg]
    unl = [i for i, r in enumerate(pos) if not r["family"]]
    unl_groups = _cluster_unlabelled(np, R[unl], CS[unl]) if unl else []
    groups = []
    ui = iter(unl_groups)
    for r in pos:
        fam = r["family"].lower()
        groups.append(f"fam:{FAMILY_ALIAS.get(fam, fam)}" if fam else next(ui))
    groups += [f"neg:{r['group']}" for r in neg]
    R_full = R.copy()
    if a.no_lval:                    # ablation: hide the file-length code (Lvalue) from every model
        R[:, 0] = 128
    X = np.array([mlp_dense(list(map(int, row))) for row in R], dtype=np.float32)

    folds = _group_folds(np, groups, a.folds, rng_py)
    fold_desc = []
    for f in range(a.folds):
        gc: dict[str, int] = {}
        for g, fo, yy in zip(groups, folds, y):
            if fo == f and yy == 1:
                key = g if g.startswith("fam:") else "unl"
                gc[key] = gc.get(key, 0) + 1
        top = sorted(gc.items(), key=lambda x: -x[1])[:3]
        fold_desc.append(", ".join(f"{k.removeprefix('fam:')} {v}" for k, v in top))
        print(f"  fold {f}: {int(((folds == f) & (y == 1)).sum())} poz. ({fold_desc[-1]}), "
              f"{int(((folds == f) & (y == 0)).sum())} neg.")
    configs = [
        ("logreg (lin.)", lambda: LogReg(np, hidden=(), epochs=40, lr=0.02, l2=1e-4), "mlp"),
        ("MLP 0.2M (561-256-256-1)", lambda: LogReg(np, hidden=(256, 256), epochs=40, lr=2e-3, l2=1e-4,
                                                     dropout=0.2), "mlp"),
        ("MLP 1M (561-1024-512-1)", lambda: LogReg(np, hidden=(1024, 512), epochs=40, lr=1e-3, l2=1e-4,
                                                    dropout=0.3), "mlp"),
        ("GBDT 300x d4", lambda: GBDT(np, trees=300, depth=4), "raw"),
        ("GBDT 600x d6", lambda: GBDT(np, trees=600, depth=6, lr=0.05), "raw"),
    ]
    if a.big:
        configs.append(("MLP 8.6M (561-4096-1536-1)", lambda: LogReg(np, hidden=(4096, 1536), epochs=25, lr=5e-4,
                                                                     l2=1e-4, dropout=0.4), "mlp"))
    if a.only:
        configs = [c for c in configs if any(o.lower() in c[0].lower() for o in a.only)]

    # nearest-neighbour baseline (the existing fuzzy engine's rule): min TLSH distance to a training positive
    results = {}
    nn_rows = []
    oof = {name: np.zeros(len(y)) for name, _, _ in configs}
    oof_nn = np.zeros(len(y))
    for f in range(a.folds):
        tr, te = folds != f, folds == f
        tr_pos = np.where(tr & (y == 1))[0]
        te_idx = np.where(te)[0]
        D = tlsh_dist_matrix(np, R_full[te_idx], R_full[tr_pos], CS[te_idx], CS[tr_pos])
        oof_nn[te_idx] = D.min(1)
    def fit_scores(make, feat, tr_mask, te_mask):
        w = _weights(np, y[tr_mask], [types[i] for i in np.where(tr_mask)[0]], tp)
        M = make()
        Xtr = X[tr_mask] if feat == "mlp" else R[tr_mask]
        Xte = X[te_mask] if feat == "mlp" else R[te_mask]
        M.fit(Xtr, y[tr_mask].astype(np.float64), w)
        return M.logit(Xtr), M.logit(Xte)

    for name, make, feat in configs:
        t0 = time.time()
        per_fold = []
        for f in range(a.folds):
            tr, te = folds != f, folds == f
            s_tr, s_te = fit_scores(make, feat, tr, te)
            oof[name][te] = s_te
            ytr, yte = y[tr], y[te]
            # deployment-like threshold: 0.1 % FPR on the *out-of-fold* scores of the training negatives
            # (inner grouped CV over the training part; the outer test fold is never looked at)
            inner = np.full(len(y), -1)
            inner[tr] = folds[tr]
            inner_scores = np.zeros(len(y))
            for g in sorted(set(folds[tr].tolist())):
                itr, ite = tr & (inner != g), tr & (inner == g)
                inner_scores[ite] = fit_scores(make, feat, itr, ite)[1]
            thr = thr_at_fpr(np, inner_scores[tr & (y == 0)], 0.001)
            thr_trainroc = thr_at_fpr(np, s_tr[ytr == 0], 0.001)
            per_fold.append({
                "auc_tr": roc_auc(np, ytr, s_tr), "auc_te": roc_auc(np, yte, s_te),
                "rec_tr": float((s_tr[ytr == 1] >= thr_trainroc).mean()),
                "rec_te": float((s_te[yte == 1] >= thr).mean()),
                "fp_te": int((s_te[yte == 0] >= thr).sum()), "neg_te": int((yte == 0).sum()),
                "tp_te": int((s_te[yte == 1] >= thr).sum()), "pos_te": int((yte == 1).sum())})
            p = per_fold[-1]
            print(f"      fold {f} [{fold_desc[f]}]: AUC tr {p['auc_tr']:.3f} te {p['auc_te']:.3f}, recall at the "
                  f"inner-CV 0.1% threshold {p['rec_te']:.3f} ({p['tp_te']}/{p['pos_te']}), "
                  f"FP {p['fp_te']}/{p['neg_te']}", flush=True)
        agg = {k: float(np.mean([p[k] for p in per_fold])) for k in per_fold[0]}
        tp_sum = sum(p["tp_te"] for p in per_fold)
        fp_sum = sum(p["fp_te"] for p in per_fold)
        o = oof[name]
        roc_thr = thr_at_fpr(np, o[y == 0], 0.001)
        agg.update({"fp_sum": fp_sum, "neg_sum": sum(p["neg_te"] for p in per_fold), "tp_sum": tp_sum,
                    "pos_sum": sum(p["pos_te"] for p in per_fold),
                    "precision": tp_sum / (tp_sum + fp_sum) if tp_sum + fp_sum else float("nan"),
                    "oof_auc": roc_auc(np, y, o),
                    "oof_rec_at_0.1": float((o[y == 1] >= roc_thr).mean()),
                    "oof_fp_at_0.1": int((o[y == 0] >= roc_thr).sum()),
                    "params": make().params(), "seconds": time.time() - t0})
        agg["oof_prec_at_0.1"] = float((o[y == 1] >= roc_thr).sum() / max(1, (o >= roc_thr).sum()))
        results[name] = agg
        print(f"  {name}: AUC tr {agg['auc_tr']:.3f} / te {agg['auc_te']:.3f} (pooled {agg['oof_auc']:.3f}) | "
              f"ROC recall@FPR<=0.1% {agg['oof_rec_at_0.1']:.3f} (FP {agg['oof_fp_at_0.1']}, prec "
              f"{agg['oof_prec_at_0.1']:.3f}) | deployed thr: recall {tp_sum / agg['pos_sum']:.3f}, "
              f"FP {fp_sum}/{agg['neg_sum']}, prec {agg['precision']:.3f} | train recall@0.1% {agg['rec_tr']:.3f} | "
              f"{agg['params']:,} par. | {agg['seconds']:.0f} s", flush=True)

    # NN baseline metrics (distance rule, no threshold fitting: <=50 and <=30 like the fuzzy engine)
    for cut in (30, 50):
        hit = oof_nn <= cut
        tpn, fpn = int(hit[y == 1].sum()), int(hit[y == 0].sum())
        results[f"TLSH-NN <= {cut}"] = {"rec_te": tpn / (y == 1).sum(), "fp_sum": fpn, "neg_sum": int((y == 0).sum()),
                                        "precision": tpn / (tpn + fpn) if tpn + fpn else float("nan"),
                                        "auc_te": roc_auc(np, y, -oof_nn.astype(float)), "params": 0}
        print(f"  TLSH-NN <= {cut}: recall {tpn / (y == 1).sum():.3f}, FP {fpn}/{(y == 0).sum()}, "
              f"AUC (−dist) {results[f'TLSH-NN <= {cut}']['auc_te']:.3f}")
    far = (oof_nn > 50) & (y == 1)
    print(f"  pozytywy testowe bez sąsiada <= 50 w treningu: {far.sum()} / {(y == 1).sum()}")
    for name in oof:
        # pooled OOF threshold at 0.1 % FPR (diagnostic): what does ML catch that NN misses?
        thr = thr_at_fpr(np, oof[name][y == 0], 0.001)
        ml = oof[name] >= thr
        print(f"    {name}: OOF recall@0.1% {ml[y == 1].mean():.3f}; na pozytywach bez sąsiada NN: "
              f"{ml[far].mean() if far.any() else float('nan'):.3f}; ML lub NN<=50: "
              f"{(ml | (oof_nn <= 50))[y == 1].mean():.3f} (NN sam: {(oof_nn <= 50)[y == 1].mean():.3f})")
        results[name]["oof_far_recall"] = float(ml[far].mean()) if far.any() else None
        results[name]["oof_union_recall"] = float((ml | (oof_nn <= 50))[y == 1].mean())

    os.makedirs(ML_DIR, exist_ok=True)
    with open(os.path.join(ML_DIR, f"results-{'-'.join(a.types)}.json"), "w") as fh:
        json.dump({"results": results, "counts": {"pos": len(pos), "neg": len(neg), "bench": len(bench),
                                                  "families": len({g for g in groups if g.startswith('fam:')})}},
                  fh, indent=1)

    if a.export and a.no_lval:
        sys.exit("--export z --no-lval nie ma sensu (analizator zawsze podaje Lvalue)")
    if a.export:
        name = next(n for n, _, _ in configs if a.export_model.lower() in n.lower())
        make, feat = next((m, f) for n, m, f in configs if n == name)
        # final model on all non-benchmark data; thresholds from the out-of-fold scores of the negatives
        # (held-out apps), i.e. what an unseen clean app is expected to score
        oof_neg = oof[name][y == 0]
        t_med = thr_at_fpr(np, oof_neg, a.fpr_medium)
        t_low = thr_at_fpr(np, oof_neg, a.fpr_low)
        w = _weights(np, y, types, tp)
        M = make().fit(X if feat == "mlp" else R, y.astype(np.float64), w)
        sig = lambda z: 1 / (1 + np.exp(-z))  # noqa: E731
        spec = {"format": MODEL_FORMAT, "version": 1, **M.export(),
                "thresholds": {"medium": float(sig(t_med)), "low": float(sig(t_low))},
                "meta": {"trained": time.strftime("%Y-%m-%d"), "model": name, "seed": SEED,
                         "positives": len(pos), "negatives": len(neg), "types": a.types,
                         "fpr_medium": a.fpr_medium, "fpr_low": a.fpr_low,
                         "cv": {k: results[name].get(k) for k in ("auc_te", "rec_te", "fp_sum", "neg_sum",
                                                                  "precision", "auc_tr", "rec_tr")}}}
        model = Model(json.loads(json.dumps(spec)))          # validate with the scan-time loader
        # sanity: the exported pure-Python model matches numpy on a sample
        for i in range(0, len(R), max(1, len(R) // 50)):
            zpy = model.logit(list(map(int, R[i])))
            znp = float(M.logit((X if feat == "mlp" else R)[i:i + 1])[0])
            assert abs(zpy - znp) < 1e-2 * max(1, abs(znp)), (i, zpy, znp)
        # benchmark files (never trained on): how many would get the hint
        if bench:
            Rb = _tlsh_np(np, [r["tlsh"] for r in bench])
            pb = np.array([model.predict(list(map(int, row))) for row in Rb])
            print(f"benchmark (wyłączone z treningu): {len(bench)} plików, >= medium: "
                  f"{int((pb >= spec['thresholds']['medium']).sum())}, >= low: "
                  f"{int((pb >= spec['thresholds']['low']).sum())}")
            for r, p in sorted(zip(bench, pb), key=lambda x: -x[1])[:5]:
                print(f"    p={p:.4f} {r['path']}")
        tmp = a.export + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(spec, fh, separators=(",", ":"))
        os.replace(tmp, a.export)
        print(f"wyeksportowano {name} -> {a.export} ({os.path.getsize(a.export) / 1e6:.1f} MB), "
              f"progi p: medium {spec['thresholds']['medium']:.4f}, low {spec['thresholds']['low']:.4f}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("negatives")
    n.add_argument("--workers", type=int, default=8)
    sub.add_parser("positives")
    t = sub.add_parser("train")
    t.add_argument("--types", nargs="+", default=["macho", "macho_fat"])
    t.add_argument("--folds", type=int, default=5)
    t.add_argument("--big", action="store_true", help="also an ~8.6M-parameter numpy MLP (slow)")
    t.add_argument("--only", nargs="*")
    t.add_argument("--no-lval", action="store_true", help="ablation: models without the length code")
    t.add_argument("--export")
    t.add_argument("--export-model", default="GBDT 300x d4")
    t.add_argument("--fpr-medium", type=float, default=0.0005)
    t.add_argument("--fpr-low", type=float, default=0.002)
    a = ap.parse_args()
    {"negatives": cmd_negatives, "positives": cmd_positives, "train": cmd_train}[a.cmd](a)


if __name__ == "__main__":
    main()
