"""Small machine-learning classifier over the TLSH fuzzy fingerprint of Mach-O files.

Analyzer "ml_tlsh" (order 60, deep mode only) for whole Mach-O files (thin and universal, top-level files and
archive/dmg/pkg members – not the slices cut out of universal binaries, because MalwareBazaar fingerprints whole
files). It computes the TLSH digest (or reuses the one the fuzzy engine stored), decodes it into numbers
(Lvalue = log length, Q1/Q2 ratios, the 128 two-bit bucket codes) and runs a tiny model trained by
tools/train_ml_tlsh.py on MalwareBazaar macOS fingerprints (positives) vs. clean Mach-O files of a Mac
(negatives), validated on malware families never seen in training.

Owner's AI policy: the model only influences, it never decides.
    * at most ML_CAP (15) points, Confidence LOW/MEDIUM – never HIGH, so on its own it can reach INFO at most
      and can never make a file MALICIOUS (verdict.py needs >= 80 points AND a HIGH finding);
    * positive-only: a "looks clean" output never subtracts points (a fuzzy fingerprint is easy to steer);
    * active defense ignores a MALICIOUS verdict that only exists because of these points
      (verdict.ml_decisive(), used by gui_backend.defend_result, watch.Watcher._persist and scan --quarantine);
    * the AI verifier neither judges nor cites "ml" findings (engines/ai.py accusations()): nothing to quote.

Security: the model is plain JSON (db/compiled/ml_tlsh.json, covered by the integrity seal), parsed with
json.loads, shape-checked and size-limited; there is no pickle/joblib/torch/numpy deserialisation anywhere and
inference is pure Python (a few hundred thousand multiply-adds per file).

Detections (engine "ml"):
    ML:TLSH.MacMalware      MEDIUM 15 / LOW 8   fingerprint resembles macOS malware families (supporting hint only)
"""
from __future__ import annotations

import json
import math
import os

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from . import register

try:
    import tlsh
except ImportError:  # pragma: no cover
    tlsh = None

ML_CAP = 15
ML_ENGINE = "ml"
DET_NAME = "ML:TLSH.MacMalware"
MODEL_FORMAT = "cerber-ml-tlsh"
MODEL_FILE = "ml_tlsh.json"
MAX_MODEL_BYTES = 64 << 20
MAX_LAYER = 4096
MIN_SIZE = 512
MAX_SIZE = 256 << 20             # TLSH of very large files: slow and far outside the training data
TYPES = {"macho", "macho_fat"}

N_BUCKETS = 128
RAW_DIM = 3 + N_BUCKETS                      # lval, q1, q2, buckets
RBF_CENTERS = tuple(range(0, 256, 16))
MLP_DIM = 4 * N_BUCKETS + 16 + 16 + 1 + len(RBF_CENTERS)


# ------------------------------------------------------------------ TLSH -> numbers (shared with training)

def tlsh_raw(digest: str) -> list[int] | None:
    """Decode a TLSH digest ("T1" + 70 hex) into [lval, q1, q2, b0..b127] (ints) or None.

    Header bytes are printed nibble-swapped (same as cerber.engines.ioc_fuzzy.tlsh_lval): the Lvalue is the
    reversed hex pair, Q1ratio/Q2ratio are the 3rd/4th hex chars of the Q byte. The checksum is ignored.
    Body: 32 bytes, four 2-bit quartile codes each."""
    if not isinstance(digest, str):
        return None
    t = digest.strip().upper()
    if t.startswith("T1"):
        t = t[2:]
    if len(t) != 70:
        return None
    try:
        lval = int(t[2:4][::-1], 16)
        q1, q2 = int(t[4], 16), int(t[5], 16)
        body = bytes.fromhex(t[6:])
    except ValueError:
        return None
    out = [lval, q1, q2]
    for byte in body:
        out += [(byte >> 6) & 3, (byte >> 4) & 3, (byte >> 2) & 3, byte & 3]
    return out


def mlp_sparse(raw: list[int]) -> list[tuple[int, float]]:
    """MLP input as (index, value) pairs of the non-zero entries: one-hot bucket codes, one-hot Q ratios,
    a scaled Lvalue and Gaussian bins over the Lvalue (log file length)."""
    lval, q1, q2 = raw[0], raw[1], raw[2]
    x = [(4 * i + v, 1.0) for i, v in enumerate(raw[3:3 + N_BUCKETS])]
    base = 4 * N_BUCKETS
    x.append((base + (q1 & 15), 1.0))
    x.append((base + 16 + (q2 & 15), 1.0))
    x.append((base + 32, (lval - 128) / 64.0))
    for k, c in enumerate(RBF_CENTERS):
        v = math.exp(-((lval - c) / 16.0) ** 2)
        if v > 1e-6:
            x.append((base + 33 + k, v))
    return x


def mlp_dense(raw: list[int]) -> list[float]:
    x = [0.0] * MLP_DIM
    for i, v in mlp_sparse(raw):
        x[i] = v
    return x


# ------------------------------------------------------------------ model (plain JSON, validated)

class ModelError(ValueError):
    pass


def _num(v) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        raise ModelError("liczba w modelu nieprawidłowa")
    return float(v)


def _vec(v, n: int | None = None) -> list[float]:
    if not isinstance(v, list) or (n is not None and len(v) != n) or len(v) > MAX_LAYER * 4:
        raise ModelError("wektor w modelu ma zły rozmiar")
    return [_num(x) for x in v]


class Model:
    """kind "mlp": layers [{"W": in x out, "b": out}], ReLU between, sigmoid at the end (no hidden = logistic).
    kind "gbdt": trees of nodes [feature, threshold, left, right] / leaves [-1, value]; sum + base -> sigmoid."""

    def __init__(self, spec: dict):
        if not isinstance(spec, dict) or spec.get("format") != MODEL_FORMAT or spec.get("version") != 1:
            raise ModelError("to nie jest model cerber-ml-tlsh v1")
        self.kind = spec.get("kind")
        th = spec.get("thresholds")
        if not isinstance(th, dict):
            raise ModelError("brak progów")
        self.t_medium = _num(th.get("medium"))
        self.t_low = _num(th.get("low", th.get("medium")))
        if not (0.0 < self.t_medium < 1.0 and 0.0 < self.t_low <= self.t_medium):
            raise ModelError("progi poza zakresem")
        self.meta = spec.get("meta") if isinstance(spec.get("meta"), dict) else {}
        if self.kind == "mlp":
            layers = spec.get("layers")
            if not isinstance(layers, list) or not 1 <= len(layers) <= 8:
                raise ModelError("zła liczba warstw")
            self.layers = []
            n_in = MLP_DIM
            for L in layers:
                if not isinstance(L, dict) or not isinstance(L.get("W"), list) or len(L["W"]) != n_in:
                    raise ModelError("zły kształt wag")
                b = _vec(L.get("b"))
                if not 1 <= len(b) <= MAX_LAYER:
                    raise ModelError("zła szerokość warstwy")
                W = [_vec(row, len(b)) for row in L["W"]]
                self.layers.append((W, b))
                n_in = len(b)
            if n_in != 1:
                raise ModelError("ostatnia warstwa musi mieć 1 wyjście")
        elif self.kind == "gbdt":
            self.base = _num(spec.get("base", 0.0))
            trees = spec.get("trees")
            if not isinstance(trees, list) or not 1 <= len(trees) <= 5000:
                raise ModelError("zła liczba drzew")
            self.trees = []
            for t in trees:
                if not isinstance(t, list) or not 1 <= len(t) <= 4096:
                    raise ModelError("złe drzewo")
                nodes = []
                for nd in t:
                    if not isinstance(nd, list) or len(nd) not in (2, 4):
                        raise ModelError("zły węzeł drzewa")
                    if len(nd) == 2:
                        if nd[0] != -1:
                            raise ModelError("zły liść")
                        nodes.append((-1, _num(nd[1]), 0, 0))
                    else:
                        f, thr, lo, hi = nd
                        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (f, lo, hi)) \
                                or not 0 <= f < RAW_DIM or not 0 <= lo < len(t) or not 0 <= hi < len(t):
                            raise ModelError("zły węzeł drzewa")
                        nodes.append((f, _num(thr), lo, hi))
                self.trees.append(nodes)
        else:
            raise ModelError(f"nieznany rodzaj modelu {self.kind!r}")

    def logit(self, raw: list[int]) -> float:
        if self.kind == "gbdt":
            s = self.base
            for nodes in self.trees:
                i, steps = 0, 0
                while nodes[i][0] != -1 and steps < 64:
                    f, thr, lo, hi = nodes[i]
                    i = lo if raw[f] <= thr else hi
                    steps += 1
                s += nodes[i][1] if nodes[i][0] == -1 else 0.0
            return s
        (W, b), rest = self.layers[0], self.layers[1:]
        h = list(b)
        for idx, v in mlp_sparse(raw):          # first layer: only the non-zero inputs
            row = W[idx]
            for j in range(len(h)):
                h[j] += v * row[j]
        for W, b in rest:
            h = [x if x > 0.0 else 0.0 for x in h]
            out = list(b)
            for i, x in enumerate(h):
                if x:
                    row = W[i]
                    for j in range(len(out)):
                        out[j] += x * row[j]
            h = out
        return h[0]

    def predict(self, raw: list[int]) -> float:
        z = max(-60.0, min(60.0, self.logit(raw)))
        return 1.0 / (1.0 + math.exp(-z))


def load_model_bytes(blob: bytes) -> Model:
    """Only JSON is accepted. Pickle (0x80 protocol header or classic opcodes), zip/npz and anything that is not a
    JSON object is refused before parsing."""
    if not isinstance(blob, (bytes, bytearray)) or len(blob) > MAX_MODEL_BYTES:
        raise ModelError("plik modelu za duży")
    head = bytes(blob[:4]).lstrip()
    if blob[:1] == b"\x80" or blob[:2] == b"PK" or not head.startswith(b"{"):
        raise ModelError("model musi być obiektem JSON (pickle/npz/zip odrzucone)")
    try:
        spec = json.loads(bytes(blob).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ModelError(f"model nie jest poprawnym JSON: {exc}") from None
    return Model(spec)


def load_model(path: str) -> Model:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as fh:
        return load_model_bytes(fh.read(MAX_MODEL_BYTES + 1))


def default_model_path() -> str:
    from .. import config
    return os.path.join(config.COMPILED, MODEL_FILE)


_MODEL: Model | None = None
_MODEL_TRIED = False


def get_model() -> Model | None:
    global _MODEL, _MODEL_TRIED
    if not _MODEL_TRIED:
        _MODEL_TRIED = True
        try:
            _MODEL = load_model(default_model_path())
        except (OSError, ModelError):
            _MODEL = None
    return _MODEL


def score_digest(model: Model, digest: str) -> tuple[float, Confidence, int] | None:
    """(probability, confidence, points) for a TLSH digest, or None below the low threshold. Points never exceed
    ML_CAP and confidence never exceeds MEDIUM."""
    raw = tlsh_raw(digest)
    if raw is None:
        return None
    p = model.predict(raw)
    if p >= model.t_medium:
        return p, Confidence.MEDIUM, ML_CAP
    if p >= model.t_low:
        return p, Confidence.LOW, min(8, ML_CAP)
    return None


@register
class MLTlshAnalyzer(Analyzer):
    name = "ml_tlsh"
    order = 60

    def __init__(self, model: Model | None = None):
        self._model = model

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype in TYPES and obj.kind not in ("slice", "decoded", "normalized") \
            and MIN_SIZE <= len(obj.data) <= MAX_SIZE

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        if not ctx.deep or any(d.confidence == Confidence.CERTAIN for d in obj.detections):
            return
        model = self._model or get_model()
        if model is None:
            return
        digest = obj.meta.get("tlsh")
        if not digest:
            if tlsh is None:
                return
            digest = tlsh.hash(obj.data)
        if not digest or digest == "TNULL":
            return
        res = score_digest(model, digest)
        if res is None:
            return
        p, conf, pts = res
        conf = min(conf, Confidence.MEDIUM)
        pts = max(0, min(ML_CAP, pts))
        ctx.detect(obj, Detection(DET_NAME, ML_ENGINE, conf, pts,
                                  f"Odcisk TLSH przypomina makowe złośliwe oprogramowanie (model ML, p={p:.3f}; "
                                  f"tylko wskazówka, nigdy samodzielny werdykt)",
                                  [f"tlsh={digest}", f"p={p:.4f}"]))
