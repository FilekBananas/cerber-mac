"""Machine-learning model files (Hugging Face repos, model zoos, pickled estimators).

Nothing here ever deserializes untrusted data: pickles are walked opcode by opcode with the
pickletools argument readers only (no pickle.load / torch.load / joblib.load), GGUF, safetensors
and .npy headers are parsed by hand, Keras configs are plain JSON, Lambda bytecode is inspected
as bytes (never marshal.loads), every loop is bounded (op count, time, sizes).

Formats
    pickle (.pkl/.pickle/.joblib/.dill/legacy torch .pt/.bin, zlib-joblib), PyTorch zip archives
    (archive/data.pkl arrives as its own member from the zip extractor), NumPy .npy/.npz object
    arrays, Keras .keras (config.json) / .h5 (model_config) / TF SavedModel .pb, GGUF metadata
    (tokenizer.chat_template), HF tokenizer_config.json / chat_template.json / *.jinja,
    safetensors headers, ONNX external_data, HF repo code (modeling_*.py, app.py, hubconf.py ...).

Detections (engine "heuristic"):
    Heur:Model.Pickle.DangerousImport       HIGH 70-95  pickle imports/calls code execution, process, network,
                                                       file-system or import-by-name callables ("os.system <- REDUCE")
    Heur:Model.Pickle.DynamicGlobal         HIGH 90 / MEDIUM 30  STACK_GLOBAL operands computed at load time
    Heur:Model.Pickle.GlobalTamper          HIGH 70     BUILD applied to an imported global (attribute overwrite)
    Heur:Model.Pickle.HiddenDangerousImport HIGH 70-90  dangerous GLOBAL/STACK_GLOBAL found by a raw scan of the
                                                       region the opcode walk could not reach (joblib/legacy tails)
    Heur:Model.Pickle.UnknownImport         INFO 0      globals outside the ML allow-list (custom code needed)
    Heur:Model.NumPy.ObjectArray            INFO 0      .npy object array (needs allow_pickle; scanned as a child)
    Heur:Model.Keras.LambdaCode             MEDIUM 35   Lambda layer with marshalled Python bytecode
    Heur:Model.Keras.LambdaDangerousCode    HIGH 90     ... whose bytecode references os/subprocess/exec/socket/...
    Heur:Model.Keras.DangerousReference     HIGH 90     config references a dangerous module/function or
                                                       enable_unsafe_deserialization (CVE-2025-1550 style)
    Heur:Model.Keras.FileDownload           MEDIUM 40   config references keras.utils.get_file
    Heur:Model.TF.PyFunc                    MEDIUM 35   SavedModel graph with PyFunc/EagerPyFunc ops
    Heur:Model.TF.FileWrite                 MEDIUM 30   SavedModel graph with WriteFile ops
    Heur:Model.GGUF.ChatTemplateSSTI        HIGH 90     Jinja sandbox escape in tokenizer.chat_template (CVE-2024-34359)
    Heur:Model.GGUF.ChatTemplateObfuscation MEDIUM 40   obfuscated attribute access in the chat template
    Heur:Model.HF.ChatTemplateSSTI / .ChatTemplateObfuscation   same for tokenizer_config.json / *.jinja
    Heur:Model.HF.RemoteCode                INFO 0      config.json auto_map (loading needs trust_remote_code)
    Heur:Model.Safetensors.MalformedHeader  INFO 5      header not JSON / inconsistent offsets / absurd sizes
    Heur:Model.ONNX.ExternalDataTraversal   MEDIUM 30   external_data location with '..'
    Heur:Model.ONNX.ExternalDataAbsolute    MEDIUM 20   absolute external_data location
    Heur:Model.HFCode.CredentialExfil       HIGH 80     repo code sends HF/cloud tokens or the environment to a
                                                       webhook/paste/tunnel/raw-IP sink
    Heur:Model.HFCode.CredentialAccess      MEDIUM 40   reads token/credential files and uploads data
    Heur:Model.HFCode.DownloadExec          HIGH 50/80  repo code executes downloaded content
    Heur:Model.HFCode.PipeToShell           HIGH 60     curl|sh style command in repo code
"""
from __future__ import annotations

import ast
import base64
import binascii
import codecs
import json
import re
import struct
import time
import zlib

import _compat_pickle
import pickletools

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from ..filetype import _LineCappedIO
from . import register

# --------------------------------------------------------------------------- limits
MAX_PICKLE_OPS = 4_000_000          # per object
PICKLE_SECONDS = 8.0                # per object
MAX_STREAMS = 64                    # concatenated pickles (legacy torch writes 5)
MAX_NESTED = 16                     # byte blobs handed back from nested loads
MAX_NESTED_BYTES = 256 << 20
RAW_SCAN_MAX = 32 << 20             # raw backstop scan of the region the opcode walk did not reach
MAX_SUBPICKLES = 64
FOLD_MAX = 16 << 20                 # constant-folded decode results
MAX_EVIDENCE = 20

PICKLE_EXTS = {"pkl", "pickle", "pck", "pcl", "p", "joblib", "jbl", "dill", "pt", "pth", "ckpt", "bin", "sav",
               "data", "pkl3", "mdl", "model", "th"}

DANGER, GADGET, SAFE, UNKNOWN = "danger", "gadget", "safe", "unknown"

# --------------------------------------------------------------------------- global classification
# fully-qualified prefixes: "os" covers os.system, os.path.join, ...
_DANGEROUS = frozenset("""
os posix nt _posixsubprocess subprocess pty commands popen2 platform.popen multiprocessing _thread thread asyncio
builtins.eval builtins.exec builtins.execfile builtins.compile builtins.__import__ builtins.open builtins.input
builtins.breakpoint builtins.globals builtins.locals builtins.vars builtins.setattr builtins.delattr builtins.apply
builtins.file builtins.reload builtins.help builtins.exit builtins.quit
runpy code codeop importlib imp pkgutil zipimport pydoc pdb bdb cProfile profile trace timeit doctest idlelib site
venv ensurepip pip setuptools distutils pkg_resources sys gc ctypes _ctypes cffi mmap marshal
types.CodeType types.FunctionType types.LambdaType types.MethodType types.ModuleType types.CellType types.new_class
operator.call pickle _pickle cPickle shelve jsonpickle yaml _yaml cloudpickle
dill.loads dill.load dill._dill._create_code dill._dill._create_function dill._dill._import_module
dill._dill._get_attr dill._dill._eval_repr dill._dill.loads dill._dill.load dill._dill._create_cell
joblib.load joblib.numpy_pickle.load joblib.numpy_pickle.NumpyUnpickler copyreg.add_extension copyreg.pickle
logging.config socket _socket ssl _ssl http.client httplib http.server socketserver SocketServer xmlrpc xmlrpclib
ftplib poplib imaplib nntplib smtplib telnetlib urllib urllib2 urllib3 requests httpx aiohttp websocket websockets
paramiko pycurl webbrowser antigravity shutil io.open _io.open io.FileIO _io.FileIO io.open_code codecs.open
fileinput IPython ipykernel jupyter_client invoke fabric sh plumbum pexpect ptyprocess sarge
typing.get_type_hints typing._eval_type sympy.sympify sympy.core.sympify
torch.hub torch.load torch.serialization.load torch.jit.load torch.jit._serialization.load torch.package
torch.utils.cpp_extension torch.utils.model_zoo torch._inductor torch.distributed.rpc torch.multiprocessing
torch.fx.graph_module.reduce_graph_module torch.fx.graph_module.reduce_package_graph_module
torch.fx.graph_module.reduce_deploy_graph_module torch.fx.graph_module._deserialize_graph_module
numpy.testing numpy.load numpy.loads numpy.lib.npyio numpy.lib._npyio_impl numpy.lib.format numpy.f2py
numpy.distutils numpy.ctypeslib numpy.lib._datasource numpy.DataSource numpy.save numpy.savez
numpy.savez_compressed numpy.savetxt numpy.memmap
pandas.read_pickle pandas.io.pickle pandas.eval pandas.core.computation
transformers.dynamic_module_utils transformers.agents transformers.tools transformers.pipeline
transformers.pipelines.pipeline sklearn.externals.joblib
keras.config.enable_unsafe_deserialization keras.utils.get_file
""".split())

# generic names: dangerous only as the module itself ("code.InteractiveConsole"), not as a prefix of a
# user package ("code.model.Net" from a research repo whose package is called "code")
_EXACT_ONLY = frozenset("code codeop profile trace site sh invoke fabric sarge plumbum gc imp thread commands "
                        "pty timeit venv".split())

# any component of a dotted name
_DANGER_NAMES = frozenset("""
system popen popen2 popen3 popen4 Popen spawnl spawnle spawnlp spawnlpe spawnv spawnve spawnvp spawnvpe posix_spawn
posix_spawnp execl execle execlp execlpe execv execve execvp execvpe forkpty check_output check_call getoutput
getstatusoutput run_path run_module import_module __import__ urlopen urlretrieve load_state_dict_from_url
hf_hub_download snapshot_download cached_download get_class_from_dynamic_module get_class_in_module load_library
LoadLibrary dlopen CDLL PyDLL WinDLL cdll enable_unsafe_deserialization rmtree exec_command runstring runctx
runcall set_trace pipepager tempfilepager sympify
""".split())

# "load"-like names are only dangerous inside serialization / model-hub libraries
_SERIAL_ROOTS = frozenset("""
pickle _pickle cPickle dill cloudpickle joblib torch numpy pandas marshal shelve yaml jsonpickle keras tensorflow
tf_keras transformers diffusers sentence_transformers sklearn skops lightning pytorch_lightning huggingface_hub timm
peft accelerate
""".split())
_SERIAL_LOAD = frozenset("load loads _load _loads load_model load_from_checkpoint from_pretrained from_single_file "
                         "Unpickler _Unpickler unpickle load_url read_pickle".split())

# import-by-name / attribute-walk gadgets: decided per call from their (constant) arguments
_GADGETS = {"builtins.getattr": "getattr", "operator.attrgetter": "attrgetter",
            "operator.methodcaller": "methodcaller", "numpy.core._ufunc_reconstruct": "ufunc",
            "numpy._core._ufunc_reconstruct": "ufunc"}

# attribute names that turn an attribute walk into a sandbox escape
_DUNDER_DANGER = frozenset("""
__class__ __mro__ __subclasses__ __globals__ __builtins__ __base__ __bases__ __dict__ __code__ __closure__
__func__ __self__ __getattribute__ __import__ __loader__ __spec__ __reduce__ __reduce_ex__ __init__ __new__
__setattr__ __delattr__ __init_subclass__ __subclasshook__ __defaults__ __kwdefaults__ __wrapped__ __module__
func_globals f_globals f_builtins f_back gi_frame tb_frame co_code
""".split())

_SAFE_EXACT = frozenset("""
collections.OrderedDict collections.defaultdict collections.Counter collections.deque collections.ChainMap
builtins.set builtins.frozenset builtins.bytearray builtins.bytes builtins.complex builtins.range builtins.slice
builtins.object builtins.Ellipsis builtins.NotImplemented builtins.dict builtins.list builtins.tuple builtins.int
builtins.float builtins.str builtins.bool
_codecs.encode codecs.encode copyreg._reconstructor copyreg.__newobj__ copyreg.__newobj_ex__
argparse.Namespace types.SimpleNamespace re._compile operator.getitem operator.itemgetter
torch.Size torch.device torch.dtype torch.Tensor torch.storage._load_from_bytes torch._tensor._rebuild_from_type
torch._tensor._rebuild_from_type_v2 torch.torch_version.TorchVersion torch.serialization._get_layout
torch.storage.UntypedStorage torch.storage.TypedStorage torch.storage._TypedStorage
numpy.core.multiarray._reconstruct numpy.core.multiarray.scalar numpy._core.multiarray._reconstruct
numpy._core.multiarray.scalar numpy.ndarray numpy.dtype numpy.core.numeric._frombuffer numpy._core.numeric._frombuffer
numpy.ma.core._mareconstruct numpy.ma.core.MaskedArray numpy.matrix numpy.matrixlib.defmatrix.matrix
numpy.random.__RandomState_ctor numpy.core.multiarray.ndarray numpy._core.multiarray.ndarray
joblib.numpy_pickle.NumpyArrayWrapper joblib.numpy_pickle.NDArrayWrapper joblib.numpy_pickle.ZNDArrayWrapper
joblib.numpy_pickle_compat.NDArrayWrapper joblib.numpy_pickle_compat.ZNDArrayWrapper
""".split())

_SAFE_PREFIX = tuple("""
torch.nn.modules torch.nn.parameter torch.nn.utils torch.nn.functional torch.nn.init torch.jit._pickle
torch.ao.quantization torch.ao.nn torch.quantization torch.nn.quantized torch.nn.intrinsic torch.optim
torch.distributions torch.cuda.amp __torch__ torchvision.models torchvision.transforms torchaudio.models
sklearn xgboost lightgbm catboost scipy.sparse transformers tokenizers sentence_transformers accelerate peft trl
diffusers timm pytorch_lightning lightning lightning_fabric omegaconf typing pathlib pandas numpy.random
numpy.dtypes datetime decimal fractions uuid
""".split())

_SAFE_RX = re.compile(
    r"torch\._utils\._rebuild_\w+$|torch\.cuda\.\w*Storage$|"
    r"torch\.(?:[A-Za-z0-9_]*Storage|float(?:16|32|64)?|double|half|bfloat16|u?int(?:1|2|3|4|5|6|7|8|16|32|64)?|"
    r"bool|complex(?:32|64|128)?|cfloat|cdouble|chalf|long|short|qu?int\w*|bits\w*|float8_\w+|contiguous_format|"
    r"channels_last(?:_3d)?|preserve_format|strided|sparse_\w+|_mkldnn|per_tensor_\w+|per_channel_\w+)$|"
    r"numpy\.(?:bool_?|u?int(?:8|16|32|64|c|p|_)?|u?longlong|u?short|u?byte|half|single|double|longdouble|"
    r"float(?:16|32|64|96|128|_)?|complex(?:64|128|192|256|_)?|clongdouble|cdouble|csingle|str_|bytes_|unicode_|"
    r"string_|object_|void|datetime64|timedelta64|generic|number|integer|floating|recarray|record)$")

# a name under a safe library prefix that does I/O or evaluation is not "safe", only unknown
_SAFE_EXCLUDE = re.compile(r"(?:read_|to_|load|save|dump|eval|exec|open|system|popen|download|fetch_|run|call)",
                           re.I)

# names whose bytes arguments are themselves serialized objects (scanned as children)
_NESTED_NAMES = frozenset("loads load _load_from_bytes _unpickle_model load_model from_bytes".split())

_B64_FUNCS = {"base64.b64decode", "base64.standard_b64decode", "base64.urlsafe_b64decode", "base64.decodebytes",
              "base64.decodestring", "binascii.a2b_base64"}


def _normalize(mod: str, name: str) -> tuple[str, str]:
    mod, name = mod.strip(), name.strip()
    mapped = _compat_pickle.NAME_MAPPING.get((mod, name))
    if mapped:
        mod, name = mapped
    else:
        mod = _compat_pickle.IMPORT_MAPPING.get(mod, mod)
    if mod == "__builtin__":
        mod = "builtins"
    return mod, name


_CLASSIFY_CACHE: dict[tuple[str, str], tuple[str, str]] = {}


def classify_global(mod: str, name: str) -> tuple[str, str]:
    """(fully qualified name, DANGER|GADGET|SAFE|UNKNOWN) for a pickle global / config reference."""
    key = (mod, name)
    hit = _CLASSIFY_CACHE.get(key)
    if hit is not None:
        return hit
    res = _classify(mod, name)
    if len(_CLASSIFY_CACHE) < 50_000:
        _CLASSIFY_CACHE[key] = res
    return res


def _classify(mod: str, name: str) -> tuple[str, str]:
    mod, name = _normalize(mod, name)
    full = f"{mod}.{name}" if name else mod
    parts = name.split(".") if name else []
    for p in parts:
        if len(p) > 4 and p.startswith("__") and p.endswith("__") and p not in ("__newobj__", "__newobj_ex__"):
            return full, DANGER
        if p in _DUNDER_DANGER:
            return full, DANGER
    acc = ""
    for seg in full.split("."):
        acc = f"{acc}.{seg}" if acc else seg
        if acc in _DANGEROUS and (acc not in _EXACT_ONLY or acc == mod):
            return full, DANGER
    if any(p in _DANGER_NAMES for p in parts):
        return full, DANGER
    if mod.split(".", 1)[0] in _SERIAL_ROOTS and any(p in _SERIAL_LOAD for p in parts):
        return full, DANGER
    if full in _GADGETS:
        return full, GADGET
    if full in _SAFE_EXACT or _SAFE_RX.match(full):
        return full, SAFE
    if name and "." not in name and not _SAFE_EXCLUDE.match(name):
        for p in _SAFE_PREFIX:
            if mod == p or mod.startswith(p + "."):
                return full, SAFE
    return full, UNKNOWN


# --------------------------------------------------------------------------- symbolic values
class _G:
    """An imported global (class/function reference)."""
    __slots__ = ("mod", "name", "full", "kind", "called")

    def __init__(self, mod: str, name: str, full: str, kind: str):
        self.mod, self.name, self.full, self.kind, self.called = mod, name, full, kind, False


class _Call:
    """Result of REDUCE/INST/OBJ/NEWOBJ: an object built at load time."""
    __slots__ = ("func", "args", "op")

    def __init__(self, func, args, op: str):
        self.func, self.args, self.op = func, args, op


class _Obj:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<obj>"


_OBJ = _Obj()
_OPS = [None] * 256
for _op in pickletools.opcodes:
    _OPS[ord(_op.code)] = _op
_P0_START = frozenset(b"(c]})NSVILFXUTKJMG")
_PUSH_ARG = frozenset(ord(c) for c in "IJKMLSTUBCVXFG") | {0x8a, 0x8b, 0x8e, 0x96, 0x8c, 0x8d}
_MEMO_OPS = frozenset(b"pqr\x94")


def _short(v, n: int = 80) -> str:
    if isinstance(v, str):
        return repr(v[:n] + ("…" if len(v) > n else ""))
    if isinstance(v, (bytes, bytearray)):
        return f"<{len(v)} bytes>"
    if isinstance(v, _G):
        return v.full
    if isinstance(v, _Call):
        return f"{_short(v.func, 40)}(…)"
    if isinstance(v, tuple):
        inner = ", ".join(_short(x, 40) for x in v[:3])
        return f"({inner}{', …' if len(v) > 3 else ''})"
    if isinstance(v, list):
        return "[" + ", ".join(_short(x, 40) for x in v[:3]) + (", …]" if len(v) > 3 else "]")
    if v is None or isinstance(v, (int, float, bool)):
        return repr(v)
    return "<obj>"


def _args_repr(args) -> str:
    if isinstance(args, tuple) and args:
        return " " + _short(args, 100)
    return ""


def _fold(full: str, a):
    """Constant-fold the pure string/bytes helpers used to hide names and nested payloads."""
    if not isinstance(a, tuple) or not a:
        return None
    x = a[0]
    try:
        if full in ("_codecs.encode", "codecs.encode") and isinstance(x, str):
            enc = (a[1] if len(a) > 1 and isinstance(a[1], str) else "utf-8").lower().replace("_", "-")
            if enc in ("rot13", "rot-13"):
                return codecs.encode(x, "rot13")
            if enc in ("latin1", "latin-1", "iso-8859-1", "utf-8", "utf8", "ascii"):
                return x.encode(enc, "replace")
            return None
        if full in ("codecs.decode", "_codecs.decode") and len(a) > 1 and isinstance(a[1], str):
            enc = a[1].lower().replace("-", "_")
            if enc in ("rot13", "rot_13") and isinstance(x, str):
                return codecs.decode(x, "rot13")
            if enc in ("base64", "base64_codec") and isinstance(x, (str, bytes)) and len(x) <= FOLD_MAX:
                return base64.b64decode(x)
            if enc in ("hex", "hex_codec") and isinstance(x, (str, bytes)) and len(x) <= FOLD_MAX:
                return binascii.unhexlify(x)
            if enc in ("zlib", "zlib_codec") and isinstance(x, bytes):
                d = zlib.decompressobj()
                return d.decompress(x, FOLD_MAX)
            return None
        if full in _B64_FUNCS and isinstance(x, (str, bytes)) and len(x) <= FOLD_MAX:
            if "urlsafe" in full:
                return base64.urlsafe_b64decode(x)
            return base64.b64decode(x)
        if full in ("base64.b32decode", "base64.b16decode", "base64.a85decode", "base64.b85decode") and \
                isinstance(x, (str, bytes)) and len(x) <= FOLD_MAX:
            return getattr(base64, full.split(".")[1])(x)
        if full in ("binascii.unhexlify", "binascii.a2b_hex", "builtins.bytes.fromhex") and \
                isinstance(x, (str, bytes)) and len(x) <= FOLD_MAX:
            return binascii.unhexlify(x)
        if full == "zlib.decompress" and isinstance(x, bytes):
            d = zlib.decompressobj()
            return d.decompress(x, FOLD_MAX)
        if full in ("operator.add", "operator.concat", "operator.iadd") and len(a) == 2 and \
                type(a[0]) is type(a[1]) and isinstance(x, (str, bytes)) and len(x) + len(a[1]) <= FOLD_MAX:
            return a[0] + a[1]
        if full in ("builtins.str", "builtins.bytes", "builtins.bytearray") and len(a) == 1 and \
                isinstance(x, (str, bytes)):
            return x if full == "builtins.str" or isinstance(x, bytes) else None
    except Exception:  # noqa: BLE001 - not foldable
        return None
    return None


# --------------------------------------------------------------------------- pickle walker
class PickleScan:
    """Symbolic, non-executing walk over one or more concatenated pickle streams."""

    def __init__(self, data: bytes, max_ops: int = MAX_PICKLE_OPS, seconds: float = PICKLE_SECONDS):
        self.data = data
        self.max_ops = max_ops
        self.deadline = time.monotonic() + seconds
        self.dangers: dict[str, int] = {}          # evidence -> score
        self.unknown: dict[str, int] = {}          # full name -> count
        self.dynamic: dict[str, int] = {}          # evidence -> score
        self.tamper: list[str] = []
        self.hidden: dict[str, int] = {}           # raw-scan evidence -> score
        self.nested: list[bytes] = []
        self.globals: set[str] = set()
        self.protocols: set[int] = set()
        self.ops = 0
        self.streams = 0
        self.completed = 0
        self.persistent_ids = 0
        self.ext_codes: list[int] = []
        self.anomalies = 0
        self.end = 0
        self.error: str | None = None
        self._import_ev: dict[str, str] = {}
        self._gadgets: list[_G] = []
        self._nested_bytes = 0

    # -- findings ----------------------------------------------------------
    def _danger(self, ev: str, score: int) -> None:
        if len(self.dangers) < 200 and self.dangers.get(ev, 0) < score:
            self.dangers[ev] = score

    def _make_global(self, mod: str, name: str, origin: str) -> _G:
        full, kind = classify_global(mod, name)
        nm, nn = _normalize(mod, name)
        g = _G(nm, nn, full, kind)
        self.globals.add(full)
        if kind == DANGER:
            ev = f"{full} ← {origin}"
            if full not in self._import_ev:
                self._import_ev[full] = ev
                self._danger(ev, 90)
        elif kind == UNKNOWN:
            self.unknown[full] = self.unknown.get(full, 0) + 1
        elif kind == GADGET:
            self._gadgets.append(g)
        return g

    def _called(self, g: _G, op: str, args) -> None:
        g.called = True
        if g.kind == DANGER:
            imp = self._import_ev.get(g.full)
            if imp is not None and imp in self.dangers and self.dangers[imp] <= 90:
                del self.dangers[imp]
            self._danger(f"{g.full} ← {op}{_args_repr(args)}", 95)

    def _collect_bytes(self, v, depth: int = 0) -> None:
        if isinstance(v, (bytes, bytearray)):
            if len(v) >= 8 and len(self.nested) < MAX_NESTED and self._nested_bytes + len(v) <= MAX_NESTED_BYTES:
                self.nested.append(bytes(v))
                self._nested_bytes += len(v)
        elif depth < 4:
            if isinstance(v, (tuple, list)):
                for x in v[:16]:
                    self._collect_bytes(x, depth + 1)
            elif isinstance(v, _Call):
                self._collect_bytes(v.args, depth + 1)

    def _gadget(self, g: _G, args, op: str):
        a = args if isinstance(args, tuple) else ()
        kind = _GADGETS.get(g.full, "")
        if kind == "getattr":
            if len(a) < 2 or not isinstance(a[1], str):
                self._danger(f"{g.full} ← {op} with a computed attribute name", 90)
                return None
            target, attr = a[0], a[1]
            if isinstance(target, _G):
                full, k2 = classify_global(target.mod, f"{target.name}.{attr}" if target.name else attr)
                if k2 == DANGER:
                    self._danger(f"builtins.getattr({target.full}, {attr!r}) → {full} ← {op}", 95)
                g2 = _G(target.mod, f"{target.name}.{attr}", full, k2)
                if k2 == UNKNOWN:
                    self.unknown[full] = self.unknown.get(full, 0) + 1
                return g2
            if any(p in _DUNDER_DANGER for p in attr.split(".")) or \
                    (isinstance(target, _Call) and isinstance(target.func, _G) and target.func.kind == DANGER):
                self._danger(f"builtins.getattr({_short(target, 40)}, {attr!r}) ← {op}", 95)
            return None                                  # bound method of a rebuilt object
        if kind in ("attrgetter", "methodcaller"):
            names = a[:1] if kind == "methodcaller" else a
            if not names or not all(isinstance(x, str) for x in names):
                self._danger(f"{g.full} ← {op} with computed attribute names", 90)
                return None
            for x in names:
                parts = x.split(".")
                if any(p in _DUNDER_DANGER or p in _DANGER_NAMES or
                       (p.startswith("__") and p.endswith("__")) for p in parts):
                    self._danger(f"{g.full}({x!r}) ← {op}", 95)
                    break
            return None
        if kind == "ufunc":
            if len(a) >= 2 and isinstance(a[0], str) and isinstance(a[1], str):
                full, k2 = classify_global(a[0], a[1])
                if k2 in (DANGER, GADGET) or a[0].split(".")[0] not in ("numpy", "scipy"):
                    self._danger(f"{g.full}({a[0]!r}, {a[1]!r}) → {full} ← {op}", 95)
                    k2 = DANGER
                return _G(a[0], a[1], full, k2)
            self._danger(f"{g.full} ← {op} with computed module/name", 90)
            return None
        return None

    def _call(self, func, args, op: str):
        if isinstance(func, _G):
            self._called(func, op, args)
            if func.kind == GADGET:
                res = self._gadget(func, args, op)
                if res is not None:
                    return res
            folded = _fold(func.full, args)
            if folded is not None:
                return folded
            last = func.full.rsplit(".", 1)[-1]
            if last in _NESTED_NAMES:
                self._collect_bytes(args)
        elif isinstance(func, _Call) and isinstance(func.func, _G) and func.func.kind == DANGER:
            # calling the object returned by a dangerous call (e.g. __import__('os').system ...)
            self._danger(f"{func.func.full}(…)(…) ← {op}", 95)
        return _Call(func, args, op)

    # -- one stream ----------------------------------------------------------
    def _stream(self, pos: int) -> tuple[bool, int, str | None]:
        data = self.data
        f = _LineCappedIO(data, pos)
        read, tell = f.read, f.tell
        stack: list = []
        marks: list[int] = []
        memo: dict = {}
        ops = self.ops
        max_ops = self.max_ops
        opos = pos

        def pop():
            if len(stack) > (marks[-1] if marks else 0):
                return stack.pop()
            self.anomalies += 1
            return _OBJ

        def pop_mark() -> list:
            if marks:
                k = marks.pop()
                items = stack[k:]
                del stack[k:]
                return items
            self.anomalies += 1
            items = stack[:]
            stack.clear()
            return items

        try:
            while True:
                if ops >= max_ops:
                    return False, opos, "opcode limit reached"
                if not ops & 0xFFF and time.monotonic() > self.deadline:
                    return False, opos, "time limit reached"
                opos = tell()
                c = read(1)
                if not c:
                    return False, opos, "truncated (no STOP)"
                b = c[0]
                op = _OPS[b]
                if op is None:
                    return False, opos, f"invalid opcode 0x{b:02x} at offset {opos}"
                arg = op.arg.reader(f) if op.arg is not None else None
                ops += 1
                if b in _PUSH_ARG:                       # ints, floats, str, bytes
                    stack.append(arg)
                elif b == 0x94:                          # MEMOIZE
                    if stack:
                        memo[len(memo)] = stack[-1]
                elif b in (0x71, 0x72, 0x70):            # BINPUT LONG_BINPUT PUT
                    if stack:
                        memo[arg] = stack[-1]
                elif b in (0x68, 0x6a, 0x67):            # BINGET LONG_BINGET GET
                    stack.append(memo.get(arg, _OBJ))
                elif b == 0x28:                          # MARK
                    marks.append(len(stack))
                elif b == 0x52:                          # REDUCE
                    args = pop()
                    func = pop()
                    stack.append(self._call(func, args, "REDUCE"))
                elif b == 0x93:                          # STACK_GLOBAL
                    name = pop()
                    mod = pop()
                    if isinstance(mod, str) and isinstance(name, str):
                        stack.append(self._make_global(mod, name, "STACK_GLOBAL"))
                    else:
                        computed = isinstance(mod, _Call) or isinstance(name, _Call)
                        ev = f"STACK_GLOBAL({_short(mod, 40)}, {_short(name, 40)}) at offset {opos}"
                        if len(self.dynamic) < 50:
                            self.dynamic[ev] = 90 if computed else 30
                        stack.append(_G("?", "?", "?", UNKNOWN))
                elif b == 0x63:                          # GLOBAL
                    mod, _, name = arg.partition(" ")
                    stack.append(self._make_global(mod, name, "GLOBAL"))
                elif b in (0x85, 0x86, 0x87):            # TUPLE1/2/3
                    n = b - 0x84
                    items = [pop() for _ in range(n)]
                    items.reverse()
                    stack.append(tuple(items))
                elif b == 0x74:                          # TUPLE
                    stack.append(tuple(pop_mark()))
                elif b == 0x29:                          # EMPTY_TUPLE
                    stack.append(())
                elif b == 0x5d:                          # EMPTY_LIST
                    stack.append([])
                elif b in (0x7d, 0x8f):                  # EMPTY_DICT EMPTY_SET
                    stack.append(_OBJ)
                elif b == 0x61:                          # APPEND
                    v = pop()
                    if stack and isinstance(stack[-1], list) and len(stack[-1]) < 64:
                        stack[-1].append(v)
                elif b == 0x65:                          # APPENDS
                    items = pop_mark()
                    if stack and isinstance(stack[-1], list) and len(stack[-1]) < 64:
                        stack[-1].extend(items[:64])
                elif b == 0x6c:                          # LIST
                    stack.append(pop_mark()[:64])
                elif b in (0x64, 0x91):                  # DICT FROZENSET
                    pop_mark()
                    stack.append(_OBJ)
                elif b == 0x73:                          # SETITEM
                    pop()
                    pop()
                elif b in (0x75, 0x90):                  # SETITEMS ADDITEMS
                    pop_mark()
                elif b == 0x62:                          # BUILD
                    pop()
                    if stack and isinstance(stack[-1], _G) and stack[-1].full != "?":
                        if len(self.tamper) < 20:
                            self.tamper.append(f"BUILD on {stack[-1].full} at offset {opos}")
                elif b == 0x81:                          # NEWOBJ
                    args = pop()
                    cls = pop()
                    stack.append(self._call(cls, args, "NEWOBJ"))
                elif b == 0x92:                          # NEWOBJ_EX
                    pop()
                    args = pop()
                    cls = pop()
                    stack.append(self._call(cls, args, "NEWOBJ_EX"))
                elif b == 0x69:                          # INST
                    items = pop_mark()
                    mod, _, name = arg.partition(" ")
                    g = self._make_global(mod, name, "INST")
                    stack.append(self._call(g, tuple(items), "INST"))
                elif b == 0x6f:                          # OBJ
                    items = pop_mark()
                    if items:
                        stack.append(self._call(items[0], tuple(items[1:]), "OBJ"))
                    else:
                        self.anomalies += 1
                        stack.append(_OBJ)
                elif b == 0x4e:                          # NONE
                    stack.append(None)
                elif b == 0x88:
                    stack.append(True)
                elif b == 0x89:
                    stack.append(False)
                elif b == 0x30:                          # POP
                    pop()
                elif b == 0x31:                          # POP_MARK
                    pop_mark()
                elif b == 0x32:                          # DUP
                    stack.append(stack[-1] if stack else _OBJ)
                elif b == 0x80:                          # PROTO
                    self.protocols.add(arg)
                elif b == 0x95:                          # FRAME
                    pass
                elif b == 0x2e:                          # STOP
                    pop()
                    return True, tell(), None
                elif b == 0x50:                          # PERSID
                    self.persistent_ids += 1
                    stack.append(_OBJ)
                elif b == 0x51:                          # BINPERSID
                    pop()
                    self.persistent_ids += 1
                    stack.append(_OBJ)
                elif b in (0x82, 0x83, 0x84):            # EXT1/2/4 (copyreg extension registry)
                    if len(self.ext_codes) < 20:
                        self.ext_codes.append(arg)
                    stack.append(_G("<extension>", str(arg), f"<extension code {arg}>", UNKNOWN))
                elif b == 0x97:                          # NEXT_BUFFER
                    stack.append(_OBJ)
                elif b == 0x98:                          # READONLY_BUFFER
                    pass
                else:                                    # pragma: no cover - every opcode is handled
                    self.anomalies += 1
        except Exception as exc:  # noqa: BLE001 - malformed argument / truncated stream
            return False, opos, f"malformed at offset {opos}: {str(exc)[:80]}"
        finally:
            self.ops = ops

    def _snapshot(self):
        return (dict(self.dangers), dict(self.unknown), dict(self.dynamic), list(self.tamper), len(self.nested),
                set(self.globals), dict(self._import_ev), len(self._gadgets), self.ext_codes[:])

    def _restore(self, s) -> None:
        (self.dangers, self.unknown, self.dynamic, self.tamper, n, self.globals, self._import_ev, ng,
         self.ext_codes) = s
        del self.nested[n:]
        del self._gadgets[ng:]

    # -- whole object ----------------------------------------------------------
    def run(self, start: int = 0) -> "PickleScan":
        data = self.data
        n = len(data)
        pos = start
        while pos < n and self.streams < MAX_STREAMS:
            first = self.streams == 0
            if not first:
                skip = 0
                while pos < n and data[pos] in b" \t\r\n" and skip < 16:
                    pos += 1
                    skip += 1
                if pos >= n:
                    break
                b0 = data[pos]
                proto = b0 == 0x80 and pos + 1 < n and 2 <= data[pos + 1] <= 5
                if not proto and b0 not in _P0_START:
                    break
                snap = self._snapshot()
            stopped, end, err = self._stream(pos)
            if not first and not stopped and not proto:
                self._restore(snap)             # trailing bytes that merely looked like a pickle
                break
            self.streams += 1
            self.end = end
            if not stopped:
                self.error = err
                break
            self.completed += 1
            pos = end
        for g in self._gadgets:
            if not g.called:
                self._danger(f"{g.full} referenced but not called directly (indirect use)", 70)
        # back-stop the unparsed region only when there is genuinely a pickle here: either a stream
        # completed (joblib/concat tails) or a resource limit cut a real parse short. A stream that
        # broke on an invalid opcode after a handful of ops is not a pickle - don't scan its bytes.
        limit_hit = bool(self.error) and self.error.startswith(("opcode limit", "time limit"))
        if self.end < n and (self.completed or limit_hit) and (self.ops >= 8 or limit_hit):
            self._raw_backstop(self.end)
        return self

    # -- raw backstop over the unparsed region --------------------------------
    _RAW_GLOBAL = re.compile(rb"[ci]([A-Za-z_][\w.]{0,63})\n([A-Za-z_][\w.]{0,63})\n")
    _RAW_STR = re.compile(rb"\x8c([\x01-\x40])|X([\x01-\x40])\x00\x00\x00", re.S)
    _RAW_ROOTS = frozenset("""
os posix nt subprocess builtins __builtin__ socket runpy pty ctypes marshal importlib pickle _pickle cPickle
webbrowser shutil requests urllib urllib2 httpx sys pdb bdb timeit code codeop cProfile profile commands
multiprocessing asyncio torch numpy types operator pydoc pkgutil dill cloudpickle joblib yaml _posixsubprocess
""".split())

    def _raw_backstop(self, start: int) -> None:
        region_end = min(len(self.data), start + RAW_SCAN_MAX)
        data = self.data
        seen: set[str] = set()

        def report(mod: str, name: str, how: str, off: int) -> None:
            full, kind = classify_global(mod, name)
            if kind in (DANGER, GADGET) and full not in seen and len(self.hidden) < 50:
                seen.add(full)
                self.hidden[f"{full} ({how} at offset {off})"] = 90 if kind == DANGER else 70

        for m in self._RAW_GLOBAL.finditer(data, start, region_end):
            mod = m.group(1).decode("latin-1")
            if mod.split(".")[0] in self._RAW_ROOTS:
                report(mod, m.group(2).decode("latin-1"), "raw GLOBAL", m.start())

        def read_str(p: int) -> tuple[str | None, int]:
            if p >= region_end:
                return None, p
            if data[p] == 0x8c and p + 1 < region_end:
                ln = data[p + 1]
                s = data[p + 2:p + 2 + ln]
                return (s.decode("latin-1") if len(s) == ln else None), p + 2 + ln
            if data[p] == 0x58 and p + 5 <= region_end:
                ln = struct.unpack_from("<I", data, p + 1)[0]
                if ln > 256:
                    return None, p
                s = data[p + 5:p + 5 + ln]
                return (s.decode("latin-1") if len(s) == ln else None), p + 5 + ln
            return None, p

        def skip_memo(p: int) -> int:
            if p < region_end:
                if data[p] == 0x94:
                    return p + 1
                if data[p] == 0x71:
                    return p + 2
                if data[p] == 0x72:
                    return p + 5
            return p

        checked = 0
        for m in self._RAW_STR.finditer(data, start, region_end):
            checked += 1
            if checked > 400_000:
                break
            mod, p = read_str(m.start())
            if not mod or mod.split(".")[0] not in self._RAW_ROOTS:
                continue
            p = skip_memo(p)
            name, p = read_str(p)
            if not name:
                continue
            p = skip_memo(p)
            if p < region_end and data[p] == 0x93:
                report(mod, name, "raw STACK_GLOBAL", m.start())
        self._subpickles(start, region_end)

    def _subpickles(self, start: int, end: int) -> None:
        """Nested pickles inside the unparsed region (joblib object arrays are pickled inline)."""
        data = self.data
        attempts = 0
        pos = start + 1
        while attempts < MAX_SUBPICKLES:
            j = data.find(b"\x80", pos, end)
            if j < 0 or j + 2 >= end:
                break
            pos = j + 1
            p = data[j + 1]
            if not 2 <= p <= 5 or (p >= 4 and data[j + 2] != 0x95):
                continue
            attempts += 1
            sub = PickleScan(data, max_ops=200_000, seconds=1.0)
            stopped, sub_end, _err = sub._stream(j)
            if not stopped or sub.ops < 4:
                continue
            for k, v in sub.dangers.items():
                self.hidden[f"{k} (nested pickle at offset {j})"] = v
            for k, v in sub.unknown.items():
                self.unknown[k] = self.unknown.get(k, 0) + v
            for k, v in sub.dynamic.items():
                self.dynamic[k] = v
            self.nested.extend(sub.nested[:max(0, MAX_NESTED - len(self.nested))])
            pos = max(pos, sub_end)


def _emit_pickle(ctx: ScanContext, obj: ScanObject, ps: PickleScan, what: str) -> None:
    if ps.dangers:
        ev = sorted(ps.dangers, key=lambda e: -ps.dangers[e])[:MAX_EVIDENCE]
        ctx.detect(obj, Detection(
            "Heur:Model.Pickle.DangerousImport", "heuristic", Confidence.HIGH, max(ps.dangers.values()),
            f"{what} imports/calls dangerous callables that run when the file is loaded "
            f"(pickle.load / torch.load / joblib.load)", ev))
    if ps.hidden:
        ev = sorted(ps.hidden, key=lambda e: -ps.hidden[e])[:MAX_EVIDENCE]
        ctx.detect(obj, Detection(
            "Heur:Model.Pickle.HiddenDangerousImport", "heuristic", Confidence.HIGH, max(ps.hidden.values()),
            f"{what}: dangerous pickle imports found past the end of the parsable stream "
            f"(interleaved data, nested or appended pickle)", ev))
    if ps.dynamic:
        sc = max(ps.dynamic.values())
        ctx.detect(obj, Detection(
            "Heur:Model.Pickle.DynamicGlobal", "heuristic", Confidence.HIGH if sc >= 70 else Confidence.MEDIUM, sc,
            "STACK_GLOBAL whose module/name are not string literals (computed at load time: obfuscation)",
            sorted(ps.dynamic, key=lambda e: -ps.dynamic[e])[:MAX_EVIDENCE]))
    if ps.tamper:
        ctx.detect(obj, Detection(
            "Heur:Model.Pickle.GlobalTamper", "heuristic", Confidence.HIGH, 70,
            "BUILD applied to an imported global: overwrites attributes of a module/class at load time",
            ps.tamper[:MAX_EVIDENCE]))
    unknown = sorted(ps.unknown, key=lambda k: -ps.unknown[k])
    if ps.ext_codes:
        unknown += [f"<extension code {c}>" for c in ps.ext_codes]
    if unknown:
        ctx.detect(obj, Detection(
            "Heur:Model.Pickle.UnknownImport", "heuristic", Confidence.INFO, 0,
            f"{what} references {len(unknown)} global(s) outside the ML allow-list (loading needs that code)",
            unknown[:25]))


def _pickle_meta(obj: ScanObject, ps: PickleScan, fmt: str) -> None:
    obj.meta["model"] = {
        "format": fmt, "protocols": sorted(ps.protocols), "streams": ps.streams, "opcodes": ps.ops,
        "globals": len(ps.globals), "persistent_ids": ps.persistent_ids, "parsed_bytes": ps.end,
        "complete": ps.error is None, "error": ps.error, "nested_payloads": len(ps.nested),
    }


def _looks_pickle_start(d: bytes) -> bool:
    if len(d) < 2:
        return False
    if d[0] == 0x80:
        return 2 <= d[1] <= 5
    return d[0] in _P0_START


def _is_zlib(d: bytes) -> bool:
    return len(d) > 2 and d[0] == 0x78 and ((d[0] << 8) | d[1]) % 31 == 0


@register
class PickleAnalyzer(Analyzer):
    """Pickle streams: raw pickles, legacy torch files, torch-zip data.pkl members, joblib, dill."""
    name = "ml_pickle"
    order = 45

    def applies(self, obj: ScanObject) -> bool:
        if obj.ftype == "pickle":
            return True
        ext = obj.extension
        if ext in PICKLE_EXTS and obj.ftype in ("binary", "unknown", "text", "json"):
            d = obj.data
            return _looks_pickle_start(d) or (ext in ("joblib", "jbl", "pkl", "pickle", "dill") and _is_zlib(d))
        return obj.name.lower() == "data.pkl" or (ext == "pkl" and obj.ftype in ("binary", "unknown"))

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        d = obj.data
        if not _looks_pickle_start(d) and _is_zlib(d):
            # joblib compress=True writes a raw zlib stream
            try:
                out = zlib.decompressobj().decompress(d, ctx.limits.max_child_size)
            except zlib.error as exc:
                obj.errors.append(f"ml_pickle: zlib: {exc}")
                return
            ctx.add_child(obj, out, (obj.name or "joblib") + ".unz", kind="decoded",
                          meta={"decoded_by": "zlib (joblib)"})
            obj.meta["model"] = {"format": "joblib (zlib-compressed)"}
            return
        ps = PickleScan(d).run(0)
        fmt = "pickle"
        low = obj.display_path.lower()
        if obj.name.lower().endswith("data.pkl") and obj.kind == "member":
            fmt = "pytorch zip (data.pkl)"
        elif _LEGACY_TORCH_MAGIC in _first_ints(d) or (ps.streams >= 4 and ps.persistent_ids):
            fmt = "legacy torch serialization"
        elif "joblib.numpy_pickle.NumpyArrayWrapper" in ps.globals or low.endswith((".joblib", ".jbl")):
            fmt = "joblib"
        _pickle_meta(obj, ps, fmt)
        if obj.ftype != "pickle" and ps.ops < 16 and ps.error is not None:
            ps.unknown.clear()                   # a few "opcodes" parsed out of text/binary: not a pickle
            ps.ext_codes.clear()
        _emit_pickle(ctx, obj, ps, f"{fmt} stream")
        for i, blob in enumerate(ps.nested):
            ctx.add_child(obj, blob, f"nested-load-{i}.bin", kind="decoded",
                          meta={"decoded_by": "pickle nested load argument"})


_LEGACY_TORCH_MAGIC = 0x1950a86a20f9469cfc6c


def _first_ints(d: bytes) -> tuple[int, ...]:
    """Legacy torch files start with the pickled magic number 0x1950a86a20f9469cfc6c (LONG1)."""
    if d[:4] == b"\x80\x02\x8a\x0a":
        return (int.from_bytes(d[4:14], "little"),)
    return ()


# --------------------------------------------------------------------------- NumPy .npy
@register
class NumpyAnalyzer(Analyzer):
    name = "ml_numpy"
    order = 45

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype == "npy"

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        d = obj.data
        if len(d) < 10:
            return
        major = d[6]
        try:
            if major == 1:
                hlen, hstart = struct.unpack_from("<H", d, 8)[0], 10
            else:
                hlen, hstart = struct.unpack_from("<I", d, 8)[0], 12
        except struct.error:
            return
        if hlen > (1 << 20) or hstart + hlen > len(d):
            obj.meta["model"] = {"format": "npy", "error": "header truncated or oversized"}
            return
        raw = d[hstart:hstart + hlen].decode("utf-8" if major >= 3 else "latin-1", "replace")
        try:
            header = ast.literal_eval(raw.strip())
        except (ValueError, SyntaxError, MemoryError, RecursionError, TypeError):
            obj.meta["model"] = {"format": "npy", "error": "header is not a Python literal"}
            return
        if not isinstance(header, dict):
            return
        descr = header.get("descr")
        obj.meta["model"] = {"format": "npy", "descr": str(descr)[:80], "shape": str(header.get("shape"))[:80]}
        if not _npy_has_object(descr):
            return
        ctx.detect(obj, Detection(
            "Heur:Model.NumPy.ObjectArray", "heuristic", Confidence.INFO, 0,
            "NumPy object array: the data is a pickle (np.load needs allow_pickle=True); scanned as a child",
            [f"descr={str(descr)[:80]}"]))
        ctx.add_child(obj, d[hstart + hlen:], "object-array.pkl", kind="decoded",
                      meta={"decoded_by": "npy object array"})


def _npy_has_object(descr, depth: int = 0) -> bool:
    if depth > 8:
        return False
    if isinstance(descr, str):
        return descr.lstrip("<>|=") == "O"
    if isinstance(descr, (list, tuple)):
        return any(_npy_has_object(x, depth + 1) for x in descr)
    return False


# --------------------------------------------------------------------------- Keras / TensorFlow
_CODE_DANGER = frozenset("""
system popen Popen subprocess exec eval __import__ import_module socket urlopen urlretrieve requests check_output
check_call getoutput getstatusoutput spawnl spawnv spawnve execv execve execl fork pty posix __builtins__ builtins
marshal pickle ctypes rmtree webbrowser shutil environ open compile os nt runpy b64decode loads
""".split())
_CODE_STRINGS = re.compile(rb"(?i)curl\s|wget\s|/bin/(?:ba)?sh|bash\s+-c|rm\s+-rf|https?://|powershell|nc\s+-e|"
                           rb"\.ssh/|/etc/passwd|chmod\s")
_MARSHAL_SHORT = re.compile(rb"[\x5a\x7a\xda\xfa]([\x01-\xff])", re.S)
_MARSHAL_LONG = re.compile(rb"[\x61\x41\xe1\xc1\x74\xf4\x75\xf5]([\x01-\xff][\x00-\x0f]\x00\x00)", re.S)
_B64_CODE = re.compile(rb'"(?:function|code|output_shape)"\s*:\s*(?:\{\s*"class_name"\s*:\s*"__tuple__"\s*,\s*'
                       rb'"items"\s*:\s*)?\[?\s*"((?:[A-Za-z0-9+/=]|\\n){24,})"')
_MODULE_REF = re.compile(rb'"module"\s*:\s*"([\w.]{1,128})"\s*,\s*"class_name"\s*:\s*"([\w.]{1,128})"'
                         rb'(?:\s*,\s*"config"\s*:\s*"([\w.]{1,128})")?')


def _marshal_names(blob: bytes) -> set[str]:
    names: set[str] = set()
    for rx, width in ((_MARSHAL_SHORT, 1), (_MARSHAL_LONG, 4)):
        for m in rx.finditer(blob):
            ln = blob[m.start(1)] if width == 1 else struct.unpack_from("<I", blob, m.start(1))[0]
            s = blob[m.end(1) if width == 1 else m.start(1) + 4:][:ln]
            if len(s) == ln and ln <= 512 and all(0x20 <= c < 0x7f for c in s):
                names.add(s.decode("ascii"))
            if len(names) > 4000:
                return names
    return names


def _decode_code_b64(s: str | bytes) -> bytes | None:
    if isinstance(s, bytes):
        s = s.replace(b"\\n", b"\n")
    try:
        raw = base64.b64decode(s, validate=False)
    except (binascii.Error, ValueError):
        return None
    # marshalled code object: TYPE_CODE ('c'), optionally with FLAG_REF
    if len(raw) >= 16 and raw[0] in (0x63, 0xe3):
        return raw
    return None


class _KerasFindings:
    def __init__(self) -> None:
        self.lambdas: dict[bytes, tuple[str, list[str]]] = {}   # code digest -> (where, dangerous names)
        self.refs: dict[str, int] = {}                           # evidence -> score
        self.downloads: list[str] = []
        self.blobs: list[bytes] = []

    def code(self, raw: bytes, where: str) -> None:
        key = raw[:4096]
        if key in self.lambdas or len(self.lambdas) >= 64:
            return
        names = _marshal_names(raw)
        bad = sorted(n for n in names if n in _CODE_DANGER)
        strs = [m.group(0).decode("latin-1") for m in _CODE_STRINGS.finditer(raw)][:5]
        self.lambdas[key] = (where, bad + strs)

    def ref(self, mod: str, name: str, where: str) -> None:
        full, kind = classify_global(mod, name)
        if "enable_unsafe_deserialization" in full:
            self.refs[f"{where}: {full} (turns off Keras safe_mode)"] = 90
        elif full.endswith(".get_file") or name == "get_file":
            self.downloads.append(f"{where}: {full}")
        elif kind in (DANGER, GADGET):
            self.refs[f"{where}: {full}"] = 90


def _walk_keras_json(doc, kf: _KerasFindings) -> None:
    stack = [(doc, "config")]
    visited = 0
    while stack and visited < 200_000:
        node, where = stack.pop()
        visited += 1
        if isinstance(node, dict):
            cls = node.get("class_name")
            mod = node.get("module")
            if isinstance(mod, str) and isinstance(cls, str):
                cfg = node.get("config")
                target = cfg if cls == "function" and isinstance(cfg, str) else cls
                kf.ref(mod, target, where)
            if cls == "Lambda" or (isinstance(cls, str) and cls.endswith("Lambda")):
                cfg = node.get("config") if isinstance(node.get("config"), dict) else {}
                lname = cfg.get("name", "lambda")
                for key in ("function", "output_shape"):
                    for s in _strings_in(cfg.get(key), 4):
                        raw = _decode_code_b64(s)
                        if raw is not None:
                            kf.code(raw, f"Lambda '{lname}' {key}")
            if cls == "__lambda__" and isinstance(node.get("config"), dict):
                raw = _decode_code_b64(str(node["config"].get("code", "")))
                if raw is not None:
                    kf.code(raw, "__lambda__")
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    stack.append((v, f"{where}.{k}" if len(where) < 120 else where))
                elif isinstance(v, str) and len(v) >= 64 and len(kf.blobs) < 8:
                    _maybe_blob(v, kf)
        elif isinstance(node, list):
            for v in node[:100_000]:
                if isinstance(v, (dict, list)):
                    stack.append((v, where))


def _strings_in(v, depth: int):
    if isinstance(v, str):
        yield v
    elif depth > 0 and isinstance(v, list):
        for x in v[:8]:
            yield from _strings_in(x, depth - 1)
    elif depth > 0 and isinstance(v, dict):
        for k in ("items", "code", "value", "config"):
            if k in v:
                yield from _strings_in(v[k], depth - 1)


_B64_FULL = re.compile(r"^[A-Za-z0-9+/=\s]+$")


def _maybe_blob(s: str, kf: _KerasFindings) -> None:
    """Base64 config values that decode to a pickle / zip (TorchModuleWrapper-style payloads)."""
    if len(s) > (96 << 20) or not _B64_FULL.match(s[:4096]):
        return
    try:
        head = base64.b64decode(s[:64], validate=False)
    except (binascii.Error, ValueError):
        return
    if not (head[:1] == b"\x80" or head[:2] == b"PK"):
        return
    try:
        raw = base64.b64decode(s, validate=False)
    except (binascii.Error, ValueError):
        return
    kf.blobs.append(raw)


def _emit_keras(ctx: ScanContext, obj: ScanObject, kf: _KerasFindings) -> None:
    for i, blob in enumerate(kf.blobs):
        ctx.add_child(obj, blob, f"config-blob-{i}.bin", kind="decoded",
                      meta={"decoded_by": "keras config base64"})
    if kf.lambdas:
        bad = [(w, b) for w, b in kf.lambdas.values() if b]
        if bad:
            ctx.detect(obj, Detection(
                "Heur:Model.Keras.LambdaDangerousCode", "heuristic", Confidence.HIGH, 90,
                "Keras Lambda layer bytecode references process/exec/network/file APIs (runs on model load)",
                [f"{w}: {', '.join(b[:8])}" for w, b in bad][:MAX_EVIDENCE]))
        ctx.detect(obj, Detection(
            "Heur:Model.Keras.LambdaCode", "heuristic", Confidence.MEDIUM, 35,
            "Keras Lambda layer with marshalled Python bytecode (executed when the model is loaded "
            "with safe_mode=False / old Keras)", [w for w, _ in kf.lambdas.values()][:MAX_EVIDENCE]))
    if kf.refs:
        ctx.detect(obj, Detection(
            "Heur:Model.Keras.DangerousReference", "heuristic", Confidence.HIGH, max(kf.refs.values()),
            "Keras config deserializes a dangerous Python callable", sorted(kf.refs)[:MAX_EVIDENCE]))
    if kf.downloads:
        ctx.detect(obj, Detection(
            "Heur:Model.Keras.FileDownload", "heuristic", Confidence.MEDIUM, 40,
            "Keras config calls keras.utils.get_file (downloads/overwrites files when loaded)",
            kf.downloads[:MAX_EVIDENCE]))


def _scan_keras_bytes(d: bytes, kf: _KerasFindings, json_anchors: bool) -> None:
    """Regex pass (works on h5 attributes / protobuf metadata), plus JSON walks from anchors."""
    for m in _B64_CODE.finditer(d):
        raw = _decode_code_b64(m.group(1))
        if raw is not None:
            kf.code(raw, "Lambda (raw config)")
    for m in _MODULE_REF.finditer(d):
        mod = m.group(1).decode()
        cls = m.group(2).decode()
        cfg = m.group(3).decode() if m.group(3) else None
        kf.ref(mod, cfg if cls == "function" and cfg else cls, "config")
    if json_anchors:
        dec = json.JSONDecoder()
        pos = 0
        for _ in range(8):
            j = d.find(b'{"class_name"', pos)
            if j < 0:
                break
            pos = j + 1
            chunk = d[j:j + (16 << 20)].decode("latin-1")      # 1 char per byte: offsets stay valid
            try:
                doc, end = dec.raw_decode(chunk)
            except (ValueError, RecursionError):
                continue
            _walk_keras_json(doc, kf)
            pos = j + max(1, end)


@register
class KerasAnalyzer(Analyzer):
    """Keras .h5/.hdf5 model_config, TF SavedModel / keras_metadata .pb graphs."""
    name = "ml_keras"
    order = 45

    def applies(self, obj: ScanObject) -> bool:
        if obj.ftype == "hdf5":
            return True
        return obj.extension == "pb" and obj.ftype in ("binary", "unknown") and obj.size < (2 << 30)

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        d = obj.data
        kf = _KerasFindings()
        if obj.ftype == "hdf5":
            if b"class_name" in d:
                _scan_keras_bytes(d, kf, json_anchors=True)
            _emit_keras(ctx, obj, kf)
            obj.meta["model"] = {"format": "hdf5", "keras_config": b"model_config" in d}
            return
        # TF SavedModel / keras_metadata.pb
        if b"class_name" in d:
            _scan_keras_bytes(d, kf, json_anchors=False)
        _emit_keras(ctx, obj, kf)
        pyfunc = [n for n in (b"PyFunc", b"EagerPyFunc", b"PyFuncStateless")
                  if bytes([0x12, len(n)]) + n in d]
        if pyfunc:
            ctx.detect(obj, Detection(
                "Heur:Model.TF.PyFunc", "heuristic", Confidence.MEDIUM, 35,
                "TensorFlow graph calls back into Python (PyFunc ops)", [n.decode() for n in pyfunc]))
        if b"\x12\tWriteFile" in d:
            ctx.detect(obj, Detection(
                "Heur:Model.TF.FileWrite", "heuristic", Confidence.MEDIUM, 30,
                "TensorFlow graph contains WriteFile ops (writes files when the graph runs)", ["WriteFile"]))
        obj.meta["model"] = {"format": "tensorflow protobuf", "pyfunc": [n.decode() for n in pyfunc]}


# --------------------------------------------------------------------------- chat templates (Jinja SSTI)
_JINJA_CODE = re.compile(r"\{[{%](?:(?![}%]\}).){0,8000}[}%]\}", re.S)
_SSTI_DUNDER = re.compile(r"__(?:class|mro|subclasses|globals|builtins|base|bases|import|getattribute|code|func|"
                          r"closure|loader|spec|reduce|reduce_ex|subclasshook)__")
_SSTI_WEAK_DUNDER = re.compile(r"__(?:init|new|dict|self|call|getitem|module|name|qualname|doc)__")
_SSTI_EXEC = re.compile(r"\bpopen\b|\bos\s*\.\s*system\b|\bsubprocess\b|\bcheck_output\b|\b__import__\b|"
                        r"\bimport_module\b|\b(?:eval|exec|compile)\s*\(|\bspawn[lv]p?e?\s*\(|\bgetoutput\b|"
                        r"/bin/(?:ba)?sh\b|\bos\.environ\b")
_SSTI_HELPER = re.compile(r"\b(?:lipsum|cycler|joiner|namespace|range|self|config|request|url_for|"
                          r"get_flashed_messages|dict|loop)\s*(?:\.\s*_|\[\s*['\"]_|\|\s*attr\s*\(\s*['\"]_)")
_SSTI_OBF = re.compile(r"\\x5[fF]|\\u005[fF]|\\137|\\x2[eE]|(['\"])_\1\s*\*\s*\d|"
                       r"\|\s*attr\s*\(\s*(?!['\"][A-Za-z][A-Za-z0-9]*['\"]\s*\))|"
                       r"format\s*\(\s*95\b|%c|\|\s*join\b[^}%]{0,80}['\"]_['\"]|\[\s*['\"]_|"
                       r"\|\s*attr\s*\(\s*['\"]_")
TEMPLATE_MAX = 512 << 10


def _ctx_snip(text: str, m: re.Match, n: int = 70) -> str:
    a = max(0, m.start() - n // 2)
    return text[a:m.end() + n // 2].replace("\n", " ")[:160]


def check_chat_template(tpl: str) -> tuple[list[str], int, list[str]]:
    """(strong evidence, strong score, obfuscation evidence) for a Jinja chat template."""
    code = "\n".join(m.group(0) for m in _JINJA_CODE.finditer(tpl[:TEMPLATE_MAX]))
    strong: list[str] = []
    score = 0
    for rx, sc in ((_SSTI_DUNDER, 90), (_SSTI_EXEC, 90), (_SSTI_HELPER, 90)):
        for m in rx.finditer(code):
            strong.append(_ctx_snip(code, m))
            score = max(score, sc)
            if len(strong) >= 6:
                break
    weak = [_ctx_snip(code, m) for m in _SSTI_WEAK_DUNDER.finditer(code)][:3]
    obf = [_ctx_snip(code, m) for m in _SSTI_OBF.finditer(code)][:4]
    if weak and not strong:
        obf = weak + obf
    return strong, score, obf


def _emit_template(ctx: ScanContext, obj: ScanObject, prefix: str, where: str, tpl: str) -> None:
    strong, score, obf = check_chat_template(tpl)
    if strong:
        ctx.detect(obj, Detection(
            f"{prefix}.ChatTemplateSSTI", "heuristic", Confidence.HIGH, score,
            "Chat template contains a Jinja sandbox escape / code execution payload (runs when the model "
            "formats a prompt; CVE-2024-34359 style)", [f"{where}: {s}" for s in strong][:MAX_EVIDENCE]))
    if obf:
        ctx.detect(obj, Detection(
            f"{prefix}.ChatTemplateObfuscation", "heuristic", Confidence.MEDIUM, 40,
            "Chat template uses obfuscated/underscore attribute access (Jinja SSTI technique)",
            [f"{where}: {s}" for s in obf][:MAX_EVIDENCE]))


# --------------------------------------------------------------------------- GGUF
class _Trunc(Exception):
    pass


_GGUF_FIXED = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
GGUF_MAX_KV = 1 << 16
GGUF_MAX_ELEMS = 16_000_000


class _GGUF:
    def __init__(self, data: bytes, endian: str, v1: bool):
        self.d, self.p, self.e, self.v1 = data, 0, endian, v1
        self.elems = 0

    def u32(self) -> int:
        if self.p + 4 > len(self.d):
            raise _Trunc
        v = struct.unpack_from(self.e + "I", self.d, self.p)[0]
        self.p += 4
        return v

    def u64(self) -> int:
        if self.p + 8 > len(self.d):
            raise _Trunc
        v = struct.unpack_from(self.e + "Q", self.d, self.p)[0]
        self.p += 8
        return v

    def length(self) -> int:
        return self.u32() if self.v1 else self.u64()

    def string(self, keep: bool, cap: int = 4 << 20) -> bytes | None:
        n = self.length()
        if n > (1 << 40):
            raise ValueError(f"absurd string length {n}")
        start = self.p
        self.p += n
        if keep:
            return self.d[start:min(start + n, start + cap, len(self.d))]
        if self.p > len(self.d):
            raise _Trunc
        return None

    def value(self, t: int, keep: bool, depth: int = 0):
        size = _GGUF_FIXED.get(t)
        if size is not None:
            if self.p + size > len(self.d):
                raise _Trunc
            v = None
            if keep:
                fmt = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "?", 10: "Q", 11: "q", 12: "d"}[t]
                v = struct.unpack_from(self.e + fmt, self.d, self.p)[0]
            self.p += size
            return v
        if t == 8:
            return self.string(keep)
        if t == 9:
            et = self.u32()
            cnt = self.length()
            self.elems += cnt
            if self.elems > GGUF_MAX_ELEMS:
                raise ValueError("array element budget exceeded")
            es = _GGUF_FIXED.get(et)
            if es is not None:
                self.p += es * cnt
                if self.p > len(self.d):
                    raise _Trunc
                return cnt
            if et == 8:
                d, p, L = self.d, self.p, len(self.d)
                fmt = self.e + ("I" if self.v1 else "Q")
                w = 4 if self.v1 else 8
                unpack = struct.unpack_from
                for _ in range(cnt):
                    if p + w > L:
                        self.p = p
                        raise _Trunc
                    p += w + unpack(fmt, d, p)[0]
                if p > L:
                    self.p = p
                    raise _Trunc
                self.p = p
                return cnt
            if et == 9 and depth < 2:
                for _ in range(cnt):
                    self.value(9, False, depth + 1)
                return cnt
            raise ValueError(f"unsupported array element type {et}")
        raise ValueError(f"unknown metadata value type {t}")


def parse_gguf(d: bytes) -> dict:
    """Header + metadata KV of a (possibly truncated) GGUF file; never touches tensor data."""
    info: dict = {"format": "gguf", "templates": {}, "truncated": False, "error": None}
    if len(d) < 8 or d[:4] != b"GGUF":
        info["error"] = "bad magic"
        return info
    ver = struct.unpack_from("<I", d, 4)[0]
    endian = "<"
    if not 1 <= ver <= 0xFFFF:
        ver_be = struct.unpack_from(">I", d, 4)[0]
        if 1 <= ver_be <= 0xFFFF:
            ver, endian = ver_be, ">"
    info["version"] = ver
    info["endian"] = "big" if endian == ">" else "little"
    r = _GGUF(d, endian, ver == 1)
    r.p = 8
    try:
        n_tensors = r.length()
        n_kv = r.length()
        info["tensors"] = n_tensors
        info["kv_count"] = n_kv
        if n_kv > GGUF_MAX_KV:
            info["error"] = f"absurd metadata count {n_kv}"
            n_kv = GGUF_MAX_KV
        meta: dict[str, object] = {}
        for _ in range(n_kv):
            raw_key = r.string(True, 4096)
            if raw_key is None or len(raw_key) > 1024:
                raise ValueError("bad key")
            key = raw_key.decode("utf-8", "replace")
            t = r.u32()
            want = "chat_template" in key or key in ("general.architecture", "general.name",
                                                     "tokenizer.ggml.model", "general.file_type")
            v = r.value(t, want)
            if want and v is not None:
                if isinstance(v, bytes):
                    v = v.decode("utf-8", "replace")
                    if "chat_template" in key:
                        info["templates"][key] = v
                    else:
                        meta[key] = v[:200]
                else:
                    meta[key] = v
            if r.p > len(d):
                raise _Trunc
        info["meta"] = meta
        info["kv_end"] = r.p
    except _Trunc:
        info["truncated"] = True
    except (ValueError, struct.error, OverflowError, MemoryError) as exc:
        info["error"] = str(exc)[:120]
    if not info["templates"] and (info["truncated"] or info["error"]):
        _gguf_template_fallback(d, endian, ver == 1, info)
    return info


def _gguf_template_fallback(d: bytes, endian: str, v1: bool, info: dict) -> None:
    """Locate tokenizer.chat_template* KV entries directly when the structured walk stopped early."""
    w = 4 if v1 else 8
    fmt = endian + ("I" if v1 else "Q")
    pos = 0
    for _ in range(16):
        i = d.find(b"tokenizer.chat_template", pos)
        if i < 0:
            break
        pos = i + 1
        if i < w:
            continue
        klen = struct.unpack_from(fmt, d, i - w)[0]
        if not 23 <= klen <= 256 or i + klen + 4 + w > len(d):
            continue
        key = d[i:i + klen].decode("utf-8", "replace")
        t = struct.unpack_from(endian + "I", d, i + klen)[0]
        if t != 8:
            continue
        slen = struct.unpack_from(fmt, d, i + klen + 4)[0]
        s0 = i + klen + 4 + w
        info["templates"][key] = d[s0:s0 + min(slen, 4 << 20)].decode("utf-8", "replace")


@register
class GGUFAnalyzer(Analyzer):
    name = "ml_gguf"
    order = 45

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype == "gguf"

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        info = parse_gguf(obj.data)
        templates = info.pop("templates", {})
        info["chat_templates"] = sorted(templates)
        obj.meta["model"] = info
        for key, tpl in templates.items():
            _emit_template(ctx, obj, "Heur:Model.GGUF", key, tpl)


# --------------------------------------------------------------------------- safetensors
_ST_DTYPES = {"F64": 8, "F32": 4, "F16": 2, "BF16": 2, "I64": 8, "I32": 4, "I16": 2, "I8": 1, "U64": 8, "U32": 4,
              "U16": 2, "U8": 1, "BOOL": 1, "F8_E4M3": 1, "F8_E5M2": 1, "F8_E8M0": 1, "F4": 0.5, "F6_E2M3": 0.75,
              "F6_E3M2": 0.75, "C64": 8, "C128": 16, "E8M0": 1}


@register
class SafetensorsAnalyzer(Analyzer):
    name = "ml_safetensors"
    order = 45

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype == "safetensors" or (obj.extension == "safetensors" and len(obj.data) >= 8)

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        d = obj.data
        problems: list[str] = []
        n = struct.unpack_from("<Q", d, 0)[0]
        meta: dict = {"format": "safetensors", "header_bytes": n}
        obj.meta["model"] = meta
        if n > (100 << 20) or n < 2:
            problems.append(f"header length {n} outside 2..100 MiB")
        elif 8 + n > len(d):
            meta["truncated"] = True              # partial download: nothing to judge
            return
        else:
            try:
                hdr = json.loads(d[8:8 + n].decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                hdr = None
                problems.append(f"header is not JSON ({str(exc)[:60]})")
            if hdr is not None and not isinstance(hdr, dict):
                problems.append("header is not a JSON object")
            elif isinstance(hdr, dict):
                problems += _check_st_header(hdr, len(d) - 8 - n, meta)
        if problems:
            ctx.detect(obj, Detection(
                "Heur:Model.Safetensors.MalformedHeader", "heuristic", Confidence.INFO, 5,
                "safetensors header is malformed (the format cannot execute code; file may be corrupt "
                "or crafted to crash loaders)", problems[:10]))


def _check_st_header(hdr: dict, data_len: int, meta: dict) -> list[str]:
    problems: list[str] = []
    md = hdr.get("__metadata__")
    if md is not None and (not isinstance(md, dict) or not all(isinstance(v, str) for v in md.values())):
        problems.append("__metadata__ is not a string->string map")
    n_t = 0
    max_end = 0
    for name, t in hdr.items():
        if name == "__metadata__":
            continue
        n_t += 1
        if not isinstance(t, dict):
            problems.append(f"{name[:60]}: entry is not an object")
            continue
        dt, shape, offs = t.get("dtype"), t.get("shape"), t.get("data_offsets")
        if not (isinstance(shape, list) and all(isinstance(x, int) and 0 <= x < (1 << 40) for x in shape)):
            problems.append(f"{name[:60]}: bad shape {str(shape)[:40]}")
            continue
        if not (isinstance(offs, list) and len(offs) == 2 and all(isinstance(x, int) for x in offs)
                and 0 <= offs[0] <= offs[1] < (1 << 45)):
            problems.append(f"{name[:60]}: bad data_offsets {str(offs)[:40]}")
            continue
        max_end = max(max_end, offs[1])
        isz = _ST_DTYPES.get(dt) if isinstance(dt, str) else None
        if isz is None:
            continue                              # new dtypes appear regularly; not an anomaly
        numel = 1
        for x in shape:
            numel *= x
        if numel * isz != offs[1] - offs[0] and not (isz < 1 and abs(numel * isz - (offs[1] - offs[0])) < 1):
            problems.append(f"{name[:60]}: {dt}{shape} needs {int(numel * isz)} bytes, offsets give "
                            f"{offs[1] - offs[0]}")
        if len(problems) > 20:
            break
    meta["tensors"] = n_t
    meta["data_bytes_declared"] = max_end
    return problems


# --------------------------------------------------------------------------- ONNX
_ONNX_LOC = re.compile(rb"\n\x08location\x12")


@register
class OnnxAnalyzer(Analyzer):
    name = "ml_onnx"
    order = 45

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype == "onnx" or (obj.extension == "onnx" and obj.ftype in ("binary", "unknown"))

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        d = obj.data
        trav: list[str] = []
        absol: list[str] = []
        n = 0
        for m in _ONNX_LOC.finditer(d):
            n += 1
            if n > 100_000:
                break
            p = m.end()
            ln, shift = 0, 0
            while p < len(d) and shift < 35:          # varint
                b = d[p]
                ln |= (b & 0x7F) << shift
                p += 1
                shift += 7
                if not b & 0x80:
                    break
            if ln > 4096:
                continue
            path = d[p:p + ln].decode("utf-8", "replace")
            norm = path.replace("\\", "/")
            if ".." in norm.split("/"):
                if path not in trav and len(trav) < 10:
                    trav.append(path)
            elif norm.startswith(("/", "~")) or re.match(r"^[A-Za-z]:/", norm):
                if path not in absol and len(absol) < 10:
                    absol.append(path)
        obj.meta["model"] = {"format": "onnx", "external_data_refs": n}
        if trav:
            ctx.detect(obj, Detection(
                "Heur:Model.ONNX.ExternalDataTraversal", "heuristic", Confidence.MEDIUM, 30,
                "ONNX external_data location escapes the model directory ('..' path traversal)", trav))
        if absol:
            ctx.detect(obj, Detection(
                "Heur:Model.ONNX.ExternalDataAbsolute", "heuristic", Confidence.MEDIUM, 20,
                "ONNX external_data location is an absolute path (reads arbitrary files into tensors)", absol))


# --------------------------------------------------------------------------- HF configs (json / jinja)
@register
class ModelConfigAnalyzer(Analyzer):
    """.keras config.json, HF config.json auto_map, tokenizer_config.json / chat_template.* templates."""
    name = "ml_config"
    order = 45

    def applies(self, obj: ScanObject) -> bool:
        n = obj.name.lower()
        if n.endswith(".jinja") or n.endswith(".jinja2"):
            return obj.size < (8 << 20)
        if not n.endswith(".json") or obj.size > (64 << 20) or obj.data.lstrip()[:1] not in (b"{", b"["):
            return False
        if n.endswith(("config.json", "chat_template.json", "generation_config.json", "tokenizer.json")):
            return True
        head = obj.data[:1 << 20]
        return b'"chat_template"' in head or b'"class_name"' in head or b'"auto_map"' in head

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        n = obj.name.lower()
        if n.endswith((".jinja", ".jinja2")):
            _emit_template(ctx, obj, "Heur:Model.HF", n, obj.text())
            return
        try:
            doc = json.loads(obj.text())
        except (ValueError, RecursionError):
            return
        if not isinstance(doc, (dict, list)):
            return
        if isinstance(doc, dict):
            tpl = doc.get("chat_template")
            if isinstance(tpl, str):
                _emit_template(ctx, obj, "Heur:Model.HF", "chat_template", tpl)
            elif isinstance(tpl, list):
                for t in tpl[:32]:
                    if isinstance(t, dict) and isinstance(t.get("template"), str):
                        _emit_template(ctx, obj, "Heur:Model.HF", f"chat_template[{t.get('name')}]",
                                       t["template"])
            am = doc.get("auto_map")
            if isinstance(am, dict) and am:
                refs = [f"{k}: {v}" for k, v in list(am.items())[:10]]
                ctx.detect(obj, Detection(
                    "Heur:Model.HF.RemoteCode", "heuristic", Confidence.INFO, 0,
                    "Model needs trust_remote_code=True: auto_map points at Python files in the repo "
                    "(scanned separately)", refs))
        if b'"class_name"' in obj.data[:1 << 20]:
            kf = _KerasFindings()
            _walk_keras_json(doc, kf)
            _emit_keras(ctx, obj, kf)


# --------------------------------------------------------------------------- HF repo Python code
_HF_FILE = re.compile(r"^(?:modeling|configuration|tokenization|processing|image_processing|feature_extraction|"
                      r"video_processing|pipeline|custom|handler|app|main|inference|predict|hubconf|model|"
                      r"interface|server|demo)[\w.-]*\.py$", re.I)
_ML_IMPORT = re.compile(rb"(?m)^[ \t]*(?:from|import)[ \t]+(?:transformers|torch|gradio|huggingface_hub|diffusers|"
                        rb"streamlit|tensorflow|keras|safetensors|accelerate|sentence_transformers|spaces|"
                        rb"timm|peft|vllm|llama_cpp)\b")
_TOKEN_SRC = re.compile(r"\bHF_TOKEN\b|HUGGING_FACE_HUB_TOKEN|HUGGINGFACEHUB_API_TOKEN|HF_API_TOKEN|"
                        r"\.cache/huggingface/(?:token|stored_tokens)|HfFolder\.get_token|\bget_token\s*\(\s*\)|"
                        r"\.git-credentials|\.aws/credentials|\.ssh/id_\w+|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|"
                        r"WANDB_API_KEY|ANTHROPIC_API_KEY")
_TOKEN_FILE = re.compile(r"\.cache/huggingface/(?:token|stored_tokens)|HfFolder\.get_token|\.git-credentials|"
                         r"\.aws/credentials|\.ssh/id_\w+|\.netrc\b")
_ENV_DUMP = re.compile(r"(?:dict|str|repr|json\.dumps)\s*\(\s*(?:dict\s*\(\s*)?os\.environ\b|"
                       r"\bfor\s+\w+(?:\s*,\s*\w+)?\s+in\s+os\.environ\b|os\.environ\.items\s*\(\s*\)|"
                       r"\{\s*\*\*\s*os\.environ\s*\}")
_SINK = re.compile(r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services|"
                   r"webhook\.site|pipedream\.net|requestbin|\.ngrok(?:-free)?\.(?:io|app|dev)|interact\.sh|"
                   r"\.oast\.(?:fun|me|pro|live|site|online)|burpcollaborator|canarytokens|pastebin\.com/api|"
                   r"transfer\.sh|https?://(?:\d{1,3}\.){3}\d{1,3}")
_SEND = re.compile(r"requests\.(?:post|put|patch)\s*\(|httpx\.(?:post|put)\s*\(|urllib\.request\.Request\s*\(|"
                   r"urlopen\s*\([^)\n]{0,200}data\s*=|\.sendall?\s*\(|\.sendto\s*\(|smtplib\.SMTP|ftplib\.FTP|"
                   r"session\.post\s*\(")
_DL = re.compile(r"requests\.get\s*\(|httpx\.get\s*\(|\burlopen\s*\(|\burlretrieve\s*\(|wget\.download\s*\(|"
                 r"urllib\.request\.\w+\s*\(")
_EXEC_SINK = re.compile(r"(?<![\w.])(?:exec|eval)\s*\(|runpy\.run_path\s*\(|"
                        r"spec_from_file_location\s*\(|marshal\.loads\s*\(")
_EXEC_DIRECT = re.compile(r"(?<![\w.])(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?(?:requests|httpx)\.get\s*\(|"
                          r"(?<![\w.])(?:exec|eval)\s*\([^\n]{0,120}\b(?:urlopen|urlretrieve)\s*\(|"
                          r"(?<![\w.])(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?open\s*\(\s*hf_hub_download\s*\(")
_PIPE_SHELL = re.compile(r"(?:curl|wget)\s[^\n'\"]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")


def _near(a: list[int], b: list[int], window: int) -> bool:
    return any(abs(x - y) <= window for x in a[:200] for y in b[:200])


@register
class HFCodeAnalyzer(Analyzer):
    """Model-repo Python (trust_remote_code modules, Space app.py, torch.hub hubconf.py)."""
    name = "ml_hfcode"
    order = 56

    def applies(self, obj: ScanObject) -> bool:
        if obj.size < 32 or obj.size > (8 << 20):
            return False
        if obj.extension not in ("py", "pyw") and obj.ftype != "python":
            return False
        if obj.ftype not in ("python", "text", "script", "javascript", "shell", "perl", "powershell"):
            return False
        p = obj.display_path.replace("\\", "/")
        if "/site-packages/" in p or "/dist-packages/" in p or "/lib/python3" in p:
            return False
        return bool(_HF_FILE.match(obj.name)) or bool(_ML_IMPORT.search(obj.data[:65536]))

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        text = obj.text(4 << 20)
        tok = [m.start() for m in _TOKEN_SRC.finditer(text)]
        env = [m.start() for m in _ENV_DUMP.finditer(text)]
        sink = [m.start() for m in _SINK.finditer(text)]
        send = [m.start() for m in _SEND.finditer(text)]
        if (tok or env) and sink and send:
            ev = [text[i:i + 80].split("\n")[0] for i in (tok + env)[:2] + sink[:2]]
            ctx.detect(obj, Detection(
                "Heur:Model.HFCode.CredentialExfil", "heuristic", Confidence.HIGH, 80,
                "Repo code sends tokens/credentials or the environment to a webhook/paste/tunnel endpoint", ev))
        else:
            tf = [m.start() for m in _TOKEN_FILE.finditer(text)]
            if tf and send and _near(tf, send, 1500):
                ev = [text[i:i + 80].split("\n")[0] for i in tf[:2] + send[:1]]
                ctx.detect(obj, Detection(
                    "Heur:Model.HFCode.CredentialAccess", "heuristic", Confidence.MEDIUM, 40,
                    "Repo code reads credential files / dumps the environment and uploads data", ev))
        m = _EXEC_DIRECT.search(text)
        if m:
            ctx.detect(obj, Detection(
                "Heur:Model.HFCode.DownloadExec", "heuristic", Confidence.HIGH, 80,
                "Repo code executes content fetched from the network", [m.group(0)[:160]]))
        else:
            dl = [m.start() for m in _DL.finditer(text)]
            ex = [m.start() for m in _EXEC_SINK.finditer(text)]
            if dl and ex and _near(dl, ex, 400):
                ctx.detect(obj, Detection(
                    "Heur:Model.HFCode.DownloadExec", "heuristic", Confidence.HIGH, 50,
                    "Repo code downloads content and executes code next to it",
                    [text[dl[0]:dl[0] + 80].split("\n")[0], text[ex[0]:ex[0] + 80].split("\n")[0]]))
        m = _PIPE_SHELL.search(text)
        if m:
            ctx.detect(obj, Detection(
                "Heur:Model.HFCode.PipeToShell", "heuristic", Confidence.HIGH, 60,
                "Repo code pipes a downloaded script into a shell", [m.group(0)[:160]]))
