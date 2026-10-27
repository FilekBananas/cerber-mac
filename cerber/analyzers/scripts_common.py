"""Shared machinery for the script analyzers (no analyzer is registered here).

Rules are plain data: Rule(name, regex, score, description, caps, need). A rule with
score 0 only contributes a capability tag; capability combinations are scored by
COMBOS. Every regex must be bounded (no nested unbounded quantifiers).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core import Confidence, Detection, ScanContext, ScanObject
from ..deobf import Budget, deobfuscate
from . import register

MAX_SCAN = 2 << 20          # characters of text given to the rule engine per object
MAX_LAYER_TEXT = 512 << 10  # characters taken from each decoded layer
MAX_CHILDREN = 48           # decoded layers handed back per object

# capabilities that make obfuscation actually worth reporting
_ACTIONABLE = frozenset({"exec", "download", "decode", "cred", "exfil", "persist", "evasion",
                         "keychain", "browser", "clipboard"})

_PAD = re.compile(r"(.)\1{256,}", re.S)


@dataclass(frozen=True)
class Rule:
    name: str
    rx: re.Pattern[str]
    score: int = 0
    desc: str = ""
    caps: tuple[str, ...] = ()
    need: tuple[str, ...] = ()   # any-of lowercase substrings required before running rx


def R(name: str, pattern: str, score: int, desc: str, caps: str = "", need: str = "") -> Rule:
    return Rule(name, re.compile(pattern, re.I | re.M), score, desc,
                tuple(c for c in caps.split(",") if c), tuple(n for n in need.split("|") if n))


@dataclass
class Combo:
    name: str
    all_of: tuple[str, ...]
    score: int
    desc: str
    any_of: tuple[str, ...] = ()
    window: int = 600           # required caps must all match within this many characters


def C(name: str, all_of: str, score: int, desc: str, any_of: str = "", window: int = 600) -> Combo:
    return Combo(name, tuple(all_of.split(",")) if all_of else (), score, desc,
                 tuple(any_of.split(",")) if any_of else (), window)


COMBOS = [
    C("DownloadExecute", "download,exec", 35, "Downloads remote content and executes code", window=400),
    C("CredentialExfil", "cred,exfil", 45, "Collects credentials and uploads data", window=2000),
    C("HiddenPersistence", "persist,hidden", 30, "Installs persistence with hidden execution", window=1200),
    C("PersistentDownloader", "persist,download", 25, "Persistence combined with remote download", window=1200),
    C("EvasionAndExecution", "evasion", 20, "Security-control tampering together with code execution",
      "exec,download", window=1200),
]


@dataclass
class Hits:
    caps: set[str] = field(default_factory=set)
    dets: list[tuple[Rule, str]] = field(default_factory=list)
    pos: dict = field(default_factory=dict)     # cap -> sorted list of match offsets

    def add_pos(self, cap: str, offset: int) -> None:
        self.pos.setdefault(cap, []).append(offset)


def scan_text(text: str, rules: list[Rule], hits: Hits | None = None) -> Hits:
    hits = hits or Hits()
    low = text.lower()
    seen = {r.name for r, _ in hits.dets}
    for rule in rules:
        if rule.need and not any(n in low for n in rule.need):
            continue
        m = rule.rx.search(text)
        if not m:
            continue
        hits.caps.update(rule.caps)
        for cap in rule.caps:
            hits.add_pos(cap, m.start())
        if rule.score > 0 and rule.name not in seen:
            seen.add(rule.name)
            hits.dets.append((rule, m.group(0)[:200]))
    return hits


def _near(hits: Hits, caps: tuple[str, ...], window: int) -> bool:
    """True if there is a text window of `window` chars containing a match of every cap in caps."""
    if not caps:
        return True
    lists = [hits.pos.get(c) for c in caps]
    if any(not lst for lst in lists):
        return False
    if len(caps) == 1:
        return True
    import bisect
    anchor = min(lists, key=len)
    for p in anchor:
        lo, hi = p - window, p + window
        if all(bisect.bisect_left(lst, lo) < bisect.bisect_right(lst, hi) for lst in lists):
            return True
    return False


def emit(ctx: ScanContext, obj: ScanObject, prefix: str, hits: Hits, combos: list[Combo] | None = None) -> int:
    total = 0
    for rule, ev in hits.dets:
        conf = Confidence.HIGH if rule.score >= 30 else Confidence.MEDIUM if rule.score >= 15 else Confidence.LOW
        ctx.detect(obj, Detection(f"Heur:{prefix}.{rule.name}", "heuristic", conf, rule.score, rule.desc, [ev]))
        total += rule.score
    for cb in (combos if combos is not None else COMBOS):
        if not _near(hits, cb.all_of, cb.window):
            continue
        if cb.any_of and not any(_near(hits, cb.all_of + (a,), cb.window) for a in cb.any_of):
            continue
        conf = Confidence.HIGH if cb.score >= 30 else Confidence.MEDIUM
        ctx.detect(obj, Detection(f"Heur:{prefix}.{cb.name}", "heuristic", conf, cb.score, cb.desc,
                                  [",".join(sorted(hits.caps))]))
        total += cb.score
    return total


def bounded(text: str) -> str:
    if len(text) > MAX_SCAN:
        text = _PAD.sub(lambda m: m.group(1) * 8, text[: MAX_SCAN * 4])
        if len(text) > MAX_SCAN:
            text = text[: MAX_SCAN - (1 << 20)] + "\n" + text[-(1 << 20):]
    return text


# deobf "ops" that count as real obfuscation evidence (not benign escapes/concat)
_OBF_OPS = ("charcode", "b64inline", "format", "join", "reverse", "replace", "backtick",
            "varsubst", "quotefrag", "backslash", "emptyquote")


def obfuscation_score(res, n_layers: int) -> tuple[int, list[str]]:
    """Obfuscation is only moderately suspicious, and benign code has lots of escapes/concats,
    so we score only heavy character-code / format-string obfuscation or many decoded layers.

    The op count is relative to the amount of code: a multi-megabyte minified bundle reaches
    80 escapes/concats trivially, obfuscated droppers are dense with them."""
    ops = res.ops
    ev = []
    weight = sum(ops.get(k, 0) for k in _OBF_OPS)
    kb = max(1.0, len(getattr(res, "code", "") or "") / 1024)
    density = weight / kb
    score = 0
    if weight >= 80 and density >= 0.5:
        score += 20
        ev.append("heavy character/format obfuscation")
    elif weight >= 30 and density >= 0.25:
        score += 10
        ev.append("character/format obfuscation")
    if n_layers >= 8:
        score += 8
        ev.append(f"{n_layers} decoded layers")
    return min(score, 25), ev


# extension -> language, used only as a fallback hint when content identification returns "text"
EXT_LANG = {
    "ps1": "powershell", "psm1": "powershell", "psd1": "powershell",
    "sh": "shell", "bash": "shell", "zsh": "shell", "ksh": "shell", "command": "shell", "tool": "shell",
    "bat": "batch", "cmd": "batch",
    "vbs": "vbs", "vbe": "vbs", "wsh": "vbs",
    # WSH job files / scriptlets are XML wrappers around <script language="VBScript|JScript">
    # blocks: the HTML path extracts each block and hands it to the right language analyzer
    "wsf": "html", "wsc": "html", "sct": "html",
    "js": "javascript", "jse": "javascript", "mjs": "javascript", "cjs": "javascript", "jsx": "javascript",
    "py": "python", "pyw": "python",
    "php": "php", "php3": "php", "php4": "php", "php5": "php", "phtml": "php",
    "pl": "perl", "pm": "perl", "cgi": "perl",
    "rb": "ruby",
    "applescript": "applescript", "scpt": "applescript",
    "html": "html", "htm": "html", "hta": "html", "svg": "html",
}

# Extensions that decide the language when the content type only came from the weak text
# sniffer in filetype.py (e.g. any "$x = " makes minified JavaScript look like PowerShell,
# a Perl man page or a Python module "javascript"). Shebang/magic-based types are never
# overridden. "" = not a script language at all (no script analyzer applies).
ROUTE_EXT = dict(EXT_LANG, **{
    "ts": "javascript", "tsx": "javascript", "mts": "javascript", "cts": "javascript", "es6": "javascript",
    "css": "", "scss": "", "sass": "", "less": "", "map": "", "json": "",
})

# --------------------------------------------------------------------------- documentation
# Man pages, markdown, POD, ... merely *mention* commands (curl --data, CreateThread, scp
# user@host); running exec-style heuristics on them only produces false positives.
DOC_EXT = frozenset({"md", "markdown", "mdown", "mkd", "mdx", "rst", "adoc", "asciidoc", "texi", "texinfo",
                     "pod", "rdoc", "man", "mdoc", "groff", "roff", "nroff", "troff"})
_MAN_EXT = re.compile(r"^(?:[1-9n][a-z0-9]{0,6}|l)$")          # .1 .3pm .1ssl .8 .n
_TROFF_START = re.compile(rb"^(?:\.\\\"|'\\\"|\.TH\s|\.Dd\s|\.Dt\s|\.so\s|\.de\s|\.ig\b|\.nh\b|\.ds\s|\.TL\b)")
_TROFF_MACRO = re.compile(rb"(?m)^[.'](?:[A-Za-z]{1,3}\b|\\\")")


def is_documentation(obj: ScanObject) -> bool:
    """troff man page / markdown / POD etc. (never a decoded layer or a shebang script)."""
    if obj.kind == "decoded" or obj.meta.get("script_lang"):
        return False
    cached = obj.cache.get("is_doc")
    if cached is not None:
        return cached
    head = obj.data[:16384].lstrip(b"\xef\xbb\xbf \t\r\n")
    res = False
    if head[:2] != b"#!" and obj.ftype not in ("pe", "elf", "macho", "macho_fat"):
        ext = obj.extension
        if ext in DOC_EXT:
            res = True
        else:
            troff_start = bool(_TROFF_START.match(head))
            if troff_start or _MAN_EXT.match(ext):
                n_lines = head.count(b"\n") + 1
                n_macro = len(_TROFF_MACRO.findall(head))
                res = n_macro >= 5 and n_macro >= n_lines * (0.04 if troff_start else 0.08)
    obj.cache["is_doc"] = res
    return res


def routed_lang(obj: ScanObject) -> str | None:
    """Language decided by the file extension when the content sniffer was only guessing.

    Returns None when the normal ftype-based routing applies."""
    if obj.kind == "decoded" or obj.meta.get("script_lang"):
        return None
    if not (obj.fdesc or "").endswith(" text"):    # shebang / magic / anchored markup: authoritative
        return None
    return ROUTE_EXT.get(obj.extension)


# --------------------------------------------------------------------------- layer-based signals
# Obfuscation that the deobfuscator had to *undo* (as opposed to minification): tool-specific
# encodings are rare in legitimate code, executables/shellcode decoded from a literal rarer still.
LAYER_SIGNALS = [
    # (layer-method prefix, detection suffix, score, description)
    ("script-encoder", "ScriptEncoded", 25, "Microsoft Script Encoder (VBE/JSE) encoded script"),
    ("js-string-array", "ObfuscatorStringTable", 15, "javascript-obfuscator (obfuscator.io) string table"),
    ("js-packer", "Packed", 10, "P.A.C.K.E.R.-packed script"),
    ("shellcode", "Shellcode", 45, "Byte array starting with a shellcode prologue"),
]
_EXE_LAYER = frozenset({"pe", "dos", "elf", "macho", "macho_fat", "dex"})
# layer methods that undo an *encoding* (vs. merely extracting an inline/embedded script)
_ENCODING_STEP = re.compile(r"b64|base64|hex|gzip|zlib|deflate|rot13|rev|xor|charcode|bytearray|"
                            r"encodedcommand|script-encoder|packer|string-array|uu|bzip2|lzma|b32|b85|a85")
MULTI_LAYER_MIN = 3


def _encoded_depth(obj: ScanObject) -> int:
    """Number of consecutive encoding layers (decoded children created by the script analyzers)
    from this object up to its first non-decoded ancestor."""
    n = 0
    o = obj
    while o is not None and o.kind == "decoded" and n < 32:
        method = o.meta.get("decoded_by")
        if not method:
            break
        if _ENCODING_STEP.search(method):
            n += 1
        o = o.parent
    return n


def layer_signals(ctx: ScanContext, obj: ScanObject, prefix: str, layers) -> None:
    for lay in layers[:MAX_CHILDREN]:
        method = lay.method or ""
        for start, suffix, score, desc in LAYER_SIGNALS:
            if method.startswith(start):
                ctx.detect(obj, Detection(f"Heur:{prefix}.{suffix}", "heuristic",
                                          Confidence.HIGH if score >= 30 else Confidence.MEDIUM, score, desc,
                                          [lay.source[:120] or method]))
        if lay.kind == "binary" and lay.ftype in _EXE_LAYER:
            ctx.detect(obj, Detection(f"Heur:{prefix}.DecodedExecutable", "heuristic", Confidence.HIGH, 45,
                                      f"Executable ({lay.ftype}) decoded from a script literal",
                                      [f"{method}: {lay.source[:100]}"]))
    depth = _encoded_depth(obj)
    if depth >= MULTI_LAYER_MIN:
        ctx.detect(obj, Detection(f"Heur:{prefix}.MultiLayerEncoding", "heuristic", Confidence.MEDIUM, 20,
                                  f"Payload wrapped in {depth} nested encoding layers",
                                  [str(obj.meta.get("decoded_by", ""))]))


def make_script_analyzer(cls_name: str, an_name: str, ftypes: set[str], lang: str,
                         rules: list, combos=None, order: int = 55, seconds: float = 2.0,
                         exts: set[str] | None = None, head_marker: bytes | None = None,
                         head_exclude: bytes | None = None):
    """Build and return a registered Analyzer subclass driven by a rule table.

    exts:         extensions that route a "text"/"script" object here when content id is generic.
    head_marker:  a byte string in the first 512 bytes forces this analyzer to apply.
    head_exclude: a byte string in the first 512 bytes prevents this analyzer from applying
                  (used so <?php ... eval( isn't handled as JavaScript).
    """
    from ..core import Analyzer

    prefix = an_name.upper()
    _exts = exts or {e for e, lg in EXT_LANG.items() if lg == lang}

    class _ScriptAnalyzer(Analyzer):
        name = an_name

        def applies(self, obj: ScanObject) -> bool:
            if obj.size < 16 or obj.size > 64 << 20:
                return False
            if head_exclude is not None and head_exclude in obj.data[:512]:
                return False
            if head_marker is not None and head_marker in obj.data[:512]:
                return True
            route = routed_lang(obj)
            if route is not None:
                # PHP pages are HTML templates too (phishing / ClickFix kits are served as .php)
                return route == lang or (route == "php" and lang == "html")
            if is_documentation(obj):
                return False
            if obj.ftype in ftypes or obj.meta.get("script_lang") == lang:
                return True
            if obj.ftype in ("text", "script") and obj.extension in _exts:
                return True
            return False

        def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
            text = obj.text(MAX_SCAN * 4)
            if not text.strip():
                return
            res, corpus = deobf_and_feed(ctx, obj, text, lang, seconds)
            hits = scan_text(corpus, GENERIC_RULES)
            hits = scan_text(corpus, rules, hits)
            emit(ctx, obj, prefix, hits, combos)
            ob_score, ob_ev = obfuscation_score(res, len(res.layers))
            # obfuscation is only reported when the (de-obfuscated) code also does something
            # actionable -- minified/legitimately-escaped code trips the ops counters too.
            if ob_score and (hits.caps & _ACTIONABLE):
                ctx.detect(obj, Detection(f"Heur:{prefix}.Obfuscated", "heuristic",
                                          Confidence.MEDIUM if ob_score >= 15 else Confidence.LOW, ob_score,
                                          "Obfuscated code combined with actionable behaviour", ob_ev))
            layer_signals(ctx, obj, prefix, res.layers)

    _ScriptAnalyzer.order = order
    _ScriptAnalyzer.__name__ = cls_name
    _ScriptAnalyzer.__qualname__ = cls_name
    register(_ScriptAnalyzer)
    return _ScriptAnalyzer


# --------------------------------------------------------------------------- generic rules
# Language-independent techniques (URLs, decode+exec primitives) that only tag capabilities.
GENERIC_RULES = [
    # public addresses only: loopback/private/link-local/CGNAT, the RFC 5737 documentation nets,
    # the RFC 2544 benchmark net and multicast/reserved space are excluded
    R("RawIpUrl",
      r"https?://(?!127\.|10\.|0\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|255\.|"
      r"192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|198\.1[89]\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|"
      r"2(?:2[4-9]|[3-5]\d)\.)"
      r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/\S", 5,
      "Download from a bare public IP address", "download", need="http"),
]


def _html_result(text: str, seconds: float):
    """deobfuscate() has no HTML mode: pull <script> blocks (JS/VBScript, incl. WSF/SCT scriptlets),
    inline event handlers / javascript: URLs and data: URIs out with cerber.deobf.html, and
    entity-decode the page so the rules see &#x..; encoded markup in clear."""
    from ..deobf import Result
    from ..deobf import html as _dh
    from ..deobf.generic import ps_encoded_commands

    budget = Budget(seconds=seconds)
    res = Result(code=text, normalized=text)
    try:
        norm = _dh.unescape_entities(text)
        if norm != text:
            res.ops["entities"] += 1
        res.normalized = norm
        layers = _dh.layers_from_html(text, budget)
        if not budget.expired():
            layers += ps_encoded_commands(norm, budget)
        res.layers = layers
    except (RecursionError, MemoryError) as exc:
        res.errors.append(f"deobf[html]: {type(exc).__name__}")
    except Exception as exc:  # noqa: BLE001 - a decoder bug must never kill the analyzer
        res.errors.append(f"deobf[html]: {exc!r}")
    return res


def deobf_and_feed(ctx: ScanContext, obj: ScanObject, text: str, lang: str, seconds: float = 1.5):
    """Run the deobfuscator, hand decoded layers back as children, return (result, corpus).

    De-obfuscation is expensive per byte, so for large objects (usually benign bundles) we
    only de-obfuscate the head with a tighter time budget; obfuscated malware is small.
    """
    n = len(text)
    if n > (4 << 20):
        text, seconds = text[: 256 << 10], min(seconds, 0.6)
    elif n > (1 << 20):
        text, seconds = text[: 1 << 20], min(seconds, 1.0)
    if lang == "html":
        res = _html_result(text, seconds)
    else:
        res = deobfuscate(text, lang, Budget(seconds=seconds))
    obj.errors.extend(res.errors[:4])
    parts = [res.normalized]
    for i, lay in enumerate(res.layers[:MAX_CHILDREN]):
        ext = {"powershell": "ps1", "javascript": "js", "vbs": "vbs", "batch": "bat", "shell": "sh",
               "python": "py", "applescript": "applescript", "php": "php", "html": "html"}.get(lay.lang or "", "bin")
        meta = {"decoded_by": lay.method}
        if lay.lang:
            meta["script_lang"] = lay.lang
        ctx.add_child(obj, lay.data, f"decoded/{i}_{lay.method.replace('>', '_')[:40]}.{ext}", kind="decoded",
                      meta=meta)
        if lay.kind == "text":
            parts.append(lay.data[:MAX_LAYER_TEXT].decode("utf-8", "replace"))
    return res, bounded("\n".join(parts))
