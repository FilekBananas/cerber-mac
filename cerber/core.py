"""Core data model shared by every engine and analyzer.

Contract for analyzers (see cerber/analyzers/__init__.py):

    class MyAnalyzer(Analyzer):
        name = "office"
        def applies(self, obj: ScanObject) -> bool: ...
        def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
            ctx.detect(obj, Detection(...))          # report a finding
            ctx.add_child(obj, data, "vba/Module1")    # feed extracted content back
            obj.meta["office"] = {...}                 # info for the report

Children are scanned recursively by every engine (hash, ClamAV, YARA,
heuristics), so an analyzer that decodes/extracts something should always
hand the result back through ctx.add_child instead of scanning it itself.
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable


class Confidence(IntEnum):
    INFO = 0      # informational, never changes the verdict alone
    LOW = 1       # weak heuristic
    MEDIUM = 2    # heuristic that rarely fires on clean files
    HIGH = 3      # strong heuristic / generic signature
    CERTAIN = 4   # exact signature match (hash, ClamAV, family YARA rule)


class Verdict(IntEnum):
    CLEAN = 0
    INFO = 1
    SUSPICIOUS = 2
    PUA = 3        # adware / potentially unwanted / hacktool
    MALICIOUS = 4


@dataclass
class Detection:
    name: str                       # e.g. "ClamAV:Win.Trojan.Agent-1234" or "Heur:PE.Injection"
    engine: str                     # hash | clamav | yara | heuristic | fuzzy | ioc | macos | env
    confidence: Confidence
    score: int = 0                  # contribution to the heuristic score (0-100)
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    offset: int | None = None
    pua: bool = False               # adware/riskware/hacktool rather than malware

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "engine": self.engine,
            "confidence": self.confidence.name,
            "score": self.score,
            "description": self.description,
            "evidence": self.evidence[:20],
            "offset": self.offset,
            "pua": self.pua,
        }


@dataclass
class ScanObject:
    """One blob of content: a file on disk, an archive member, a decoded script, a VBA module..."""
    data: bytes
    display_path: str               # "/x/a.zip>>docs/b.docm>>vba/Module1"
    depth: int = 0
    real_path: str | None = None    # only for top-level objects on disk
    parent: "ScanObject | None" = None
    kind: str = "file"              # file | member | decoded | stream | slice | normalized
    ftype: str = "unknown"          # filled by cerber.filetype.identify
    fdesc: str = ""
    meta: dict[str, Any] = field(default_factory=dict)
    detections: list[Detection] = field(default_factory=list)
    children: list["ScanObject"] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    _hashes: dict[str, str] = field(default_factory=dict, repr=False)
    cache: dict[str, Any] = field(default_factory=dict, repr=False)   # parsed structures, never reported

    @property
    def size(self) -> int:
        return self.meta.get("_size", len(self.data))

    def release(self) -> None:
        """Drop the content of a fully processed child (hashes are kept)."""
        if self.data:
            for algo in ("md5", "sha1", "sha256"):
                self.hash(algo)
            self.meta["_size"] = len(self.data)
            self.data = b""

    @property
    def name(self) -> str:
        tail = self.display_path.rsplit(">>", 1)[-1]
        return tail.rsplit("/", 1)[-1]

    @property
    def extension(self) -> str:
        n = self.name.lower()
        return n.rsplit(".", 1)[-1] if "." in n else ""

    def hash(self, algo: str) -> str:
        h = self._hashes.get(algo)
        if h is None:
            h = hashlib.new(algo, self.data).hexdigest()
            self._hashes[algo] = h
        return h

    @property
    def md5(self) -> str:
        return self.hash("md5")

    @property
    def sha1(self) -> str:
        return self.hash("sha1")

    @property
    def sha256(self) -> str:
        return self.hash("sha256")

    def root(self) -> "ScanObject":
        o = self
        while o.parent is not None:
            o = o.parent
        return o

    def ancestors(self):
        o = self.parent
        while o is not None:
            yield o
            o = o.parent

    def iter_tree(self):
        yield self
        for c in self.children:
            yield from c.iter_tree()

    def text(self, limit: int | None = None) -> str:
        """Best-effort text view (UTF-16 aware) for script analyzers."""
        d = self.data if limit is None else self.data[:limit]
        if d[:2] in (b"\xff\xfe", b"\xfe\xff"):
            try:
                return d.decode("utf-16", "replace")
            except Exception:
                pass
        if d[:3] == b"\xef\xbb\xbf":
            d = d[3:]
        return d.decode("utf-8", "replace")


class Analyzer:
    """Base class for heuristic/format analyzers."""
    name = "base"
    # analyzers run in ascending order; extractors (unpackers) use low numbers
    order = 50

    def applies(self, obj: ScanObject) -> bool:  # pragma: no cover - interface
        return True

    def analyze(self, obj: ScanObject, ctx: "ScanContext") -> None:  # pragma: no cover
        raise NotImplementedError


@dataclass
class Limits:
    max_depth: int = 12                 # archive / decode recursion depth
    max_file_size: int = 1024 << 20     # top-level files larger than this are only hashed
    max_child_size: int = 512 << 20     # a single extracted member
    max_total_extracted: int = 4 << 30  # per top-level file (zip-bomb guard)
    max_children: int = 50_000          # per top-level file
    max_ratio: int = 250                # compression ratio guard for a single member


class ScanContext:
    """Per-top-level-file context handed to analyzers."""

    def __init__(self, root: ScanObject, limits: Limits, options: dict[str, Any] | None = None,
                 log: Callable[[str], None] | None = None, services: Any = None):
        self.root = root
        self.limits = limits
        # options: deep (bool), paranoid (bool), macos (bool: run codesign/spctl/xattr checks),
        #          tools (dict: name -> path of optional CLI tools: upx, 7zz, hdiutil)
        self.options = options or {}
        # services: optional shared lookups, e.g. services.ioc (IOC database), may be None
        self.services = services
        self.total_extracted = 0
        self.child_count = 0
        self._log = log
        self._seen: set[str] = {root.sha256}
        self._tempdir: str | None = None

    @property
    def deep(self) -> bool:
        return bool(self.options.get("deep", True))

    def tool(self, name: str) -> str | None:
        return (self.options.get("tools") or {}).get(name)

    def tempdir(self) -> str:
        """Private scratch directory for CLI-based extractors, removed after the scan."""
        if self._tempdir is None:
            import tempfile
            self._tempdir = tempfile.mkdtemp(prefix="cerber-")
        return self._tempdir

    def cleanup(self) -> None:
        if self._tempdir:
            import shutil
            shutil.rmtree(self._tempdir, ignore_errors=True)
            self._tempdir = None

    def log(self, msg: str) -> None:
        if self._log:
            self._log(msg)

    def detect(self, obj: ScanObject, det: Detection) -> None:
        for d in obj.detections:
            if d.name == det.name and d.engine == det.engine:
                # keep the stronger/larger evidence set, don't duplicate names
                if det.evidence:
                    d.evidence.extend(e for e in det.evidence if e not in d.evidence)
                return
        obj.detections.append(det)

    def add_child(self, parent: ScanObject, data: bytes, name: str, kind: str = "member",
                  meta: dict[str, Any] | None = None) -> ScanObject | None:
        """Register extracted/decoded content for recursive scanning.

        Returns None when a limit is hit or the content is a duplicate of
        something already scanned in this tree.
        """
        if not data:
            return None
        if parent.depth + 1 > self.limits.max_depth:
            parent.errors.append(f"max depth reached, not scanning {name}")
            return None
        if len(data) > self.limits.max_child_size:
            parent.errors.append(f"child {name} too large ({len(data)} bytes), truncated")
            data = data[: self.limits.max_child_size]
        if self.child_count >= self.limits.max_children:
            parent.errors.append("max children reached")
            return None
        if self.total_extracted + len(data) > self.limits.max_total_extracted:
            self.detect(self.root, Detection(
                "Heur:Archive.Bomb", "heuristic", Confidence.MEDIUM, 40,
                "Extraction exceeded the total size limit (possible decompression bomb)"))
            return None
        digest = hashlib.sha256(data).hexdigest()
        if digest in self._seen:
            return None
        self._seen.add(digest)
        self.child_count += 1
        self.total_extracted += len(data)
        child = ScanObject(data=data, display_path=f"{parent.display_path}>>{name}",
                           depth=parent.depth + 1, parent=parent, kind=kind, meta=dict(meta or {}))
        child._hashes["sha256"] = digest
        parent.children.append(child)
        return child


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:  # fast enough for windows; use entropy_fast for big buffers
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def entropy_fast(data: bytes) -> float:
    """Entropy via bytes.count – orders of magnitude faster than a Python loop."""
    n = len(data)
    if not n:
        return 0.0
    ent = 0.0
    for b in range(256):
        c = data.count(b.to_bytes(1, "little"))
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent
