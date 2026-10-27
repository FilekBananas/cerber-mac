"""Recursive scan pipeline: identify -> engines -> analyzers -> children -> finalize."""
from __future__ import annotations

import time
import traceback
from typing import Any, Callable

from .analyzers import load_all
from .core import Analyzer, Limits, ScanContext, ScanObject
from .filetype import identify
from .verdict import compute_verdict


class Engine:
    """Signature/lookup engine. scan() runs on every object in the tree,
    finalize() once per top-level file after the whole tree was processed."""
    name = "engine"

    def scan(self, obj: ScanObject, ctx: ScanContext) -> None:
        pass

    def finalize(self, root: ScanObject, ctx: ScanContext) -> None:
        pass


class Pipeline:
    def __init__(self, engines: list[Engine] | None = None, analyzers: list[Analyzer] | None = None,
                 limits: Limits | None = None, options: dict[str, Any] | None = None,
                 services: Any = None, log: Callable[[str], None] | None = None):
        self.engines = engines or []
        self.analyzers = analyzers if analyzers is not None else load_all()
        self.limits = limits or Limits()
        self.options = options or {}
        self.services = services
        self.log = log
        self.release_threshold = 4 << 20

    def scan_bytes(self, data: bytes, display_path: str, real_path: str | None = None) -> ScanObject:
        root = ScanObject(data=data, display_path=display_path, real_path=real_path)
        ctx = ScanContext(root, self.limits, self.options, self.log, self.services)
        t0 = time.monotonic()
        try:
            self._process(root, ctx)
            for eng in self.engines:
                self._safe(root, f"engine {eng.name}.finalize", eng.finalize, root, ctx)
        finally:
            ctx.cleanup()
        root.meta["scan_seconds"] = round(time.monotonic() - t0, 3)
        root.meta["objects"] = sum(1 for _ in root.iter_tree())
        compute_verdict(root)
        return root

    def scan_file(self, path: str) -> ScanObject:
        with open(path, "rb") as fh:
            data = fh.read(self.limits.max_file_size + 1)
        root_too_big = len(data) > self.limits.max_file_size
        if root_too_big:
            data = data[: self.limits.max_file_size]
        root = self.scan_bytes(data, path, real_path=path)
        if root_too_big:
            root.errors.append(f"file larger than {self.limits.max_file_size} bytes, only the head was scanned")
        return root

    def _process(self, obj: ScanObject, ctx: ScanContext) -> None:
        identify(obj)
        for eng in self.engines:
            self._safe(obj, f"engine {eng.name}", eng.scan, obj, ctx)
        for an in self.analyzers:
            try:
                ok = an.applies(obj)
            except Exception as exc:  # noqa: BLE001
                obj.errors.append(f"{an.name}.applies: {exc!r}")
                ok = False
            if ok:
                self._safe(obj, f"analyzer {an.name}", an.analyze, obj, ctx)
        i = 0
        while i < len(obj.children):  # analyzers of a child never append to obj, but be safe
            child = obj.children[i]
            self._process(child, ctx)
            # big extracted blobs are not needed after their subtree was scanned (AI context
            # only uses textual excerpts), keep memory bounded on huge archives/installers
            if child.size > self.release_threshold and not child.detections:
                child.release()
            i += 1

    def _safe(self, obj: ScanObject, what: str, fn, *args) -> None:
        try:
            fn(*args)
        except MemoryError:
            obj.errors.append(f"{what}: out of memory")
        except Exception as exc:  # noqa: BLE001
            tb = traceback.format_exc(limit=3).strip().splitlines()
            obj.errors.append(f"{what}: {exc!r} @ {tb[-2].strip() if len(tb) > 1 else ''}")
