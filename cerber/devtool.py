"""Developer tool: run the analyzer pipeline (no signature databases) on files.

    python -m cerber.devtool FILE [FILE...] [--only office,pdf] [--tree] [--json]

Prints the object tree with detections so analyzer authors can test quickly.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys

from .analyzers import load_all
from .core import ScanObject
from .pipeline import Pipeline


def default_tools() -> dict[str, str]:
    tools = {}
    for name, candidates in {"upx": ["upx"], "7z": ["7zz", "7z"], "hdiutil": ["hdiutil"],
                             "codesign": ["codesign"], "spctl": ["spctl"], "xattr": ["xattr"]}.items():
        for c in candidates:
            p = shutil.which(c)
            if p:
                tools[name] = p
                break
    return tools


def print_tree(obj: ScanObject, indent: int = 0, show_all: bool = True) -> None:
    pad = "  " * indent
    flag = "!" if obj.detections else " "
    if show_all or obj.detections or any(c.detections for c in obj.iter_tree()):
        print(f"{pad}{flag} [{obj.ftype}] {obj.display_path.rsplit('>>', 1)[-1]} ({obj.size} B, {obj.kind})")
        for d in obj.detections:
            print(f"{pad}    -> {d.name} [{d.engine}/{d.confidence.name}/+{d.score}] {d.description}")
            for e in d.evidence[:5]:
                print(f"{pad}         · {e[:160]!r}")
        for e in obj.errors:
            print(f"{pad}    !! {e}")
    for c in obj.children:
        print_tree(c, indent + 1, show_all)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--only", help="comma separated analyzer names")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--quiet-tree", action="store_true", help="only print branches with detections")
    args = ap.parse_args(argv)
    analyzers = load_all()
    if args.only:
        keep = set(args.only.split(","))
        analyzers = [a for a in analyzers if a.name in keep]
    pipe = Pipeline(analyzers=analyzers, options={"deep": True, "macos": True, "tools": default_tools()})
    for f in args.files:
        root = pipe.scan_file(f)
        if args.json:
            print(json.dumps({"file": f, "verdict": root.meta["verdict"].name, "score": root.meta["score"],
                              "detections": [d.to_dict() for o in root.iter_tree() for d in o.detections]},
                             indent=1))
        else:
            print(f"== {f}: {root.meta['verdict'].name} score={root.meta['score']} "
                  f"objects={root.meta['objects']} {root.meta['scan_seconds']}s")
            print_tree(root, 1, not args.quiet_tree)
    return 0


if __name__ == "__main__":
    sys.exit(main())
