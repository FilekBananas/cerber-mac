"""Compile YARA rule files and measure false positives on a clean corpus.

    python -m cerber.tools.yaracheck rules/custom/macos.yar [--corpus DIR ...] [--max-files N]
    python -m cerber.tools.yaracheck rules/custom/macos.yar --positive tests/samples/yara/macos

Exit code 1 when compilation fails or any rule fires on the clean corpus.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from collections import Counter, defaultdict

import yara

DEFAULT_CORPUS = ["/usr/bin", "/usr/sbin", "/usr/libexec", "/bin", "/sbin", "/System/Applications",
                  "/Applications", "/opt/homebrew/bin", "/opt/homebrew/Cellar", "/opt/homebrew/lib",
                  os.path.join(os.path.dirname(__file__), "..", "..", ".venv", "lib")]
EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}


def iter_files(roots, max_files, max_size=50 << 20):
    n = 0
    for root in roots:
        if os.path.isfile(root):
            yield root
            n += 1
            continue
        for dp, dn, fn in os.walk(root):
            for f in fn:
                p = os.path.join(dp, f)
                try:
                    if os.path.islink(p) or not os.path.isfile(p) or os.path.getsize(p) > max_size:
                        continue
                except OSError:
                    continue
                yield p
                n += 1
                if n >= max_files:
                    return


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rules", nargs="+")
    ap.add_argument("--corpus", action="append")
    ap.add_argument("--positive", action="append", help="dir/file that SHOULD match")
    ap.add_argument("--max-files", type=int, default=60000)
    args = ap.parse_args(argv)

    try:
        rules = yara.compile(filepaths={f"ns{i}": p for i, p in enumerate(args.rules)}, externals=EXTERNALS)
    except yara.Error as exc:
        print(f"COMPILE ERROR: {exc}")
        return 1
    nrules = sum(1 for _ in rules)
    print(f"compiled OK: {nrules} rules")

    rc = 0
    if args.positive:
        hit_rules = Counter()
        for p in iter_files(args.positive, 10**6):
            ms = rules.match(p, externals={"filename": os.path.basename(p), "filepath": p}, timeout=60)
            names = [m.rule for m in ms]
            for n in names:
                hit_rules[n] += 1
            print(f"  positive {p}: {names or 'NO MATCH'}")
        print(f"positive coverage: {len(hit_rules)}/{nrules} rules fired on positive samples")

    corpus = args.corpus or DEFAULT_CORPUS
    t0 = time.time()
    fp = defaultdict(list)
    scanned = 0
    for p in iter_files(corpus, args.max_files):
        try:
            ms = rules.match(p, externals={"filename": os.path.basename(p), "filepath": p}, timeout=30)
        except yara.Error:
            continue
        scanned += 1
        for m in ms:
            fp[m.rule].append(p)
    print(f"clean corpus: {scanned} files in {time.time() - t0:.1f}s")
    if fp:
        rc = 1
        print(f"FALSE POSITIVES in {len(fp)} rules:")
        for r, paths in sorted(fp.items(), key=lambda kv: -len(kv[1])):
            print(f"  {r}: {len(paths)} files, e.g. {paths[:3]}")
    else:
        print("no false positives")
    return rc


if __name__ == "__main__":
    sys.exit(main())
