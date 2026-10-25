#!/usr/bin/env python3
"""Helpers for Ghidra exports.

  normalize_export.py --strip-path FILE.json   replace binary.path with the file name
  normalize_export.py A B                      exit 0 if exports A and B are equivalent
                                               (ignores binary.path and list order;
                                               .json or .json.gz)
"""
import gzip
import json
import os
import sys


def read(p):
    opener = gzip.open if p.endswith(".gz") else open
    with opener(p, "rt") as f:
        return json.load(f)


def canon(d):
    d["binary"]["path"] = ""
    for v in d.values():
        if isinstance(v, list):
            v.sort(key=lambda x: json.dumps(x, sort_keys=True))
    return d


if sys.argv[1] == "--strip-path":
    p = sys.argv[2]
    d = read(p)
    d["binary"]["path"] = os.path.basename(p).removesuffix(".gz").removesuffix(".json")
    with open(p, "w") as f:
        json.dump(d, f, indent=1)
    sys.exit(0)

sys.exit(0 if canon(read(sys.argv[1])) == canon(read(sys.argv[2])) else 1)
