#!/usr/bin/env python3
"""Prepare empty native knowledge directories without modifying upstream code."""

import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("source", type=Path)
args = parser.parse_args()
if not all((args.source / name).is_file() for name in ("agent.py", "run_ui.py")):
    parser.error("extract the verified upstream Agent Zero source first")
for area in ("main", "fragments", "solutions"):
    (args.source / "knowledge" / area).mkdir(parents=True, exist_ok=True)
print("Native knowledge directories ready for read-only source mount")
