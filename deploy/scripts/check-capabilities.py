"""Print evidence; exit nonzero unless an exact-host runtime receipt is current."""

import argparse
import importlib.util
import json
from pathlib import Path

path = Path(__file__).resolve().parents[2] / "helpers/sovereign.py"
spec = importlib.util.spec_from_file_location("sam_sovereign_capabilities", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
parser = argparse.ArgumentParser()
parser.add_argument("--receipt")
parser.add_argument("--binary-dir", default="/opt/sam")
args = parser.parse_args()
report = (
    module.certified_probe(args.receipt, args.binary_dir) if args.receipt else module.probe_local()
)
print(json.dumps(report, sort_keys=True))
raise SystemExit(0 if report["supported"] else 1)
