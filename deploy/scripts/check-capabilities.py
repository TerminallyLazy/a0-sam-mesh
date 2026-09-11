"""Print local capability evidence; exit nonzero until the release gate passes."""

import importlib.util
import json
from pathlib import Path

path = Path(__file__).resolve().parents[2] / "helpers/sovereign.py"
spec = importlib.util.spec_from_file_location("sam_sovereign_capabilities", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
report = module.probe_local()
print(json.dumps(report, sort_keys=True))
raise SystemExit(0 if report["supported"] else 1)
