#!/bin/bash

# The verifier uses only the Python standard library, so there are no test
# dependencies to install here or in the image, and no network is required.
mkdir -p /logs/verifier

python3 - <<'PY'
import importlib.util
import json
import os
import time
import traceback

os.makedirs("/logs/verifier", exist_ok=True)

spec = importlib.util.spec_from_file_location("test_outputs", "/tests/test_outputs.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

test_names = sorted(n for n in dir(module) if n.startswith("test_"))
results = []
passed = 0
for name in test_names:
    start = time.time()
    try:
        getattr(module, name)()
        status = "passed"
        passed += 1
    except Exception:
        status = "failed"
        print(f"----- {name} FAILED -----")
        traceback.print_exc()
    duration_ms = int((time.time() - start) * 1000)
    results.append({"name": name, "status": status, "duration": duration_ms})
    print(f"{status.upper()}: {name}")

failed = len(test_names) - passed
summary = {
    "tests": len(test_names),
    "passed": passed,
    "failed": failed,
    "pending": 0,
    "skipped": 0,
    "other": 0,
    "start": 0,
    "stop": 0,
}
ctrf = {"results": {"tool": {"name": "stdlib-runner"}, "summary": summary, "tests": results}}
with open("/logs/verifier/ctrf.json", "w") as fh:
    json.dump(ctrf, fh)

with open("/logs/verifier/reward.txt", "w") as fh:
    fh.write("1" if failed == 0 else "0")

print(f"\n{passed}/{len(test_names)} checks passed")
raise SystemExit(0 if failed == 0 else 1)
PY
