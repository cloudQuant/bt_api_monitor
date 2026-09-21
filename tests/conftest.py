from __future__ import annotations

import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PACKAGE_ROOT / "src"
REPO_ROOT = PACKAGE_ROOT.parents[1]

for path in (SRC_ROOT, REPO_ROOT):
    text = str(path)
    if text not in sys.path:
        sys.path.insert(0, text)

import bt_api_monitor
import bt_api_monitor.exchange_health
import bt_api_monitor.metrics

# Shim modules to maintain backward compatibility with bt_api_py.monitoring imports
sys.modules["bt_api_py.monitoring"] = bt_api_monitor
sys.modules["bt_api_py.monitoring.exchange_health"] = bt_api_monitor.exchange_health
sys.modules["bt_api_py.monitoring.metrics"] = bt_api_monitor.metrics

try:
    import bt_api_py

    bt_api_py.monitoring = bt_api_monitor
except ImportError:
    pass
