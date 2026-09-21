"""Deprecated compatibility import for :mod:`bt_api_monitor`.

New code must import ``bt_api_monitor``.  This shim preserves the former
top-level import and its public submodules for one migration window.
"""

from __future__ import annotations

import sys
import warnings

import bt_api_monitor as _canonical

warnings.warn(
    "bt_api_monitoring has been renamed to bt_api_monitor; update your imports.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = _canonical.__all__
globals().update({name: getattr(_canonical, name) for name in __all__})

for _submodule in (
    "collector",
    "decorators",
    "elk",
    "exchange_health",
    "grafana",
    "metrics",
    "prometheus",
    "system_metrics",
):
    sys.modules[f"{__name__}.{_submodule}"] = sys.modules[f"bt_api_monitor.{_submodule}"]
