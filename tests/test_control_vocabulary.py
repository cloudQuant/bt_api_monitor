"""Monitor control actions use the shared kill-switch vocabulary (iteration 64).

Evidence level: UNIT.
"""

from __future__ import annotations

from enum import Enum

import pytest
from bt_api_base.risk_service_protocol import KILL_SWITCH_ACTIONS

from bt_api_monitor.control import ControlAction, _require_kill_switch_vocabulary


def test_action_names_are_the_base_vocabulary_and_stored_values_are_unchanged() -> None:
    assert frozenset(ControlAction.__members__) == KILL_SWITCH_ACTIONS
    # Persisted ledger values are the historical lower-case strings.
    assert {action.value for action in ControlAction} == {
        "freeze",
        "stop_new",
        "drain",
        "resume",
    }


def test_divergent_action_sets_refuse() -> None:
    class Missing(str, Enum):
        FREEZE = "freeze"
        STOP_NEW = "stop_new"
        RESUME = "resume"

    class Renamed(str, Enum):
        FREEZE = "freeze"
        STOP_NEW = "stop_new"
        DRAIN = "drain_all"
        RESUME = "resume"

    with pytest.raises(RuntimeError, match="vocabulary"):
        _require_kill_switch_vocabulary(Missing, KILL_SWITCH_ACTIONS)
    with pytest.raises(RuntimeError, match="persisted form"):
        _require_kill_switch_vocabulary(Renamed, KILL_SWITCH_ACTIONS)
    with pytest.raises(RuntimeError, match="vocabulary"):
        _require_kill_switch_vocabulary(ControlAction, frozenset(KILL_SWITCH_ACTIONS | {"PAUSE"}))
    _require_kill_switch_vocabulary(ControlAction, KILL_SWITCH_ACTIONS)
