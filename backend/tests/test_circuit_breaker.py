"""Tests for the collector circuit breaker."""
import pytest
from app.collectors.base import _CB_STATES, _cb_allow, _cb_failure, _cb_success, _CB_FAILURE_THRESHOLD


def setup_function():
    _CB_STATES.clear()


def test_initially_closed():
    assert _cb_allow("test_col") is True


def test_opens_after_threshold_failures():
    for _ in range(_CB_FAILURE_THRESHOLD):
        _cb_failure("test_col")
    assert _cb_allow("test_col") is False
    assert _CB_STATES["test_col"]["state"] == "OPEN"


def test_success_resets_to_closed():
    for _ in range(_CB_FAILURE_THRESHOLD):
        _cb_failure("test_col2")
    assert _cb_allow("test_col2") is False
    # Simulate recovery window passed by faking opened_at
    import time
    _CB_STATES["test_col2"]["opened_at"] = time.monotonic() - 9999
    assert _cb_allow("test_col2") is True  # HALF_OPEN
    _cb_success("test_col2")
    assert _CB_STATES["test_col2"]["state"] == "CLOSED"


def test_independent_collectors():
    for _ in range(_CB_FAILURE_THRESHOLD):
        _cb_failure("col_a")
    # col_b should still be fine
    assert _cb_allow("col_b") is True
    assert _cb_allow("col_a") is False
