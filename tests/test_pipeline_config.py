from __future__ import annotations

from blitz_dfir.pipeline.analyze import _sql_correlation_finding_limit, _sql_correlation_support_event_limit


def test_sql_correlation_defaults_are_scaled_for_dfir_runs(monkeypatch) -> None:
    monkeypatch.delenv("BLITZ_SQL_CORRELATION_FINDING_LIMIT", raising=False)
    monkeypatch.delenv("BLITZ_SQL_CORRELATION_SUPPORT_EVENT_LIMIT", raising=False)

    assert _sql_correlation_finding_limit() == 25_000
    assert _sql_correlation_support_event_limit() == 50_000


def test_sql_correlation_limits_can_be_raised_but_are_bounded(monkeypatch) -> None:
    monkeypatch.setenv("BLITZ_SQL_CORRELATION_FINDING_LIMIT", "999999")
    monkeypatch.setenv("BLITZ_SQL_CORRELATION_SUPPORT_EVENT_LIMIT", "999999")

    assert _sql_correlation_finding_limit() == 100_000
    assert _sql_correlation_support_event_limit() == 250_000
