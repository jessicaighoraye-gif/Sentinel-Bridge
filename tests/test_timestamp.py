import re
from datetime import datetime, timezone

from engine.timestamp import days_between, hours_between, parse_timestamp, utc_now


def test_utc_now_has_the_expected_format():
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", utc_now())


def test_a_clock_can_be_pinned_for_tests():
    pinned_time = datetime(2026, 10, 2, 9, 30, 12, tzinfo=timezone.utc)

    assert utc_now(lambda: pinned_time) == "2026-10-02T09:30:12Z"


def test_parse_timestamp_accepts_timestamps_and_plain_dates():
    assert parse_timestamp("2026-10-02T09:00:00Z").hour == 9
    assert parse_timestamp("2026-10-02T09:00:00.500Z").microsecond == 500000
    assert parse_timestamp("2026-10-02").day == 2


def test_time_differences():
    later = parse_timestamp("2026-10-02T09:00:00Z")
    earlier = parse_timestamp("2026-09-30T06:00:00Z")

    assert days_between(later, earlier) == 2
    assert hours_between(later, earlier) == 51
