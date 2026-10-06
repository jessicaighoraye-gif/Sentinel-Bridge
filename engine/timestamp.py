"""
Two kinds of time exist in this project:
  * collected_at: when the evidence was collected. It comes from the input file.
  * detected_at:  when the engine produced a finding. It is ALWAYS created here.
"""
from datetime import datetime, timezone

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utc_now(clock=None):
    """Return the current UTC time as text, for example 2026-10-02T09:30:12Z.

    Tests pass a 'clock' function so the time can be fixed to a known value.
    """
    if clock is None:
        current_time = datetime.now(timezone.utc)
    else:
        current_time = clock()
    current_time = current_time.astimezone(timezone.utc)
    return current_time.strftime(TIMESTAMP_FORMAT)


def parse_timestamp(value):
    """Turn '2026-10-02T09:00:00Z' (or a plain date '2026-10-02') into a datetime."""
    value = value.strip()

    is_plain_date = len(value) == 10
    if is_plain_date:
        parsed = datetime.strptime(value, "%Y-%m-%d")
        return parsed.replace(tzinfo=timezone.utc)

    value_without_z = value.rstrip("Z")
    has_fractional_seconds = "." in value_without_z
    if has_fractional_seconds:
        parsed = datetime.strptime(value_without_z, "%Y-%m-%dT%H:%M:%S.%f")
    else:
        parsed = datetime.strptime(value_without_z, "%Y-%m-%dT%H:%M:%S")
    return parsed.replace(tzinfo=timezone.utc)


def hours_between(later_time, earlier_time):
    """Hours from earlier_time to later_time, as a decimal number."""
    difference = later_time - earlier_time
    return difference.total_seconds() / 3600


def days_between(later_time, earlier_time):
    """Whole days from earlier_time to later_time (partial days are dropped)."""
    difference = later_time - earlier_time
    return difference.days
