"""Parse native UTC token expiry without discarding fractional seconds."""
from __future__ import annotations

import calendar
from datetime import datetime
import re

UTC_EXPIRY = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z\Z"
)


def expiry_nanoseconds(value):
    """Return an exact native expiry, or None for an invalid wire value."""
    if not isinstance(value, str):
        return None
    match = UTC_EXPIRY.fullmatch(value)
    if match is None:
        return None
    try:
        instant = datetime(*(int(part) for part in match.groups()[:6]))
    except ValueError:
        return None
    fraction = (match.group(7) or "").ljust(9, "0")
    return calendar.timegm(instant.timetuple()) * 1_000_000_000 + int(fraction)
