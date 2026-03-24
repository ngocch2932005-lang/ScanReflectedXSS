"""
marker.py — Unique marker generation for XSS reflection probing.

Each marker is a distinctive string injected into parameters to detect
if and where user input is reflected in the response.
"""

import random
import string


def generate_marker(length: int = 7) -> str:
    """
    Generate a unique, recognizable marker string.

    Format: __XSS_<random>__
    Random part: 6–8 lowercase ASCII letters.

    Args:
        length: Length of the random suffix (clamped to 6–8).

    Returns:
        A marker string like '__XSS_abcdefg__'.
    """
    length = max(6, min(8, length))
    suffix = "".join(random.choices(string.ascii_lowercase, k=length))
    return f"__XSS_{suffix}__"


def generate_marker_set(count: int) -> list[str]:
    """
    Generate a set of *distinct* markers.

    Useful when you need one marker per parameter across a batch of
    probes and want to guarantee no accidental collisions.

    Args:
        count: How many unique markers to produce.

    Returns:
        A list of distinct marker strings.
    """
    markers: set[str] = set()
    while len(markers) < count:
        markers.add(generate_marker())
    return list(markers)