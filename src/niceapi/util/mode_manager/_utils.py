from __future__ import annotations

import re
from os import getenv
from typing import TYPE_CHECKING

__all__ = (
    "boolenv",
    "intenv",
)

if TYPE_CHECKING:
    from typing import Optional, Sequence, TypeVar

    T = TypeVar("T", int, None)


def boolenv(key: str, truth: Optional[Sequence[str]] = None) -> bool:
    """Get an environment variable as a boolean,
    i.e.:
    >>> import os
    >>> from ... import boolenv
    >>> os.environ['DEBUG'] = "1"
    >>> boolenv('DEBUG')
    True"""
    truth = (
        truth
        and tuple(truth)
        or (
            "true",
            "yes",
            "y",
            "1",
        )
    )
    return getenv(key, "-unset-").lower() in truth


_bases = {
    re.compile(r"^0b[01]+$", re.IGNORECASE): 2,
    re.compile(r"^0o[0-7]+$", re.IGNORECASE): 8,
    re.compile(r"^0x[0-9a-f]+$", re.IGNORECASE): 16,
}


def intenv(key: str, default: T = None) -> T:
    """Load an environment variable as an integer

    Example:
    >>> os.environ["DEVICE_NODE_COUNT"] = (
    ...     # Any of the following will work
    ...     "10"        # without prefix is decimal
    ...     or "0xa"    # for Hexadecimal
    ...     or "0o12"   # Octal
    ...     or "0b1010" # Binary
    ... )
    >>> intenv("DEVICE_NODE_COUNT")
    15
    """
    value = getenv(key, None)
    if value is None:
        return default
    for pattern, base in _bases.items():
        if pattern.match(value):
            return int(value, base)
    return int(value)
