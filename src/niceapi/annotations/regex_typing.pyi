from __future__ import annotations


from re import Pattern, RegexFlag
from typing import (Generic,
                    TypeVar,
                    Tuple,
                    overload)

from typing_extensions import LiteralString

__all__ = (
    "RegEx",
    "_RegExMeta",
)

_RE = TypeVar("T", bound=LiteralString)
_RF = TypeVar("F", RegexFlag, int)
_RE_co = TypeVar("_RE_co", covariant=True)
_RF_co = TypeVar("_RF_co", bound=int, covariant=True)


class _RegExMeta(type):
    @overload
    def __getitem__(
        cls,
        pattern: Tuple[_RE, _RF],
    ) -> RegEx[_RE, _RF]: ...


class RegEx(Pattern[_RE_co, _RF_co], Generic[_RE_co, _RF_co], metaclass=_RegExMeta):
    ...