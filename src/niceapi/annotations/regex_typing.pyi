from __future__ import annotations


from re import Pattern, RegexFlag
from types import NotImplementedType
from typing import (Generic,
                    Union,
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

    def __subclasscheck__(cls: Pattern, subclass: object) -> Union[NotImplementedType, bool]:
        if not hasattr(subclass, "__str__"):
            return NotImplemented
        match_ = cls.match(str(subclass))
        return bool(match_)


class RegEx(Pattern[_RE_co, _RF_co], Generic[_RE_co, _RF_co], metaclass=_RegExMeta):
    ...