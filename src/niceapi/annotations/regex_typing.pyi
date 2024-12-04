from __future__ import annotations

from re import Match
from types import NotImplementedType
from typing import (Generic,
                    Optional,
                    Union,
                    TypeVar,
                    Tuple,)

from typing_extensions import LiteralString

__all__ = (
    "RegEx",
    "_RegExMeta",
)

T = TypeVar("T", bound=str)

_T_co = TypeVar("_T_co", bound=LiteralString, covariant=True)

class _RegExMeta(type):
    def __getitem__(
        cls,
        pattern: Tuple[_T_co],
    ) -> RegEx[_T_co]: ...

    def __subclasscheck__(cls, subclass: object) -> Union[NotImplementedType, bool]:
        if not hasattr(subclass, "__str__"):
            return NotImplemented
        match_ = cls.match(str(subclass)) # type: ignore
        return bool(match_)


class RegEx(Generic[_T_co], metaclass=_RegExMeta):
    def match(self, *match_args, **match_kwarch) -> Optional[Match[_T_co]]:
        ...