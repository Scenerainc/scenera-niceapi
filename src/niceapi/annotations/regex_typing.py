from __future__ import annotations

import re
import sys
from typing import TYPE_CHECKING, Protocol, TypeVar, overload

__all__ = (
    "RegEx",
    "_RegExMeta",
)

if TYPE_CHECKING:
    from typing import Literal, Optional

    from typing_extensions import Match, Pattern

    IGNORECASE = Literal[re.IGNORECASE]
    NOFLAG = Literal[0]

_T_expression = TypeVar("_T_expression", covariant=True)
_T_flags = TypeVar("_T_example", covariant=True)


class _RegExMeta(type):
    """RegEx Type MetaClass, can be matched against"""

    def __getitem__(
        cls,
        pattern: _T_expression,
        flags: Optional[re.RegexFlag[_T_flags]] = None,
    ) -> Pattern[_T_expression]:
        return re.compile(pattern, flags or 0)


class RegEx(Protocol[_T_expression, _T_flags], metaclass=_RegExMeta):
    def __init__(self):
        # pylint: disable=C0209
        raise SyntaxError(
            "Cannot create an instance of RegEx, please use square brackets instead \
                          i.e. '%s' -> 'RegEx[...]'"
            % "".join("%s\u0336" % i for i in "RegEx(...)")
        )
        # pylint: enable=C0209

    @overload
    def match(
        self, string: str, pos=0, endpos=sys.maxsize
    ) -> Optional[Match[_T_expression]]:
        ...
