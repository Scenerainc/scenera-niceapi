from __future__ import annotations

import re
from typing import TYPE_CHECKING

__all__ = (
    "RegEx",
    "_RegExMeta",
)

if TYPE_CHECKING:
    from types  import NotImplementedType
    from typing import Union
    from typing_extensions import Pattern

class _RegExMeta(type):
    """RegEx Type MetaClass, can be matched against"""
    def __getitem__(
        cls,
        pattern: Pattern,
    ) -> Pattern:
        """Compile a regular expression pattern.

        Args:
            args (Union[Pattern, Tuple[Pattern[T], int]]): 
                A pattern to compile or a tuple containing a pattern 
                and flags. If a tuple is provided, the first element 
                should be a regex pattern and the second an integer 
                representing flags for the regex compilation.

        Returns:
            Pattern[T]: A compiled regular expression pattern.

        Example:
            >>> regex = RegEx[r"\d+"]
            >>> compiled = regex
            >>> compiled.match("123")
            <re.Match object; span=(0, 3), match='123'>

            >>> regex_with_flags = RegEx[(r"\d+", re.IGNORECASE)]
            >>> compiled_with_flags = regex_with_flags
            >>> compiled_with_flags.match("ABC123")
            <re.Match object; span=(3, 6), match='123'>
        """
        return re.compile(pattern)

    def __subclasscheck__(cls, subclass: object) -> Union[NotImplementedType, bool]:
        if not hasattr(subclass, "__str__"):
            return NotImplemented
        return bool(cls.match(subclass)) # type: ignore

class RegEx(metaclass=_RegExMeta):
    """A class for functional and passive regex typing.

    This class cannot be instantiated directly. Instead, 
    use square brackets to define your regex patterns.

    Example:
        >>> regex = RegEx[r"^\w+@\w+\.\w+$"]
        >>> regex.match("test@example.com")
        <re.Match object; span=(0, 16), match='test@example.com'>

        >>> invalid_instance = RegEx()  # Raises TypeError
        TypeError: Cannot create an instance of RegEx, please use square brackets instead
    """
    def __init__(self):
        """Cannot be initialized, please use square brackets instead."""
        raise TypeError(
            "Cannot create an instance of RegEx, please use square brackets instead"
        )
