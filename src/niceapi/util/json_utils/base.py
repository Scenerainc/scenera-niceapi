"""Mapping base objects"""

from __future__ import annotations

from abc    import (ABC,
                    abstractmethod,)
from typing import (TYPE_CHECKING,
                    TypeVar,
                    cast,)

from collections.abc import Mapping

__all__ = ("JSONMapping",)

if TYPE_CHECKING:
    from typing import Iterator, Dict, Any

VT = TypeVar("VT",)

class JSONMapping(ABC, Mapping[str, VT]):
    """Mapping base for objects supporting the .json attribute
    This allows one to use the object itself as the dictionary.
    
    It deliberately does not support __setitem__ and __delitem__,
    to modify the underlying dictionary, obtain the dictionary
    through the .json attribute if you truely must

    It's main functionality reflects an immutable dictionary
    
    Example:
        ```python
        >>> from niceapi.json_utils import JSONMapping
        >>>
        >>> class Example(JSONMapping[int],):
        ...     @property
        ...     def json(self) -> Dict[str, int]:
        ...         return self._data_attr
        ...     def __init__(self, __data: Dict[str, int], /):
        ...         self._data_attr = __data
        ...
        >>> example = Example({"one": 1, "two": 2})
        >>> print(
        ...     dict(mapping) == mapping.json
        ... )
        True
        >>> print(mapping['one'])
        1
        ```
    """

    def __len__(self) -> int:
        """Returns the 'length' of 'dictionary keys'"""
        return len(self.json)

    def __iter__(self) -> Iterator[str]:
        """returns an iterable of the underlying dictionary keys"""
        return iter(self.json.keys())

    def __missing__(self, key: str) -> VT:
        """Optional method, may return a default value to
        become similar to a 'defaultdict'"""
        _ = key
        return NotImplemented

    def __getitem__(self, key: str) -> VT:
        """getitem method (i.e. mapping['name'])"""
        value = self.json.get(key,
                              NotImplemented)
        if value is NotImplemented:
            value = self.__missing__(key)
        if value is NotImplemented:
            raise KeyError(key)
        return cast("VT", value)

    @property
    @abstractmethod
    def json(self) -> ...:
        """Get the object's underlying dictionary"""
