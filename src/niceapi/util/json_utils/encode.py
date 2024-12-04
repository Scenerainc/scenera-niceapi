from __future__ import annotations

import sys

from typing import (TYPE_CHECKING,
                    Union,
                    cast,
                    Mapping,
                    Iterable,
                    List,
                    Dict,
                    SupportsInt,
                    SupportsIndex,
                    SupportsFloat)

__all__ = ("JSONEncoderDefault",
           "JSONPreEncodeError",)


if TYPE_CHECKING:
    from typing import TypeVar
    from typing_extensions import LiteralString, Optional
    from .base import JSONString

    T = TypeVar("T")
    PlainType = Union[str, int, float, bool, None]
    JSONLike  = Union[LiteralString, PlainType, List["JSONLike"], Dict[str, "JSONLike",]]
    Encodable = Union[JSONLike,
                SupportsIndex,
                SupportsInt,
                SupportsFloat,
                JSONString,
                Mapping[Union[JSONString,
                                SupportsIndex,
                                str,],
                        "Encodable"],
                Iterable["Encodable"]]
    JSONEncodable = Union[
        Dict[Union[str, SupportsIndex], Encodable],
        Mapping[Union[str, SupportsIndex], Encodable],
    ]
else:
    JSONLike = Union[str, int, float, bool, None]
    JSONLike = Union[JSONLike, List[JSONLike], Dict[str, JSONLike]]

class JSONPreEncodeError(TypeError):
    ...

class _recursionlimit:
    def __init__(self, limit) -> None:
        self.limit = limit

    def __enter__(self) -> None:
        self.old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(self.limit)

    def __exit__(self, *args, **kwargs) -> None:
        _ = args, kwargs
        sys.setrecursionlimit(self.old_limit)

def _json_key(key: Union[JSONString,
                         SupportsIndex,
                         str,
                         T]) -> Union[str, T]:
    if isinstance(key, str):
        return key
    if hasattr(key, "__str__"):
        return str(key)
    if hasattr(key, "__index__"):
        return hex(key)
    raise JSONPreEncodeError("Cannot JSON encode object key of type: '%s'" % type(key))

def _rjson(obj: Union[Encodable, T],
           /,
           *,
           type_overflow: bool = False,
    ) -> Union[JSONLike, T]:
    try:
        if obj is None or isinstance(obj, (str, int, float, bool)):
            return obj
        if hasattr(obj, "json"):
            return _rjson(obj.json, type_overflow=type_overflow)
        if isinstance(obj, (SupportsIndex, SupportsInt,)):
            return int(obj)
        if isinstance(obj, SupportsFloat):
            return float(obj)
        if isinstance(obj, (Mapping, Dict, dict)):
            # pylint: disable-next=W0212
            return {
                _json_key(k): _rjson(v, type_overflow=type_overflow)
                for k, v, in obj.items()
            }
        if isinstance(obj, Iterable):
            return [
                _rjson(i, type_overflow=type_overflow) for i in obj
            ]
        if isinstance(obj, JSONString):
            return str(obj)
        raise JSONPreEncodeError("Cannot JSON encode '%r'" % type(obj))
    except JSONPreEncodeError as ex:
        if type_overflow:
            return cast('T', obj)
        raise TypeError(
            ex
        ) from ex


class JSONEncoderDefault:
    if TYPE_CHECKING:
        rlimit:   Optional[int]
        overflow: bool

    __slots__ = ("overflow", "rlimit",)

    def __init__(self, type_overflow: bool = False, *, recursion_limit: Optional[int] = None):
        self.overflow = type_overflow
        self.rlimit   = recursion_limit

    def __call__(
        self,
        obj: Union[Encodable, T],
    ) -> Union[JSONLike, T]:
        if self.rlimit is not None:
            with _recursionlimit(limit=self.rlimit):
                values = _rjson(obj, type_overflow=self.overflow)
            return cast("Union[JSONLike, T]", values)
        values = _rjson(obj, type_overflow=self.overflow)
        return cast("Union[JSONLike, T]", values)