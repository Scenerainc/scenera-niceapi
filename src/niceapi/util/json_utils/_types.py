from typing import TYPE_CHECKING, List, Dict, SupportsIndex, Union, Mapping, SupportsFloat, SupportsInt, Iterable

__all__ = ("JSONLike", "JSONEncodable",)

if TYPE_CHECKING:
    from typing import TypeVar


    T = TypeVar("T")
    PlainType = Union[str, int, float, bool, None]
    JSONLike  = Union[ PlainType, List["JSONLike"], Dict[str, "JSONLike",]]
    Encodable = Union[JSONLike,
                SupportsIndex,
                SupportsInt,
                SupportsFloat,
                Mapping[Union[SupportsIndex,
                              str,],
                        "Encodable"],
                Iterable["Encodable"]]
    JSONEncodable = Union[
        Dict[Union[str, SupportsIndex], Encodable],
        Mapping[Union[str, SupportsIndex], Encodable],
    ]
else:
    JSONEncodable = Union[
        Dict[Union[str, SupportsIndex], "Encodable"],
        Mapping[Union[str, SupportsIndex], "Encodable"],
    ]
    JSONLike = Union[str, int, float, bool, None]
    JSONLike = Union[JSONLike, List[JSONLike], Dict[str, JSONLike]]
