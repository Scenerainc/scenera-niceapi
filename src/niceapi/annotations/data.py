"""Data Section annotations"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict


__all__ = ("DataSection_DICT_T",)

if TYPE_CHECKING:
    from typing import List
    from typing_extensions import Required, NotRequired, ReadOnly

    from .common import MediaFormat_T


class DataSection_DICT_T(TypedDict):
    Version:           ReadOnly[Required[str]]
    DataID:            ReadOnly[Required[str]]
    Section:           ReadOnly[Required[int]]
    LastSection:       ReadOnly[Required[int]]
    SectionBase64:     ReadOnly[Required[str]]
    MediaFormat:       ReadOnly[Required[
        MediaFormat_T
    ]]

    EncryptionOn:      ReadOnly[NotRequired[bool]]
    FileType:          ReadOnly[NotRequired[str]]
    HashMethod:        ReadOnly[NotRequired[str]]
    OriginalFileHash:  ReadOnly[NotRequired[str]]
    RelatedSceneMarks: ReadOnly[NotRequired[
        List[str]
    ]]

