"""Mark annotatations"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict, Literal

__all__ = ("RelatedSceneDataItem_DICT_T",
           "AnalysisItem_DICT_T",
           "PrivacyEndPoint_DICT_T",
           "EncryptionAlg_DICT_T",
           "EncryptionSpec_DICT_T",
           "Resolution_DICT_T",
           "SceneMark_DICT_T",
           "SceneData_DICT_T",
           "DetectedObject_DICT_T",)

if TYPE_CHECKING:
    from re import RegexFlag
    from typing import List, Optional
    from typing_extensions import Required, NotRequired, ReadOnly

    from numpy import uint16
    from .common       import (SceneDataType_T, NiceItemType_T, SceneMarkStatus_T,
                               AnalysisProcessingStatus_T,  DeviceNodeID,
                               ZuluTimeStamp, MediaFormat_T)
    from .scenemode    import NetworkEndPointSpecifier, ApplicationEndPointSpecifier


class RelatedSceneDataItem_DICT_T(TypedDict):
    VersionNumber: ReadOnly[Required[str]]
    SceneDataID:   ReadOnly[Required[str]]

class DetectedObject_DICT_T(TypedDict):
    NiceItemType:         ReadOnly[Required[NiceItemType_T]]
    CustomItemType:       ReadOnly[NotRequired[str]]
    RelatedSceneDataList: ReadOnly[NotRequired[Optional[List[RelatedSceneDataItem_DICT_T]]]]

class AnalysisItem_DICT_T(TypedDict):
    """AnalysisItem JSON Specification"""
    VersionNumber:       ReadOnly[NotRequired[int]]
    EventType:           ReadOnly[NotRequired[str]]
    SceneMode:           ReadOnly[NotRequired[str]]
    CustomAnalysisID:    ReadOnly[NotRequired[str]]
    AnalysisDescription: ReadOnly[NotRequired[str]]
    ProcessingStatus:    ReadOnly[NotRequired[
        AnalysisProcessingStatus_T
    ]]
    DetectedObjects:     ReadOnly[NotRequired[List[
        DetectedObject_DICT_T
    ]]]

class PrivacyEndPoint_DICT_T(TypedDict):
    """PrivacyEndPoint JSON specification"""
    NetEndPoint: ReadOnly[Required[[NetworkEndPointSpecifier]]]
    AppEndPoint: ReadOnly[Required[ApplicationEndPointSpecifier]]


class EncryptionAlg_DICT_T(TypedDict):
    """Encryption Algorithm JSON Specification"""
    JWEAlg: ReadOnly[Required[str]]
    JWEEnc: ReadOnly[Required[str]]

class EncryptionSpec_DICT_T(TypedDict):
    """Encryption JSON specification"""
    EncryptionOn:           ReadOnly[Required[bool]]
    SceneEncryptionKeyID:   ReadOnly[NotRequired[
        Optional[str]
    ]]
    SceneMarkEncryption:    ReadOnly[NotRequired[Optional[EncryptionAlg_DICT_T]]]

     # TODO the spec says this, but 'this' is probably incorrect
    SceneDataEncryption:    ReadOnly[NotRequired[str]]

    PrivacyServerEndPoint:  ReadOnly[NotRequired[Optional[PrivacyEndPoint_DICT_T]]]

class Resolution_DICT_T(TypedDict):
    "Resolution JSON specification"
    Width: ReadOnly[Required[uint16]]
    Heiht: ReadOnly[Required[uint16]]

class SceneData_DICT_T(TypedDict):
    """SceneData JSON specification"""
    VersionNumber:         ReadOnly[Required[int]]
    SceneDataID:           ReadOnly[Required[str]]
    SourceNodeID:          ReadOnly[Required[str]]
    DataType:              ReadOnly[Required[SceneDataType_T]]
    MediaFormat:           ReadOnly[Required[MediaFormat_T]]
    Status:                ReadOnly[Required[str]]
    
    TimeStamp:             ReadOnly[Required[
        ZuluTimeStamp
    ]]
    SourceNodeDescription: ReadOnly[NotRequired[str]]
    Duration:              ReadOnly[NotRequired[Optional[str]]]
    SceneDataURI:          ReadOnly[NotRequired[str]]
    Resolution:            ReadOnly[NotRequired[Resolution_DICT_T]]
    Required:              ReadOnly[NotRequired[bool]] # Yes, this is in the spec
    Encryption:            ReadOnly[NotRequired[EncryptionSpec_DICT_T]]


class SceneMark_DICT_T(TypedDict):
    Version:         ReadOnly[Required[str]]
    TimeStamp:       ReadOnly[Required[
        ZuluTimeStamp
    ]]
    SceneMarkID:     ReadOnly[Required[str]]
    NodeID:          ReadOnly[Required[
        DeviceNodeID
    ]] # WARNING: DeviceNodeID, not the 'plain' NodeID
    DestinationID:   ReadOnly[Required[str]]
    SceneMarkStatus: ReadOnly[Required[SceneMarkStatus_T]]

    AnalysisList:    ReadOnly[Required[
        List[AnalysisItem_DICT_T]]
    ]
    SceneDataList:   ReadOnly[Required[
        Optional[List[SceneData_DICT_T]]
    ]]

