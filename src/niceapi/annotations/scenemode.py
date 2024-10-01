from __future__ import annotations

import re
from typing import TYPE_CHECKING, TypedDict

# type: ignore


__all__ = ("SceneMode",)

if TYPE_CHECKING:
    import sys
    from typing import List, Literal, Optional, Protocol, TypeVar, Union

    from typing_extensions import (
        LiteralString,
        Match,
        NotRequired,
        Pattern,
        ReadOnly,
        Required,
        TypeAlias,
    )

    from .regex_typing import RegEx

    T = TypeVar("T")

    RegExpr: TypeAlias = Literal

    class Example(Protocol[T]):
        ...

    IGNORECASE = Literal[re.IGNORECASE]
    NOFLAG = Literal[0]

    NodeIDRegex = RegEx[Literal[r"^[0-9a-f]{4}$"], IGNORECASE] = re.compile(
        "", re.IGNORECASE
    )


class WebAPIScheme(TypedDict, total=False):
    Protocol: ReadOnly[
        Required[
            Literal[
                "MQTT",
                "WebAPI",
                "WebRTC",
                "Local",
            ]
        ]
    ]
    Authority: ReadOnly[Required[str]]
    AccessToken: ReadOnly[NotRequired[str]]
    Role: ReadOnly[NotRequired[Literal["Server", "Client"]]]


class NetworkEndPointSpecifier(TypedDict, total=False):
    APIVersion: ReadOnly[
        Required[
            # TODO find example to determine if regexable and what pattern
            Literal["1.0"]
        ]
    ]

    EndPointID: ReadOnly[
        Required[
            # TODO find example to determine if regexable and what pattern
            Union[
                RegEx[
                    RegExpr[
                        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
                    ],
                    IGNORECASE,
                ],
                Example[Literal["00000001-0001-0001-0001-000000000001"]],
            ]
        ]
    ]

    NodeID: ReadOnly[
        NotRequired[
            # Idk what kind of node id this is, device+node or hex node id?
            Union[
                RegEx[RegExpr[r"^[0-9a-f]{4}$"], IGNORECASE],
                Example[Literal["0001", "ffff", "FFFF"]],
            ]
        ]
    ]
    PortID: ReadOnly[
        NotRequired[
            Union[
                RegEx[RegExpr[r"^[0-9a-f]{4}$"], IGNORECASE],
                Example[Literal["0001", "ffff", "FFFF"]],
            ]
        ]
    ]
    Scheme: ReadOnly[NotRequired[List[WebAPIScheme]]]


class SceneModeInput(TypedDict, total=False):
    SceneMarkInputEndPoint: ReadOnly[NotRequired[NetworkEndPointSpecifier]]
    ImmediateProcessing: ReadOnly[NotRequired[bool]]


class SceneModeOutput(TypedDict, total=False):
    PortID: ReadOnly[
        Required[
            Union[
                RegEx[RegExpr[r"^[0-9a-f]{4}$"], Literal[0]],
                Example[Literal["0001", "ffff", "FFFF"]],
            ]
        ]
    ]
    Type: ReadOnly[
        Required[
            Literal[
                "Video",
                "Thermometer" "Humidity",
                "CarbonMonoxide",
                "PIR",
                "Audio",
                "Image",
            ]
        ]
    ]
    DestinationEndPointList: ReadOnly[
        NotRequired[List[NetworkEndPointSpecifier]]
    ]


class Transducer(TypedDict, total=False):
    """This seems incomplete on the datapipeline?"""

    Type: Literal["Speaker", "Microphone", "ImageSensor"]
    TransducerID: LiteralString


class Region(TypedDict, total=True):
    XCoord: ReadOnly[Required[float]]
    YCoord: ReadOnly[Required[float]]


class ROICoord(TypedDict, total=False):
    Severity: ReadOnly[
        Required[
            Literal[
                "None",
                "Warning",
                "Critical",
            ]
        ]
    ]
    Coords: ReadOnly[NotRequired[List[Region]]]


class AnalysisRegion(TypedDict, total=False):
    ROITypeEnum: ReadOnly[
        NotRequired[
            Literal[
                "SingleLine",
                "MultiLine",
                "SinglePolygon",
                "MultiPolygon",
            ]
        ]
    ]
    ROICoords: ReadOnly[NotRequired[List[ROICoord]]]


class IgnoreObjectDetection(TypedDict, total=False):
    ObjectLargerThan: ReadOnly[Required[float]]
    ObjectSmallerThan: ReadOnly[Required[float]]


class SceneMarkEncryption(TypedDict, total=False):
    # TODO find out specifics
    JWEAlg: ReadOnly[NotRequired[str]]
    JWEEnc: ReadOnly[NotRequired[str]]


class ApplicationEndPointSpecifier(TypedDict, total=False):
    APIVersion: ReadOnly[
        Required[
            # TODO find reference/regex
            str
        ]
    ]
    EndPointID: ReadOnly[Required[str]]
    X509Certificate: ReadOnly[Required[List[str]]]
    AccessToken: ReadOnly[Required[List[str]]]


class PrivacyServerEndPoint(TypedDict, total=False):
    AppEndPoint: ReadOnly[NotRequired[ApplicationEndPointSpecifier]]
    NetEndPoint: ReadOnly[Required[NetworkEndPointSpecifier]]


class Encryption(TypedDict, total=False):
    EncryptionOn: ReadOnly[Required[bool]]
    SceneEncryptionKeyID: ReadOnly[NotRequired[str]]
    SceneMarkEncryption: ReadOnly[NotRequired[SceneMarkEncryption]]
    SceneDataEncryption: ReadOnly[NotRequired[str]]
    PrivacyServerEndPoint: ReadOnly[NotRequired[PrivacyServerEndPoint]]


class Scheduling(TypedDict, total=False):
    SchedulingType: ReadOnly[
        Required[
            Literal[
                "Default",
                "ScheduledOnce",
                "ScheduledHourly",
                "ScheduledDaily",
                "ScheduledWeekDay",
                "ScheduledWeekEnd",
                "ScheduledWeekly",
                "ScheduledMonthly",
                "ScheduledAnnually",
                "Sunday",
                "Monday",
                "Tuesday",
                "Wednesday",
                "Thursday",
                "Friday",
                "Saturday",
                "Holiday",
            ]
        ]
    ]
    StartTime: ReadOnly[
        Required[
            Union[
                RegEx[RegExpr[r"^[0-9]{2}:[0-9]{2}$"], NOFLAG],
                Example[Literal["09:00", "21:00"]],
            ]
        ]
    ]
    EndTime: ReadOnly[
        Required[
            Union[
                RegEx[RegExpr[r"^[0-9]{2}:[0-9]{2}$"], NOFLAG],
                Example[Literal["09:00", "21:00"]],
            ]
        ]
    ]


class Filters(TypedDict, total=False):
    IgnoreTheseDetectedItems: ReadOnly[NotRequired[List[str]]]
    TriggerOnTheseDetectedItems: ReadOnly[NotRequired[List[str]]]


class MinimumSceneDataItem(TypedDict, total=False):
    DataType: ReadOnly[
        Required[
            Literal[
                "Thumbnail",
                "RGBStill",
                "IRStill",
                "DepthStill",
                "RGBStereoStill",
                "ThermalStill",
                "RGBVideo",
                "IRVideo",
                "DepthVideo",
                "RGBStereoVideo",
                "ThermalVideo",
                "Audio",
                "Temperature",
                "Humidity",
                "PIR",
                "CarbonMonoxide",
                "AudioTranscript",
                "IRDetection",
                "Pressure",
                "Proximity",
                "LiquidLevel",
                "Acceleration",
                "Rotation",
                "Vector",
                "Other",
            ]
        ]
    ]
    Count: ReadOnly[Required[int]]
    Required: ReadOnly[NotRequired[bool]]


class AnalysisParamItem(TypedDict, total=True):
    ParamName: ReadOnly[Required[str]]
    ParamValue: ReadOnly[Required[str]]


class AIServer(TypedDict, total=False):
    Protocol: ReadOnly[NotRequired[str]]
    Authority: ReadOnly[NotRequired[str]]
    ID: ReadOnly[NotRequired[str]]
    Pass: ReadOnly[NotRequired[str]]


class Blurring(TypedDict, total=True):
    Blur: ReadOnly[
        Required[
            List[
                Literal[
                    "Face",
                    "Text",
                    # Yes, the following value is really a valid value...
                    "Penis",
                ]
            ]
        ]
    ]
    ExecuteOnPipeline: ReadOnly[Required[bool]]


class DrawBoundingBoxes(TypedDict, total=True):
    Draw: ReadOnly[Required[bool]]
    ExecuteOnPipeline: ReadOnly[Required[bool]]


class Resolution(TypedDict, total=True):
    Height: ReadOnly[Required[int]]
    Width: ReadOnly[Required[int]]


class SceneModeConfig(TypedDict, total=False):
    Analysis: ReadOnly[NotRequired[str]]
    AnalysisVendor: ReadOnly[NotRequired[str]]
    NodeVersion: ReadOnly[
        NotRequired[
            # TODO find example to determine if regexable and what pattern
            Union[
                RegEx[RegExpr[r"^[1-9]+\.[0-9]+$"], NOFLAG],
                Example[Literal["1.0"]],
            ]
        ]
    ]
    AnalysisDescription: ReadOnly[NotRequired[str]]
    InferenceEngineVersion: ReadOnly[
        NotRequired[
            # TODO find example to determine if regexable and what pattern
            Union[
                RegEx[RegExpr[r"^[1-9]+\.[0-9]+$"], NOFLAG],
                Example[Literal["1.0"]],
            ]
        ]
    ]
    AnalysisStage: ReadOnly[
        NotRequired[
            Literal[
                "CustomAnalysis",
                "Motion",
                "Detect",
                "Recognize",
                "Characterize",
            ]
        ]
    ]
    CustomAnalysisID: ReadOnly[
        NotRequired[
            # TODO Figure out possible values somehow
            Literal["1"]
        ]
    ]
    CustomAnalysisStage: ReadOnly[NotRequired[str,]]
    ExecuteOnPipeline: ReadOnly[NotRequired[bool]]
    LabelRefDataList: ReadOnly[NotRequired[List[LabelRefData]]]
    AnalysisThreshold: ReadOnly[NotRequired[float]]
    AnalysisSampleRate: ReadOnly[NotRequired[float]]
    AnalysisRegion: ReadOnly[NotRequired[AnalysisRegion]]
    IgnoreObjectDetection: ReadOnly[NotRequired[IgnoreObjectDetection]]
    Scheduling: ReadOnly[NotRequired[List[Scheduling]]]
    Encryption: ReadOnly[NotRequired[Encryption]]
    Filters: ReadOnly[NotRequired[Filters]]
    MinimumSceneData: ReadOnly[NotRequired[List[MinimumSceneDataItem]]]
    AnalysisParams: ReadOnly[NotRequired[List[AnalysisParamItem]]]
    StartTimeRelTrigger: ReadOnly[NotRequired[float]]
    EndTimeRelTrigger: ReadOnly[NotRequired[float]]
    SceneMarkWindow: ReadOnly[NotRequired[float]]
    SceneMarkFrequency: ReadOnly[NotRequired[float]]
    AIServer: ReadOnly[NotRequired[AIServer]]
    Blurring: ReadOnly[NotRequired[Blurring]]
    DrawBoundingBoxes: ReadOnly[NotRequired[DrawBoundingBoxes]]
    Resolution: ReadOnly[NotRequired[Resolution]]


class CustomAnalysis(TypedDict, total=False):
    CustomAnalysisID: ReadOnly[NotRequired[str]]
    AnalysisDescription: ReadOnly[NotRequired[str]]
    AnalysisDrivenRegionOfInterest: ReadOnly[NotRequired[bool]]
    AnalysisThreshold: ReadOnly[NotRequired[float]]
    CaptureSequenceID: ReadOnly[NotRequired[str]]
    FeedbackEndPoint: ReadOnly[NotRequired[NetworkEndPointSpecifier]]


class ProcessingStage(TypedDict, total=False):
    ...


class RefDataListItem(TypedDict, total=False):
    ...


class RefDataItem(TypedDict, total=False):
    ...


class LabelRefData(TypedDict, total=False):
    LabelName: ReadOnly[Required[str]]
    ProcessingStage: ReadOnly[Required[ProcessingStage]]
    RefDataList: ReadOnly[NotRequired[List[RefDataListItem]]]
    RefData: ReadOnly[NotRequired[List[RefDataItem]]]


class SceneMarkInput(TypedDict, total=False):
    ...


class SceneMarkOutput(TypedDict, total=False):
    ...


class Mode(TypedDict, total=False):
    SceneModeDetectionType: ReadOnly[
        Required[
            Literal[
                "Motion",
                "Face",
                "Human",
                "Vehicle",
                "Label",
                "Animal",
                "TextLogoQRCode",
                "Custom",
                "Scene",
            ]
        ]
    ]
    SceneModeConfig: ReadOnly[NotRequired[List[SceneModeConfig]]]
    CustomAnalysis: ReadOnly[NotRequired[List[CustomAnalysis]]]
    LabelRefDataList: ReadOnly[NotRequired[List[LabelRefData]]]
    SceneMarkInputList: ReadOnly[NotRequired[List[SceneMarkInput]]]
    SceneMarkOutputList: ReadOnly[NotRequired[List[SceneMarkOutput]]]
    AudioAnalysisID: ReadOnly[NotRequired[LiteralString]]
    TransducerInput: ReadOnly[NotRequired[List[str]]]


class Storage(TypedDict, total=False):
    InputSceneMarkList: ReadOnly[NotRequired[List[str]]]
    SceneMarkBufferSize: ReadOnly[NotRequired[int]]
    InputSceneDataList: ReadOnly[NotRequired[List[str]]]
    SceneDataBufferSize: ReadOnly[NotRequired[int]]


class SceneMode(TypedDict, total=False):
    Version: ReadOnly[
        Required[
            Union[
                RegEx[RegExpr[r"^[1-9]+\.[0-9]+$"], NOFLAG],
                Example[Literal["1.0"]],
            ]
        ]
    ]
    NodeID: ReadOnly[
        Required[
            Union[
                RegEx[RegExpr[r"^[0-9a-z]{4}$"], IGNORECASE],
                Example[Literal["0001", "ffff", "FFFF"]],
            ]
        ]
    ]
    SceneModeID: ReadOnly[
        Required[
            # TODO find example to determine if regexable and what pattern
            Union[
                RegEx[
                    RegExpr[
                        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
                    ],
                    IGNORECASE,
                ],
                Example[Literal["00000001-0001-0001-0001-000000000001"]],
            ]
        ]
    ]

    Mode: ReadOnly[NotRequired[Mode]]
    Storage: ReadOnly[NotRequired[Storage]]
    Inputs: ReadOnly[NotRequired[List[SceneModeInput]]]
    Outputs: ReadOnly[NotRequired[List[SceneModeOutput]]]
    Transducers: ReadOnly[NotRequired[List[Transducer]]]
