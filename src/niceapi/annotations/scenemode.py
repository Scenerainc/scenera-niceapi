from __future__ import annotations

from re import RegexFlag
from typing import TYPE_CHECKING, TypedDict, Literal

from .regex_typing import RegEx

__all__ = (
    "SceneMode",
    "WebAPIScheme",
    "NetworkEndPointSpecifier",
    "SceneModeInput",
    "SceneModeOutput",
    "Transducer",
    "Region",
    "ROICoord",
    "AnalysisRegion",
    "IgnoreObjectDetection",
    "SceneMarkEncryption",
    "ApplicationEndPointSpecifier",
    "PrivacyServerEndPoint",
    "Encryption",
    "Scheduling",
    "SceneDataType",
    "WebAPIProcotol",
    "SchedulingType",
    "Blurable",
    "AnalysisStage",
    "SceneModeOuputType",
    "SceneModeDetectionType",
    "ROITypeEnum",
    "StringVersionRegex",
    "ScheduleTimeRegex",
    "NodeIDRegex",
    "PortIDRegex",
    "SceneModeIDRegex",
    "EndPointIDRegex",
    "ZERO_FLAG",
)

if TYPE_CHECKING:
    from re import Match
    from typing import Protocol, TypeVar, List

    from typing_extensions import (
        LiteralString,
        NotRequired,
        ReadOnly,
        Required,
    )

    Example = Literal

    RegExpr_T = TypeVar("T", bound=RegEx)
    Example_T = TypeVar("T", bound=LiteralString)

    class StringSpecification(str, Protocol[RegExpr_T, Example_T]):
        """Example value for a given field"""

    NodeID = StringSpecification[
        Match["NodeIDRegex"],
        Literal["0001", "ffff", "FFFF"],
    ]
    PortID = StringSpecification[
        Match["PortIDRegex"],
        Example["0001", "7fff" "ffff",],
    ]
    EndPointID = StringSpecification[
        Match["EndPointIDRegex"],
        Example["0000000f-0001-0001-0001-000000000001"],
    ]

    SceneModeID  = StringSpecification[
        Match["SceneModeIDRegex"],
        Example["0000000f-0001-0001-0001-000000000001"],
    ]

    ScheduleTime  = StringSpecification[
        Match["ScheduleTimeRegex"],
        Example["09:00", "21:00"],
    ]

    StringVersion = StringSpecification[
        Match["StringVersionRegex"],
        Example["1.0",  "1.1"]
    ]


ZERO_FLAG = RegexFlag(0)

StringVersionRegex = RegEx[r"^[1-9]+\.[0-9]+$", ZERO_FLAG],

NodeIDRegex = PortIDRegex = RegEx[r"^[0-9a-f]{4}$", ZERO_FLAG]

EndPointIDRegex = SceneModeIDRegex = RegEx[
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    ZERO_FLAG,
]

ScheduleTimeRegex = RegEx[r"^[0-9]{2}:[0-9]{2}$", ZERO_FLAG]

SceneDataType = Literal[
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

WebAPIProcotol = Literal[
    "MQTT",
    "WebAPI",
    "WebRTC",
    "Local",
]

SchedulingType = Literal[
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

Blurable = Literal[
    "Face",
    "Text",
    # Yes, the following value is really a valid value...
    "Penis",
]

AnalysisStage = Literal[
    "CustomAnalysis",
    "Motion",
    "Detect",
    "Recognize",
    "Characterize",
]

SceneModeOuputType = Literal[
    "Video",
    "Thermometer",
    "Humidity",
    "CarbonMonoxide",
    "PIR",
    "Audio",
    "Image",
]

SceneModeDetectionType = Literal[
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

ROITypeEnum = Literal[
    "SingleLine",
    "MultiLine",
    "SinglePolygon",
    "MultiPolygon",
]


class WebAPIScheme(TypedDict, total=False):
    """Represents the configuration for a Web API scheme,
    including protocol, authority, and optional access token and role."""
    Protocol: ReadOnly[Required[WebAPIProcotol]]
    Authority: ReadOnly[Required[str]]
    AccessToken: ReadOnly[NotRequired[str]]
    Role: ReadOnly[NotRequired[Literal["Server", "Client"]]]


class NetworkEndPointSpecifier(TypedDict, total=False):
    """Specifies the configuration for a network endpoint,
    including API version, endpoint ID, node ID, and port ID."""
    APIVersion: ReadOnly[
        Required[
            # TODO find example to determine if regexable and what pattern
            Literal["1.0"]
        ]
    ]

    EndPointID: ReadOnly[
        Required[
            EndPointID
        ]
    ]

    NodeID: ReadOnly[
        NotRequired[
            # Idk what kind of node id this is, device+node or hex node id?
            NodeID
        ]
    ]
    PortID: ReadOnly[
        NotRequired[
            PortID
        ]
    ]
    Scheme: ReadOnly[NotRequired[List[WebAPIScheme]]]


class SceneModeInput(TypedDict, total=False):
    """Represents the input configuration for a scene mode,
    including port ID and optional scene mark input."""
    PortID: ReadOnly[
        Required[
            PortID
        ]
    ]
    SceneMarkInput: ReadOnly[NotRequired[NetworkEndPointSpecifier]]


class SceneModeOutput(TypedDict, total=False):
    """Represents the output configuration for a scene mode,
    including port ID, output type, and optional destination endpoints."""
    PortID: ReadOnly[
        Required[
            PortID
        ]
    ]
    Type: ReadOnly[Required[SceneModeOuputType]]
    DestinationEndPointList: ReadOnly[NotRequired[List[NetworkEndPointSpecifier]]]


class Transducer(TypedDict, total=False):
    """This seems incomplete on the datapipeline?"""

    Type: Literal["Speaker", "Microphone", "ImageSensor"]
    TransducerID: LiteralString


class Region(TypedDict, total=True):
    """Defines a region with X and Y coordinates."""
    XCoord: ReadOnly[Required[float]]
    YCoord: ReadOnly[Required[float]]


class ROICoord(TypedDict, total=False):
    """Specifies the region of interest (ROI) coordinates,
    including severity level and optional coordinates."""
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
    """Represents an analysis region, including the ROI type
    and optional list of ROI coordinates."""
    ROITypeEnum: ReadOnly[NotRequired[ROITypeEnum]]
    ROICoords: ReadOnly[NotRequired[List[ROICoord]]]


class IgnoreObjectDetection(TypedDict, total=False):
    """Defines conditions for ignoring objects based on
    their size in object detection."""
    ObjectLargerThan: ReadOnly[Required[float]]
    ObjectSmallerThan: ReadOnly[Required[float]]

class SceneMarkEncryption(TypedDict, total=False):
    """Specifies encryption settings for scene marks
      including optional JWE algorithm and encryption methods."""
    JWEAlg: ReadOnly[NotRequired[str]]
    JWEEnc: ReadOnly[NotRequired[str]]


class ApplicationEndPointSpecifier(TypedDict, total=False):
    """Specifies an application endpoint, including API version,
    endpoint ID, X509 certificate, and access token."""
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
    """Represents a privacy server endpoint,
    including application and network endpoint details."""
    AppEndPoint: ReadOnly[NotRequired[ApplicationEndPointSpecifier]]
    NetEndPoint: ReadOnly[Required[NetworkEndPointSpecifier]]


class Encryption(TypedDict, total=False):
    """Defines encryption settings for scene data,
    including scene encryption key, scene mark encryption,
    and privacy server endpoint."""
    EncryptionOn: ReadOnly[Required[bool]]
    SceneEncryptionKeyID: ReadOnly[NotRequired[str]]
    SceneMarkEncryption: ReadOnly[NotRequired[SceneMarkEncryption]]
    SceneDataEncryption: ReadOnly[NotRequired[str]]
    PrivacyServerEndPoint: ReadOnly[NotRequired[PrivacyServerEndPoint]]


class Scheduling(TypedDict, total=False):
    """Represents the scheduling configuration,
    including the type of schedule and start/end times."""
    SchedulingType: ReadOnly[Required[SchedulingType]]
    StartTime: ReadOnly[
        Required[
            ScheduleTime
        ]
    ]
    EndTime: ReadOnly[
        Required[
            ScheduleTime
        ]
    ]


class Filters(TypedDict, total=False):
    """Defines detection filters, including ignored and triggered detected items."""
    IgnoreTheseDetectedItems: ReadOnly[NotRequired[List[str]]]
    TriggerOnTheseDetectedItems: ReadOnly[NotRequired[List[str]]]


class MinimumSceneDataItem(TypedDict, total=False):
    """Specifies a minimum scene data item, including count,
    data type, and an optional requirement flag."""
    Count: ReadOnly[Required[int]]
    DataType: ReadOnly[Required[SceneDataType]]
    Required: ReadOnly[NotRequired[bool]]


class AnalysisParamItem(TypedDict, total=True):
    """Defines an analysis parameter item,
    including the parameter name and value."""
    ParamName: ReadOnly[Required[str]]
    ParamValue: ReadOnly[Required[str]]


class AIServer(TypedDict, total=False):
    """Represents an AI server configuration,
    including optional protocol, authority, ID, and password."""
    Protocol: ReadOnly[NotRequired[str]]
    Authority: ReadOnly[NotRequired[str]]
    ID: ReadOnly[NotRequired[str]]
    Pass: ReadOnly[NotRequired[str]]


class Blurring(TypedDict, total=True):
    """Specifies blurring settings for sensitive information,
    including the blur target and whether to execute on the pipeline."""
    Blur: ReadOnly[Required[List[Blurable]]]
    ExecuteOnPipeline: ReadOnly[Required[bool]]


class DrawBoundingBoxes(TypedDict, total=True):
    """Defines settings for drawing bounding boxes,
    including whether to draw and execute on the pipeline."""
    Draw: ReadOnly[Required[bool]]
    ExecuteOnPipeline: ReadOnly[Required[bool]]


class Resolution(TypedDict, total=True):
    """Specifies the resolution of an image or video,
    including height and width."""
    Height: ReadOnly[Required[int]]
    Width: ReadOnly[Required[int]]


class SceneModeConfig(TypedDict, total=False):
    """Represents the configuration for a scene mode,
    including analysis settings, encryption, scheduling, and more."""
    Analysis: ReadOnly[NotRequired[str]]
    AnalysisVendor: ReadOnly[NotRequired[str]]
    NodeVersion: ReadOnly[
        NotRequired[
            StringVersion
        ]
    ]
    AnalysisDescription: ReadOnly[NotRequired[str]]
    InferenceEngineVersion: ReadOnly[NotRequired[StringVersion]]
    AnalysisStage: ReadOnly[NotRequired[AnalysisStage]]
    CustomAnalysisID: ReadOnly[NotRequired[Example["1"]]]
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
    """Defines settings for custom analysis, including analysis description,
    region of interest, and feedback endpoint."""
    CustomAnalysisID: ReadOnly[NotRequired[str]]
    AnalysisDescription: ReadOnly[NotRequired[str]]
    AnalysisDrivenRegionOfInterest: ReadOnly[NotRequired[bool]]
    AnalysisThreshold: ReadOnly[NotRequired[float]]
    CaptureSequenceID: ReadOnly[NotRequired[str]]
    FeedbackEndPoint: ReadOnly[NotRequired[NetworkEndPointSpecifier]]


class ProcessingStage(TypedDict, total=False): ...


class RefDataListItem(TypedDict, total=False): ...


class RefDataItem(TypedDict, total=False): ...


class LabelRefData(TypedDict, total=False):
    """Specifies label reference data,
    including label name, processing stage,
    and optional reference data list."""
    LabelName: ReadOnly[Required[str]]
    ProcessingStage: ReadOnly[Required[ProcessingStage]]
    RefDataList: ReadOnly[NotRequired[List[RefDataListItem]]]
    RefData: ReadOnly[NotRequired[List[RefDataItem]]]


class SceneMarkInput(TypedDict, total=False):
    """Defines input settings for scene marks,
    including optional immediate processing and scene mark endpoint."""
    ImmediateProcessing: ReadOnly[NotRequired[bool]]
    SceneMarkInputEndPoint: ReadOnly[NotRequired[NetworkEndPointSpecifier]]


class SceneMarkOutput(TypedDict, total=False):
    """Represents output settings for scene marks,
    including the scene mark output endpoint."""
    SceneMarkOutputEndPoint: ReadOnly[NotRequired[NetworkEndPointSpecifier]]


class Mode(TypedDict, total=False):
    """Specifies a mode for a scene, including SceneModeConfig and mor."""
    SceneModeDetectionType: ReadOnly[Required[SceneModeDetectionType]]
    SceneModeConfig: ReadOnly[NotRequired[List[SceneModeConfig]]]
    CustomAnalysis: ReadOnly[NotRequired[List[CustomAnalysis]]]
    LabelRefDataList: ReadOnly[NotRequired[List[LabelRefData]]]
    SceneMarkInputList: ReadOnly[NotRequired[List[SceneMarkInput]]]
    SceneMarkOutputList: ReadOnly[NotRequired[List[SceneMarkOutput]]]
    AudioAnalysisID: ReadOnly[NotRequired[LiteralString]]
    TransducerInput: ReadOnly[NotRequired[List[str]]]


class Storage(TypedDict, total=False):
    """Defines storage settings for scene marks and scene data,
    including buffer sizes and input lists."""
    InputSceneMarkList: ReadOnly[NotRequired[List[str]]]
    SceneMarkBufferSize: ReadOnly[NotRequired[int]]
    InputSceneDataList: ReadOnly[NotRequired[List[str]]]
    SceneDataBufferSize: ReadOnly[NotRequired[int]]


class SceneMode(TypedDict, total=False):
    """Represents the configuration for a scene mode,
    including version, node ID, inputs, outputs, transducers,
    analysis configurations and more."""
    Version: ReadOnly[Required[StringVersion]]
    NodeID: ReadOnly[Required[NodeID]]
    SceneModeID: ReadOnly[Required[SceneModeID]]
    Mode: ReadOnly[NotRequired[Mode]]
    Storage: ReadOnly[NotRequired[Storage]]
    Inputs: ReadOnly[NotRequired[List[SceneModeInput]]]
    Outputs: ReadOnly[NotRequired[List[SceneModeOutput]]]
    Transducers: ReadOnly[NotRequired[List[Transducer]]]
