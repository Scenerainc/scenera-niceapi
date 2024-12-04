"""Common Type Definitions"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar, Generic, Literal, Union

from .regex_typing import RegEx

__all__ = ("MediaFormat_T",
           "SceneMarkStatus_T",
           "AnalysisProcessingStatus_T",
           "NiceItemType_T",
           "SceneDataType_T",
           "UploadStatus_T",
           "SceneDataID",
           "SceneMarkID",
           "DeviceNodeID",
           "SceneDataIDRegex",
           "SceneMarkIDRegex",
           "DeviceNodeIDRegex",
)

if TYPE_CHECKING:
    from datetime import datetime, timezone

    ExampleTimeStamp = Union[
        Literal['2024-11-05T20:15:57.774Z'],
        type(datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace("+00:00", "Z")),
    ]

RegExpr_T = TypeVar("RegExpr_T", bound=RegEx, covariant=True)
Example_T = TypeVar("Example_T", bound=str, covariant=True)

class StringSpecification(str, Generic[RegExpr_T, Example_T]):
    _: Union[RegExpr_T, Example_T]

ZuluTimeStampRegex = RegEx[r"^[0-9]{4}-[0-2]{2}-[0-9]{2}T[0-2]:[0-9]{2}:[0-9]{2}.[0-9]{3}Z$"]

SceneMarkIDRegex   = RegEx[r"^SMK_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[0-9a-f]{8}$"]

SceneDataIDRegex   = RegEx[r"^SDT_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[0-9a-f]{8}$"]

DeviceNodeIDRegex  = RegEx[r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[0-9a-f]{4}$"]


ZuluTimeStamp = StringSpecification[
    ZuluTimeStampRegex,
    ExampleTimeStamp
]

SceneMarkID = StringSpecification[
    SceneDataIDRegex,
    Literal["SMK_12345678-1234-5678-9abc-123456789abc_fedcba98"]
]

SceneDataID = StringSpecification[
    SceneDataIDRegex,
    Literal["SDT_12345678-1234-5678-9abc-123456789abc_fedcba98"]
]

DeviceNodeID = StringSpecification[
    DeviceNodeIDRegex,
    Literal["12345678-1234-5678-9abc-123456789abc_1234"]
]

UploadStatus_T = Literal[
    "Upload in Progress",
    "Available at Provided URI",
]

MediaFormat_T = Literal[
        "UNSPECIFIED",
        "JPEG",
        "H.264",
        "H.265",
        "RAW",
        "JSON"
    ]

SceneMarkStatus_T = Literal["Active", "Removed", "Processed",]

AnalysisProcessingStatus_T = Literal[
    "CustomAnalysis",
    "Motion",
    "Detected",
    "Recognized",
    'Characterized',
    "Undetected",
    "Failed",
    "Error",
]

NiceItemType_T    = Literal[
    "Motion",
    "Face",
    "Human",
    "Vehicle",
    "Label",
    "TextLogoQRCode",
    "Animal",
    "Custom",
    "Scene",
    "Fire",
    "Furniture",
    "Bag",
    "Acccessory",
    "Undefined",
    "Weapon",
    "Test"
]

SceneDataType_T     = Literal[
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
    "Other"
]