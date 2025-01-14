"""Common Type Definitions"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar, Generic, Literal, Union, Match

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
           "ZuluTimeStamp",)

RegExpr_T = TypeVar("RegExpr_T", bound=RegEx, covariant=True)
Example_T = TypeVar("Example_T", bound=str,   covariant=True)
Text_T    = TypeVar("Text_T",    bound=str,   covariant=True)

class StringSpecification(Generic[RegExpr_T, Example_T]):
    regex:   RegExpr_T
    example: Example_T

    def __contains__(self, value: Text_T, /) -> bool:
        return self.match(value) is not None

    def __init__(self, expression: RegEx, example: Example_T):
        if not expression.match(example):
            raise ValueError("Example expression must match the provided regex")
        self.regex   = expression
        self.example = example

    def __class_getitem__(cls, key: Tuple[RegEx, Example_T,], /) -> StringSpecification[RegEx, Example_T]:
        try:
            assert isinstance(key, tuple) and len(key) == 2, \
                "StringSpecifier takes 2 types, a Matchable RegEx type and a matching example string"
            expression, example, = key
            assert expression.match(example), \
                "Example '%s' does not match the regex of %s" %(example,
                                                                expression)
        except AssertionError as ex:
            raise ValueError(ex) from ex
        return cls(expression, example,)

    def match(self, *match_args, **match_kwargs):
        return self.regex.match(*match_args, **match_kwargs)

    def __str__(self) -> str:
        return self.example


NodeIDRegex        = RegEx[r"^[0-9a-f]{4}$"]
DeviceIDRegex      = RegEx[r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"]
SceneMarkIDRegex   = RegEx[r"^SMK_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[0-9a-f]{8}$"]
SceneDataIDRegex   = RegEx[r"^SDT_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[0-9a-f]{8}$"]
DeviceNodeIDRegex  = RegEx[r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[0-9a-f]{4}$"]
ZuluTimeStampRegex = RegEx[r"^[0-9]{4}-[01][0-9]-[0-9]{2}T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$"]

ZuluTimeStamp = StringSpecification[
    ZuluTimeStampRegex,
    "2024-11-05T20:15:57.774Z",
    # i.e.:
    # import datetime
    # datetime.datetime.now(datetime.timezone.utc)         \
    #                  .isoformat(timespec='milliseconds') \
    #                  .replace("+00:00", "Z")
]

SceneMarkID = StringSpecification[
    SceneMarkIDRegex,
    "SMK_12345678-9abc-def0-1234-56789abcdef0_12345678",
]

SceneDataID = StringSpecification[
    SceneDataIDRegex,
    "SDT_12345678-9abc-def0-1234-56789abcdef0_12345678",
]

NodeID   = StringSpecification[
    NodeIDRegex,
    'ef01',
]

DeviceID = StringSpecification[
    DeviceIDRegex,
    "12345678-9abc-def0-1234-56789abcdef0"
]
DeviceNodeID = StringSpecification[
    DeviceNodeIDRegex,
    "12345678-9abc-def0-1234-56789abcdef0_1234"
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
