from __future__ import annotations

from enum import Enum

try:
    from enum import StrEnum # python3.11 onward
except ImportError:
    class StrEnum(Enum):
        def __str__(self):
            return self.value

__all__ = ("SceneDataType", "UploadStatus", "StrEnum",)

class SceneDataType(StrEnum):
    THUMBNAIL        = "Thumbnail"
    RGB_STILL        = "RGBStill"
    IR_STILL         = "IRStill"
    DEPTH_STILL      = "DepthStill"
    RGB_STEREO_STILL = "RGBStereoStill"
    THERMALSTILL     = "ThermalStill"
    RGB_VIDEO        = "RGBVideo"
    IR_VIDEO         = "IRVideo"
    DEPTH_VIDEO      = "DepthVideo"
    RGBSTEREO_VIDEO  = "RGBStereoVideo"
    THERMAL_VIDEO    = "ThermalVideo"
    AUDIO            = "Audio"
    TEMPERATURE      = "Temperature"
    HUMIDITY         = "Humidity"
    PIR              = "PIR"
    CARBON_MONOXIDE  = "CarbonMonoxide"
    AUDIO_TRANSCRIPT = "AudioTranscript"
    IR_DETECTION     = "IRDetection"
    PRESSURE         = "Pressure"
    PROXIMITY        = "Proximity"
    LIQUID_LEVEL     = "LiquidLevel"
    ACCELERATION     = "Acceleration"
    ROTATION         = "Rotation"
    VECTOR           = "Vector"
    OTHER            = "Other"

class UploadStatus(StrEnum):
    AVAILABLE = "Available at Provided URI"
    UPLOADING = "Upload in Progress"
