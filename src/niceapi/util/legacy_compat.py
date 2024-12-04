from __future__ import annotations

from typing import TYPE_CHECKING, cast, Dict, Any

__all__ = ("UnsupportedError",
           "_legacy_scenemark_quirks",
           "_legacy_datasection_quirks",)

DICT_T = Dict[str, Any]

if TYPE_CHECKING:
    from typing  import Union, TypeVar
    from niceapi import SceneMark, DataSection
    from niceapi.annotations import SceneMode, SceneMark_DICT_T, SceneData_DICT_T, DataSection_DICT_T

    SCENEMODE_T   = Union[DICT_T,
                          SceneMode,]

    SCENEMARK_T   = TypeVar("SCENEMARK_T",   DICT_T, 
                                             SceneMark,
                                             SceneMark_DICT_T,)

    SCENEDATA_T   = TypeVar("SCENEDATA_T",   DICT_T,
                                             SceneMark.SceneData,
                                             SceneData_DICT_T,)

    DATASECTION_T = TypeVar("DATASECTION_T", DICT_T,
                                             DataSection,
                                             DataSection_DICT_T)


class UnsupportedError(Exception):
    pass

def _legacy_datasection_quirks(scene_mode: SCENEMODE_T, scene_data: DATASECTION_T,) -> DATASECTION_T:
    _ = scene_mode
    section_json = getattr(scene_data, "_json", scene_data)
    section_json = cast(DICT_T, section_json)

    section_json["OriginalFileHash"] = 'ABCDEFGHIJKLMNO'
    return scene_data

def _legacy_scenemark_quirks(scene_mode: SCENEMODE_T, scene_mark: SCENEMARK_T,) -> SCENEMARK_T:
    """Apply 'quirks' applied by legacy rest library to ensure backwards
    compatibility with things still using the legacy rest library's output scenemarks"""
    # pylint: disable=W0212

    scene_mark_json = getattr(scene_mark, "json", scene_mark)
    scene_mark_json = cast(DICT_T, scene_mark_json)

    for scenedata in scene_mark_json.get("SceneDataList", []):
        scenedata_json = getattr(scenedata, "_json", scenedata)
        scenedata_json["Required"]      = scenedata.get("Required",      True)
        scenedata_json["VersionNumber"] = scenedata.get("VersionNumber",  1.0)

    scene_mark_json["SelfCheck"] = {}
    scene_mark_json["NotificationMessage"] = ""
    scene_mark_json["AnalysisList"] = scene_mark_json.get("AnalysisList", [])

    # NOTE Speculative preperation in case an analysis list can't be a variable size
    # as this has likely never happened before...
    if len(scene_mark_json["AnalysisList"]) != 1:
        raise UnsupportedError("Currently a scenemark can only be for a singe analysis")

    scene_mark_json["SceneModeConfig"] = scene_mark_json.get("SceneModeConfig", [])

    for analysis in scene_mark_json["AnalysisList"]:
        object_list = analysis.get("DetectedObjects", [])

        event = analysis["EventType"]
        mode_configs = {
            conf["Analysis"]: conf for conf in scene_mode.get("Mode", {})
                                                         .get("SceneModeConfig", []) # type: ignore
        }
        if event not in mode_configs:
            raise UnsupportedError(f"Cannot determine the source SceneModeConfig for the event: '{event}'")
        
        scene_mark_json["SceneModeConfig"].append(mode_configs[event])
        analysis["AnalysisID"]      = analysis.get("CustomAnalysisID", "0001-0002-AI2")
        analysis["ErrorMessage"]    = analysis.get("ErrorMessage",     "")
        analysis["CustomEventType"] = analysis.get("CustomEventType",  analysis["EventType"])
        analysis["ItemTypeCount"]   = 1

        for detected in object_list:
            detected["TimeStamp"]     = scene_mark_json["TimeStamp"]
            detected["Frame"]         = 0
            detected["AlgorithmID"]   = detected.get("AlgorithmID", "12345678-1234-1234-1234-123456789fff")

    scene_mark_json["ProcessTimeList"] = scene_mark_json.get("ProcessTimeList", [])
    scene_mark_json["AnalysisList"][0]["AnalysisID"]     = "0001-0002-AI2"
    scene_mark_json["AnalysisList"][0]["ErrorMessage"]   = ""
    scene_mark_json["AnalysisList"][0]["TotalItemCount"] = 1
    # pylint: enable=W0212

    return scene_mark