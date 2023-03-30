from enum import Enum, auto
from logging import INFO, Logger, getLogger
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from ..util._tools import _logger_setup

DICT_T = Dict[str, Any]

logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)


class _ApiID(Enum):
    GET_MANAGEMENT_END_POINT = auto()
    GET_MANAGEMENT_OBJECT = auto()
    GET_CONTROL_OBJECT = auto()
    GET_SCENE_MODE = auto()
    GET_PRIVACY_OBJECT = auto()
    GET_DATE_TIME_LA = auto()
    GET_DATE_TIME_AS = auto()
    SET_SCENE_MARK = auto()
    SET_SCENE_DATA = auto()


class _ApiComponent:
    _VERSION = "1.0"
    _MANAGEMENT_API = {
        _ApiID.GET_MANAGEMENT_END_POINT: "GetManagementEndPoint",
        _ApiID.GET_MANAGEMENT_OBJECT: "GetManagementObject",
        _ApiID.GET_CONTROL_OBJECT: "GetControlObject",
        _ApiID.GET_DATE_TIME_LA: "GetDateTime",
        _ApiID.GET_DATE_TIME_AS: "GetDateTime",
    }
    _CONTROL_API = {
        _ApiID.GET_SCENE_MODE: "GetSceneMode",
        _ApiID.GET_PRIVACY_OBJECT: "GetPrivacyObject",
    }
    _DATA_API = {
        _ApiID.SET_SCENE_MARK: "SetSceneMark",
        _ApiID.SET_SCENE_DATA: "SetSceneData",
    }

    def __init__(self, api: _ApiID):
        self._api = api

    @property
    def api(self) -> _ApiID:
        return self._api

    def get_command_type(
        self, endpoint: Optional[str], node: Optional[str] = None
    ) -> Optional[str]:
        if self._api in self._MANAGEMENT_API:
            return (
                f"/{self._VERSION}/{endpoint}/"
                f"management/{self._MANAGEMENT_API[self._api]}"
            )
        elif self._api in self._CONTROL_API:
            return (
                f"/{self._VERSION}/{endpoint}/"
                f"control/{node}/{self._CONTROL_API[self._api]}"
            )
        elif self._api in self._DATA_API:
            return self._DATA_API[self._api]
        else:
            logger.error(f"Unsupported API: {self._api}")
        return None

    def get_payload_node(self, node_id: str) -> DICT_T:
        payload = {"Version": self._VERSION, "NodeID": node_id}
        return payload

    def get_payload_key(self, key_id: Optional[str]) -> DICT_T:
        payload: DICT_T = {
            "Version": self._VERSION,
            "SceneEncryptionKeyID": key_id,
        }
        return payload

    def get_payload_random(
        self, endpoint: Optional[str], random: str
    ) -> DICT_T:
        payload = {
            "Version": self._VERSION,
            "EndPointID": endpoint,
            "RandomChallenge": random,
        }
        return payload

    def unwrap_payload(self, obj: DICT_T) -> Optional[DICT_T]:
        payload = None
        try:
            payload = obj["PayloadObject"]
        except Exception as e:
            logger.error(e)
        return payload

    def get_url(
        self,
        authority: Optional[str],
        endpoint: Optional[str],
        node: Optional[str] = None,
        port: Optional[str] = None,
    ) -> Optional[str]:
        if authority is None:
            logger.error("authority is None")
            return None

        authority_ = f"{authority[:-1 if authority[-1] == '/' else None]}"
        ret = urlparse(authority_)
        if ret.scheme in ("https", "http"):
            authority_ = f"{ret.netloc}{ret.path}"

        if self._api in self._MANAGEMENT_API:
            return (
                f"https://{authority_}/{self._VERSION}/{endpoint}/"
                f"management/{self._MANAGEMENT_API[self._api]}"
            )
        elif self._api in self._CONTROL_API:
            return (
                f"https://{authority_}/{self._VERSION}/{endpoint}/"
                f"control/{node}/{self._CONTROL_API[self._api]}"
            )
        elif self._api == _ApiID.SET_SCENE_MARK:
            if node and port:
                return (
                    f"https://{authority_}/{self._VERSION}/{endpoint}/"
                    f"data/{node}/{port}/{self._DATA_API[self._api]}"
                )
            else:
                logger.error(f"NodeID/PortID={node}/{port}")
        elif self._api == _ApiID.SET_SCENE_DATA:
            if node and port:
                return (
                    f"https://{authority_}/{self._VERSION}/{endpoint}/"
                    f"data/{node}/{port}/{self._DATA_API[self._api]}"
                )
            else:
                logger.error(f"NodeID/PortID={node}/{port}")
        else:
            logger.error(f"Unsupported API: {self._api}")
        return None
