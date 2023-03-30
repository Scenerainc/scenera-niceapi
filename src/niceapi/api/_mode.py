from logging import INFO, Logger, getLogger
from typing import Any, Dict, List, Optional

from ..util._tools import _has_required_keys, _is_list, _logger_setup
from .common import (
    WebAPIScheme,
    _is_valid_app_endpoint,
    _is_valid_endpoint,
    _is_valid_net_endpoint,
)

DICT_T = Dict[str, Any]

logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)


class _Encryption:
    def __init__(self, encryption: DICT_T) -> None:
        self._required: bool = False
        self._key_id: Optional[str] = None
        self._data_alg: Optional[str] = None
        self._mark_alg: Optional[str] = None
        self._mark_enc: Optional[str] = None
        self._app_end_point_id: Optional[str] = None
        self._app_access_token: Optional[str] = None
        self._certificate: Optional[str] = None
        self._net_end_point_id: Optional[str] = None
        self._node_id: Optional[str] = None
        self._scheme: List[WebAPIScheme] = list()
        try:
            self._required = encryption["EncryptionOn"]
            self._key_id = encryption.get("SceneEncryptionKeyID")
            self._data_alg = encryption.get("SceneDataEncryption")
            mark_encryption = encryption.get("SceneMarkEncryption")
            if mark_encryption:
                self._mark_alg = mark_encryption["JWEAlg"]
                self._mark_enc = mark_encryption["JWEEnc"]
            endpoint = encryption.get("PrivacyServerEndPoint")
            if endpoint:
                app_endpoint = endpoint.get("AppEndPoint")
                if app_endpoint:
                    if not _is_valid_app_endpoint(app_endpoint):
                        raise KeyError("Invalid AppEndPoint")
                    self._app_end_point_id = app_endpoint["EndPointID"]
                    self._app_access_token = app_endpoint.get("AccessToken")
                    certificate = app_endpoint.get("X.509Certificate")
                    if isinstance(certificate, list):
                        self._certificate = certificate[0]
                net_endpoint = endpoint["NetEndPoint"]
                if not _is_valid_net_endpoint(net_endpoint):
                    raise KeyError("Invalid NetEndPoint")
                self._net_end_point_id = net_endpoint["EndPointID"]
                self._node_id = net_endpoint.get("NodeID")
                schemes: List[DICT_T] = net_endpoint["Scheme"]
                for scheme in schemes:
                    protocol: str = scheme["Protocol"]
                    authority: str = scheme["Authority"]
                    access_token: Optional[str] = scheme.get("AccessToken")
                    if protocol == "WebAPI":
                        webapi = WebAPIScheme(authority, access_token)
                        self._scheme.append(webapi)
        except Exception as e:
            logger.error(e)

    @property
    def required(self) -> bool:
        return self._required

    @property
    def key_id(self) -> Optional[str]:
        return self._key_id

    @property
    def data_alg(self) -> Optional[str]:
        return self._data_alg

    @property
    def mark_alg(self) -> Optional[str]:
        return self._mark_alg

    @property
    def mark_enc(self) -> Optional[str]:
        return self._mark_enc

    @property
    def app_end_point_id(self) -> Optional[str]:
        return self._app_end_point_id

    @property
    def app_access_token(self) -> Optional[str]:
        return self._app_access_token

    @property
    def certificate(self) -> Optional[str]:
        return self._certificate

    @property
    def net_end_point_id(self) -> Optional[str]:
        return self._net_end_point_id

    @property
    def node_id(self) -> Optional[str]:
        return self._node_id

    @property
    def scheme(self) -> List[WebAPIScheme]:
        return self._scheme


class _OutputConfiguration:
    def __init__(self) -> None:
        self._destinations: List[Any] = list()
        self._encryption: Optional[_Encryption] = None

    @property
    def destinations(self) -> List[Any]:
        return self._destinations

    @property
    def encryption(self) -> Optional[_Encryption]:
        return self._encryption

    @encryption.setter
    def encryption(self, obj: _Encryption) -> None:
        self._encryption = obj


class _DestinationEndPoint:
    def __init__(self) -> None:
        self._end_point_id: Optional[str] = None
        self._node_id: Optional[str] = None
        self._port_id: Optional[str] = None
        self._scheme: List[WebAPIScheme] = list()

    @property
    def end_point_id(self) -> Optional[str]:
        return self._end_point_id

    @end_point_id.setter
    def end_point_id(self, obj: str) -> None:
        self._end_point_id = obj

    @property
    def node_id(self) -> Optional[str]:
        return self._node_id

    @node_id.setter
    def node_id(self, obj: str) -> None:
        self._node_id = obj

    @property
    def port_id(self) -> Optional[str]:
        return self._port_id

    @port_id.setter
    def port_id(self, obj: str) -> None:
        self._port_id = obj

    @property
    def scheme(self) -> List[WebAPIScheme]:
        return self._scheme


class _SceneMarkInput:
    def __init__(self) -> None:
        self._end_point_id: Optional[str] = None
        self._node_id: Optional[str] = None
        self._port_id: Optional[str] = None
        self._scheme: List[WebAPIScheme] = list()
        self._encryption: Optional[_Encryption] = None

    @property
    def end_point_id(self) -> Optional[str]:
        return self._end_point_id

    @end_point_id.setter
    def end_point_id(self, obj: str) -> None:
        self._end_point_id = obj

    @property
    def node_id(self) -> Optional[str]:
        return self._node_id

    @node_id.setter
    def node_id(self, obj: str) -> None:
        self._node_id = obj

    @property
    def port_id(self) -> Optional[str]:
        return self._port_id

    @port_id.setter
    def port_id(self, obj: str) -> None:
        self._port_id = obj

    @property
    def scheme(self) -> List[WebAPIScheme]:
        return self._scheme

    @property
    def encryption(self) -> Optional[_Encryption]:
        return self._encryption

    @encryption.setter
    def encryption(self, obj: _Encryption) -> None:
        self._encryption = obj


class _SceneMarkOutput:
    def __init__(self) -> None:
        self._end_point_id: Optional[str] = None
        self._node_id: Optional[str] = None
        self._port_id: Optional[str] = None
        self._scheme: List[WebAPIScheme] = list()
        self._encryption: Optional[_Encryption] = None

    @property
    def end_point_id(self) -> Optional[str]:
        return self._end_point_id

    @end_point_id.setter
    def end_point_id(self, obj: str) -> None:
        self._end_point_id = obj

    @property
    def node_id(self) -> Optional[str]:
        return self._node_id

    @node_id.setter
    def node_id(self, obj: str) -> None:
        self._node_id = obj

    @property
    def port_id(self) -> Optional[str]:
        return self._port_id

    @port_id.setter
    def port_id(self, obj: str) -> None:
        self._port_id = obj

    @property
    def scheme(self) -> List[WebAPIScheme]:
        return self._scheme

    @property
    def encryption(self) -> Optional[_Encryption]:
        return self._encryption

    @encryption.setter
    def encryption(self, obj: _Encryption) -> None:
        self._encryption = obj


#


class _SceneMode:
    _REQUIRED_KEYS = ["Version", "SceneModeID", "NodeID"]

    def __init__(self) -> None:
        self._initialize()

    def _initialize(self) -> None:
        self._json: Optional[DICT_T] = None
        self._video_url = None
        self._input_encryption: Optional[_Encryption] = None
        self._image_config: Optional[_OutputConfiguration] = None
        self._video_config: Optional[_OutputConfiguration] = None
        self._mark_inputs: List[Any] = list()
        self._mark_outputs: List[Any] = list()
        self._ref_encryptions: List[_Encryption] = list()
        self._mode_encryptions: List[_Encryption] = list()

    @property
    def is_available(self) -> bool:
        return self._json is not None

    @property
    def json(self) -> Optional[DICT_T]:
        return self._json

    @json.setter
    def json(self, obj: DICT_T) -> None:
        self._initialize()
        try:
            if not _has_required_keys(obj, self._REQUIRED_KEYS):
                raise KeyError("Invalid SceneMode")
            inputs = obj.get("Inputs")
            if inputs:
                for input_ in inputs:
                    net_endpoint = input_.get("EndPoint")
                    if net_endpoint:
                        if not _is_valid_net_endpoint(net_endpoint):
                            raise KeyError("Invalid Inputs/EndPoint")
                    encryption = input_.get("Encryption")
                    if encryption:
                        self._input_encryption = _Encryption(encryption)
                    if input_.get("Type") == "Video":
                        self._video_url = input_.get("VideoEndPoint", {}).get(
                            "VideoURI"
                        )

            outputs = obj.get("Outputs")
            if outputs:
                for output in outputs:
                    if not _has_required_keys(output, ["Type", "PortID"]):
                        raise KeyError("Invalid Outputs")
                    config = _OutputConfiguration()
                    destination_endpoints = output.get(
                        "DestinationEndPointList"
                    )
                    if destination_endpoints is not None:
                        if not _is_list(output, "DestinationEndPointList"):
                            raise ValueError("Invalid DestinationEndPointList")
                    for destination_endpoint in destination_endpoints:
                        if not _is_valid_endpoint(destination_endpoint):
                            raise KeyError("Invalid DestinationEndPointList")
                        endpoint = _DestinationEndPoint()
                        net_endpoint = destination_endpoint["NetEndPoint"]
                        endpoint.end_point_id = net_endpoint["EndPointID"]
                        endpoint.node_id = net_endpoint.get("NodeID")
                        endpoint.port_id = net_endpoint.get("PortID")
                        schemes = net_endpoint["Scheme"]
                        for scheme in schemes:
                            protocol = scheme["Protocol"]
                            authority = scheme["Authority"]
                            access_token = scheme.get("AccessToken")
                            if protocol == "WebAPI":
                                webapi = WebAPIScheme(authority, access_token)
                                endpoint.scheme.append(webapi)
                        config.destinations.append(endpoint)
                    resolution = output.get("Resolution")
                    if resolution:
                        if not _has_required_keys(
                            resolution, ["Width", "Height"]
                        ):
                            raise KeyError("Invalid Resolution")
                    encryption = output.get("Encryption")
                    if encryption:
                        config.encryption = _Encryption(encryption)
                    output_type = output["Type"]
                    if output_type == "Image":
                        self._image_config = config
                    elif output_type == "Video":
                        self._video_config = config
                    else:
                        logger.error(f"Unknown output type:{output_type}")

            mode = obj.get("Mode")
            if mode:
                if not _has_required_keys(
                    mode, ["SceneMode", "SceneModeConfig"]
                ):
                    raise KeyError("Invalid SceneMode/Mode")
                mode_configs = mode["SceneModeConfig"]
                if not _is_list(mode, "SceneModeConfig"):
                    raise ValueError("Invalid SceneModeConfig")
                for mode_config in mode_configs:
                    refs = mode_config.get("LabelRefDataList")
                    if refs is not None:
                        if not _is_list(mode_config, "LabelRefDataList"):
                            raise ValueError("Invalid LabelRefDataList")
                        for ref in refs:
                            if not _has_required_keys(
                                ref, ["LabelName", "ProcessingStage"]
                            ):
                                raise KeyError("Invalid LabelRefDataList")
                            data_list = ref.get("RefDataList")
                            if data_list is not None:
                                if not _is_list(ref, "RefDataList"):
                                    raise ValueError("Invalid RefDataList")
                                for data_item in data_list:
                                    if not _has_required_keys(
                                        data_item, ["RefDataID"]
                                    ):
                                        raise KeyError("Invalid RefDataList")
                            data = ref.get("RefData")
                            if data is not None:
                                if not _is_list(ref, "RefData"):
                                    raise ValueError("Invalid RefData")
                                for datum in data:
                                    if not _has_required_keys(
                                        datum,
                                        ["RefDataID", "RefData", "Encryption"],
                                    ):
                                        raise KeyError("Invalid RefData")
                                    encryption = datum["Encryption"]
                                    self._ref_encryptions.append(
                                        _Encryption(encryption)
                                    )
                    schedules = mode_config.get("Scheduling")
                    if schedules is not None:
                        if not _is_list(mode_config, "Scheduling"):
                            raise ValueError("Invalid Scheduling")
                        for schedule in schedules:
                            if not _has_required_keys(
                                schedule,
                                ["SchedulingType", "StartTime", "EndTime"],
                            ):
                                raise KeyError("Invalid Scheduling")
                    encryption = mode_config.get("Encryption")
                    if encryption is not None:
                        self._mode_encryptions.append(_Encryption(encryption))

                # Input
                mark_inputs = mode.get("SceneMarkInputList", {})
                for mark_input in mark_inputs:
                    scene_mark_input = _SceneMarkInput()
                    net_endpoint = mark_input.get("SceneMarkInputEndPoint")
                    if net_endpoint:
                        if not _is_valid_net_endpoint(net_endpoint):
                            raise KeyError("Invalid SceneMarkInputEndPoint")
                        scene_mark_input.end_point_id = net_endpoint[
                            "EndPointID"
                        ]
                        scene_mark_input.node_id = net_endpoint.get("NodeID")
                        scene_mark_input.port_id = net_endpoint.get("PortID")
                        schemes = net_endpoint["Scheme"]
                        for scheme in schemes:
                            protocol = scheme["Protocol"]
                            authority = scheme["Authority"]
                            access_token = scheme.get("AccessToken")
                            if protocol == "WebAPI":
                                webapi = WebAPIScheme(authority, access_token)
                                scene_mark_input.scheme.append(webapi)
                    encryption = mark_input.get("Encryption")
                    if encryption:
                        scene_mark_input.encryption = _Encryption(encryption)
                    self._mark_inputs.append(scene_mark_input)

                # Output
                mark_outputs = mode.get("SceneMarkOutputList", {})
                for mark_output in mark_outputs:
                    scene_mark_output = _SceneMarkOutput()
                    net_endpoint = mark_output.get("SceneMarkOutputEndPoint")
                    if net_endpoint:
                        if not _is_valid_net_endpoint(net_endpoint):
                            raise KeyError("Invalid SceneMarkOutputEndPoint")
                        scene_mark_output.end_point_id = net_endpoint[
                            "EndPointID"
                        ]
                        scene_mark_output.node_id = net_endpoint.get("NodeID")
                        scene_mark_output.port_id = net_endpoint.get("PortID")
                        schemes = net_endpoint["Scheme"]
                        for scheme in schemes:
                            protocol = scheme["Protocol"]
                            authority = scheme["Authority"]
                            access_token = scheme.get("AccessToken")
                            if protocol == "WebAPI":
                                webapi = WebAPIScheme(authority, access_token)
                                scene_mark_output.scheme.append(webapi)
                    encryption = mark_output.get("Encryption")
                    if encryption:
                        scene_mark_output.encryption = _Encryption(encryption)
                    self._mark_outputs.append(scene_mark_output)

            self._json = obj
        except Exception as e:
            logger.error(e)
            self._initialize()

    @property
    def video_url(self) -> Optional[str]:
        return self._video_url

    @property
    def input_encryption(self) -> Optional[_Encryption]:
        return self._input_encryption

    @property
    def image_config(self) -> Optional[_OutputConfiguration]:
        return self._image_config

    @property
    def video_config(self) -> Optional[_OutputConfiguration]:
        return self._video_config

    @property
    def mark_inputs(self) -> List[Any]:
        return self._mark_inputs

    @property
    def mark_outputs(self) -> List[Any]:
        return self._mark_outputs

    @property
    def ref_encryptions(self) -> Optional[List[_Encryption]]:
        if self._ref_encryptions:
            return self._ref_encryptions
        return None

    @property
    def mode_encryptions(self) -> Optional[List[_Encryption]]:
        if self._mode_encryptions:
            return self._mode_encryptions
        return None
