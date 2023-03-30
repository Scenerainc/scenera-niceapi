import copy
import json
import os
from datetime import datetime

# from datetime import datetime
from logging import INFO, Logger, getLogger
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from ..cmf._request import _CMFRequest
from ..cmf._response import _CMFResponse
from ..crypto._utility import _get_random_hex, _to_pem
from ..crypto.base import FAIL_T, SUCCESS_T
from ..crypto.jose import Decrypt, Encrypt, Sign, Verify, _jwe_encrypt
from ..io._webapi import _WebAPI
from ..io.webapi_base import WebAPIBase
from ..util._storage import _Storage
from ..util._tools import (
    _base64url_decode,
    _datetime_decode,
    _datetime_utcnow,
    _file_update,
    _has_required_keys,
    _json_load,
    _logger_setup,
    _logging_time,
    _TracebackOnException,
)
from ._api import _ApiComponent, _ApiID
from ._mode import _Encryption, _SceneMode
from .control import ControlObject
from .data import DataSection
from .endpoint import OPT_STR_T, ManagementEndPoint
from .management import ManagementObject
from .mark import SceneMark
from .security import DeviceSecurityObject

DICT_T = Dict[str, Any]
NG_T = Tuple[FAIL_T, None]
OK_T = Tuple[SUCCESS_T, Any]
RESULT_T = Union[NG_T, OK_T]
CERTS_T = Optional[List[str]]
_SETTER_FUNC_T = Callable[
    [_Encryption], Tuple[OPT_STR_T, OPT_STR_T, OPT_STR_T]
]

DUMP_MESSAGE = os.environ.get("DUMP_MESSAGE", "0") == "1"
logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)

TIMEOUT_MANAGEMENT: int = 60
TIMEOUT_DATA: int = 10
TIMEOUT_DATETIME: int = 5
TIME_LOG: bool = False
SEC_CERT_FILE: str = "sec.perm"
MNG_CERT_FILE: str = "mng.perm"


class ApiRequest:
    """API Request class to handle Device APIs."""

    tls_server_auth: bool = True
    """bool: If False, then disable TLS server authentication.
    """
    x5c_verify: bool = True
    """bool: If False, then disable to verify the trust chain
    of certificates in the x5c fieldof the JWS header.
    """
    security: DeviceSecurityObject = DeviceSecurityObject()
    """DeviceSecurityObject: Holding the DeviceSecurity Object
    which was set by ApiRequest.set_security_object().
    """
    endpoint: ManagementEndPoint = ManagementEndPoint()
    """ManagementEndPoint: Holding the ManagementEndPoint obtained
    from NICE LA.
    """
    management: ManagementObject = ManagementObject()
    """ManagementObject: Holding the Management Object obtained from NICE LA.
    """
    control: ControlObject = ControlObject()
    """ControlObject: Holding the DeviceControl Object obtained from NICE AS.
    """
    _jws_verify = None
    _jws_sign = None
    _jwe_decrypt = None
    _has_storage: bool = False
    _sec_root_certs: CERTS_T = None
    _mng_root_certs: CERTS_T = None
    _ctrl_root_certs: CERTS_T = None
    _permanent_loaded: bool = False
    _permanent_path: str = "."

    @classmethod
    def _is_server_auth(cls) -> bool:
        return cls.tls_server_auth

    @classmethod
    def set_security_object(cls, security: DICT_T) -> None:
        """Set DeviceSecurityObject.

        Parameters
        ----------
        security : dict
            JSON Object of the DeviceSecurity Object.

        Returns
        -------
        None
        """
        cls.security.json = security
        if not cls.security.is_available:
            logger.error("Invalid DeviceSecurityObject")
            return
        certs = cls.security.allowed_tls_root_certificates
        if certs:
            _file_update(
                path=os.path.join(cls._permanent_path, SEC_CERT_FILE),
                data=json.dumps(certs).encode(),
            )
        if not cls._permanent_loaded:
            with _TracebackOnException():
                sec_path = os.path.join(cls._permanent_path, SEC_CERT_FILE)
                mng_path = os.path.join(cls._permanent_path, MNG_CERT_FILE)
                tls_root_certs = cls._create_tls_root_certs(
                    sec_root_certs=_json_load(sec_path),
                    mng_root_certs=_json_load(mng_path),
                )
                _WebAPI.update_root_cert(tls_root_certs)
            cls._permanent_loaded = True
        else:
            tls_root_certs = cls._create_tls_root_certs(
                sec_root_certs=cls.security.allowed_tls_root_certificates,
                mng_root_certs=cls.management.allowed_tls_root_certificates,
                ctrl_root_certs=cls.control.allowed_tls_root_certificates,
            )
            _WebAPI.update_root_cert(tls_root_certs)

    @classmethod
    def set_private_key(cls, key: DICT_T) -> None:
        """Set DevicePrivateKey.

        Parameters
        ----------
        key : dict
            JSON Object of the DevicePrivateKey.

        Returns
        -------
        None
        """
        cls.security.device_private_key = key

    @classmethod
    def initialize_jose(cls) -> bool:
        """Initialize JOSE.

        DeviceSecurityObject and DevicePrivateKey are mandatory.

        Returns
        -------
        bool
            True if successful.
        """
        security = cls.security
        if security.is_available and security.device_private_key:
            kid = security.device_id
            key = security.device_private_key
            crt = security.device_certificate
            cls._jws_verify = Verify(
                cls.x5c_verify, security.nice_la_root_certificate
            )
            cls._jws_sign = Sign(kid, key, crt)  # type: ignore
            cls._jwe_decrypt = Decrypt(key)
            return True
        else:
            logger.error("cannot initialize JOSE without DeviceSecurityObject")

        return False

    @classmethod
    def activate_storage(cls, size: int) -> None:
        """Activate the storage for SceneMark and DataSection
        with the specified size.

        Parameters
        ----------
        size : int
            storage size in bytes

        Returns
        -------
        None
        """
        cls._has_storage = True
        _Storage.set_size(size)

    @classmethod
    def get_management_end_point(cls) -> bool:
        """Send GetManagementEndPoint API.

        Obtained ManagementEndPoint is stored in ApiRequest.endpoint

        Returns
        -------
        bool
            True if successful.
        """
        with _logging_time(TIME_LOG, logger, "GetManagementEndPoint"):
            api = _ApiComponent(_ApiID.GET_MANAGEMENT_END_POINT)
            # get values from DeviceSecurityObject
            security = cls.security
            if not security.is_available:
                logger.error("no DeviceSecurityObject")
                return False
            if not isinstance(security.nice_la_root_certificate, list):
                logger.error("Invalid DeviceSecurityObject")
                return False
            src: str = security.device_id  # type: ignore
            dst: str = security.net_end_point_id  # type: ignore
            app: str = security.net_end_point_id  # type: ignore
            crt = None
            access_token = None

            # only support scheme[0] for now
            security_scheme = security.scheme[0]
            authority = security_scheme.authority
            bearer = security_scheme.access_token

            obj = cls._handle_management_request(
                api, src, dst, app, crt, access_token, authority, bearer
            )
            if not obj:
                return False

            cls.endpoint.json = obj
            if not cls.endpoint.is_available:
                logger.error("Invalid GetManagementEndPoint")
                return False
            if cls._jws_sign is not None:
                cls._jws_sign.update_certificate(
                    cls.endpoint.device_certificate
                )
        return True

    @classmethod
    def get_management_object(cls) -> bool:
        """Send GetManagementObject API.

        Obtained ManagementObject is stored in ApiRequest.management.

        Returns
        -------
        bool
            True if successful.
        """
        with _logging_time(TIME_LOG, logger, "GetManagementObject"):
            api = _ApiComponent(_ApiID.GET_MANAGEMENT_OBJECT)
            # get values from DeviceSecurityObject & ManagementEndPoint
            security = cls.security
            if not security.is_available:
                logger.error("no DeviceSecurityObject")
                return False
            if not isinstance(security.nice_la_root_certificate, list):
                logger.error("Invalid DeviceSecurityObject")
                return False
            endpoint = cls.endpoint
            if not endpoint.is_available:
                logger.error("no ManagementEndPoint")
                return False

            src: str = security.device_id  # type: ignore
            dst: str = endpoint.net_end_point_id  # type: ignore
            app: str = endpoint.app_end_point_id  # type: ignore
            crt = endpoint.certificate
            access_token = endpoint.app_access_token

            # only support scheme[0] for now
            endpoint_scheme = endpoint.scheme[0]
            authority = endpoint_scheme.authority
            bearer = endpoint_scheme.access_token

            obj = cls._handle_management_request(
                api,
                src,
                dst,
                app,
                crt,
                access_token,
                authority,
                bearer,
            )
            if not obj:
                return False

            cls.management.json = obj
            if not cls.management.is_available:
                logger.error("Invalid ManagementObject")
                return False
            if cls._jws_sign is not None:
                cls._jws_sign.update_certificate(
                    cls.management.device_certificate
                )
            certs = cls.management.allowed_tls_root_certificates
            if certs:
                _file_update(
                    path=os.path.join(cls._permanent_path, MNG_CERT_FILE),
                    data=json.dumps(certs).encode(),
                )
            tls_root_certs = cls._create_tls_root_certs(
                sec_root_certs=cls.security.allowed_tls_root_certificates,
                mng_root_certs=cls.management.allowed_tls_root_certificates,
                ctrl_root_certs=cls.control.allowed_tls_root_certificates,
            )
            _WebAPI.update_root_cert(tls_root_certs)
        return True

    @classmethod
    def get_control_object(cls) -> bool:
        """Send GetControlObject API.

        Obtained ControlObject is stored in ApiRequest.control

        Returns
        -------
        bool
            True if successful.
        """

        with _logging_time(TIME_LOG, logger, "GetControlObject"):
            api = _ApiComponent(_ApiID.GET_CONTROL_OBJECT)
            # get values from DeviceSecurityObject & ManagementObject
            security = cls.security
            if not security.is_available:
                logger.error("no DeviceSecurityObject")
                return False
            management = cls.management
            if not management.is_available:
                logger.error("no ManagementObject")
                return False

            src: str = security.device_id  # type: ignore
            dst: str = management.net_end_point_id  # type: ignore
            app: str = management.app_end_point_id  # type: ignore
            crt = management.certificate
            access_token = management.app_access_token

            # only support scheme[0] for now
            management_scheme = management.scheme[0]
            authority = management_scheme.authority
            bearer = management_scheme.access_token

            obj = cls._handle_management_request(
                api,
                src,
                dst,
                app,
                crt,
                access_token,
                authority,
                bearer,
            )
            if not obj:
                return False

            cls.control.json = obj
            if not cls.control.is_available:
                logger.error("Invalid ControlObject")
                return False
            tls_root_certs = cls._create_tls_root_certs(
                sec_root_certs=cls.security.allowed_tls_root_certificates,
                mng_root_certs=cls.management.allowed_tls_root_certificates,
                ctrl_root_certs=cls.control.allowed_tls_root_certificates,
            )
            _WebAPI.update_root_cert(tls_root_certs)
        return True

    @classmethod
    def get_scene_mode(cls, node_id: str) -> RESULT_T:
        """Send GetSceneMode API.

        SceneMode is returned if the API request was successful.

        Parameters
        ----------
        node_id : str
            NodeID

        Returns
        -------
        bool
            True if successful.
        dict
            SceneMode JSON Object or None.
        """
        with _logging_time(TIME_LOG, logger, "GetSceneMode"):
            api = _ApiComponent(_ApiID.GET_SCENE_MODE)
            # get values from DeviceSecurityObject & ControlObject
            security = cls.security
            if not security.is_available:
                logger.error("no DeviceSecurityObject")
                return False, None
            control = cls.control
            if not control.is_available:
                logger.error("no ControlObject")
                return False, None

            src: str = security.device_id  # type: ignore
            dst: str = control.net_end_point_id  # type: ignore
            app: str = control.app_end_point_id  # type: ignore
            crt = control.certificate
            access_token = control.app_access_token

            # only support scheme[0] for now
            control_scheme = control.scheme[0]
            authority = control_scheme.authority
            bearer = control_scheme.access_token

            obj = cls._handle_control_request(
                api,
                src,
                dst,
                app,
                crt,
                access_token,
                node_id,
                authority,
                bearer,
                node_id,
            )
            if not obj:
                return False, None
            mode = _SceneMode()
            mode.json = obj
            if not mode.is_available:
                logger.error("Invalid SceneMode")
                return False, None
            return True, obj

    @classmethod
    def _register_key_id(
        cls,
        api: _ApiComponent,
        src: Optional[str],
        key_id: str,
        setter: _SETTER_FUNC_T,
        enc: _Encryption,
    ) -> Optional[DICT_T]:
        dst = enc.net_end_point_id
        app, crt, access_token = setter(enc)

        # only support scheme[0] for now
        scheme = enc.scheme[0]
        authority = scheme.authority
        bearer = scheme.access_token

        node = enc.node_id
        obj = cls._handle_privacy_request(
            api,
            src,
            dst,
            app,
            crt,
            access_token,
            key_id,
            authority,
            bearer,
            node,
        )
        if obj:
            REQUIRED_KEYS = [
                "Version",
                "EndPointID",
                "PrivacyObjectID",
                "StartDateTime",
                "EndDateTime",
            ]
            if not _has_required_keys(obj, REQUIRED_KEYS):
                logger.error("Invalid Privacy")
                return None
            encryption_key = obj.get("SceneEncryptionKey")
            if encryption_key:
                if not _has_required_keys(encryption_key, ["k", "kid"]):
                    logger.error("Invalid SceneEncryptionKey")
                    return None
            """
            start = obj["StartDateTime"]
            start = _datetime_decode(start)
            end = obj["EndDateTime"]
            end = _datetime_decode(end)
            now = datetime.utcnow()
            if now < start or end < now:
                logger.error(
                    f"Out of date! now:{now}, start:{start}, "
                    f"end:{end}"
                )
                return None
            """
        return obj

    @classmethod
    def _make_privacy_dictionary(
        cls,
        setter: _SETTER_FUNC_T,
        api: _ApiComponent,
        src: Optional[str],
        enc_list: List[Optional[_Encryption]],
    ) -> DICT_T:
        key_ids: List[str] = list()
        privacy: DICT_T = dict()

        for enc in enc_list:
            if not enc or not enc.required:
                continue
            key_id = enc.key_id
            if key_id is None:
                continue
            if key_id not in key_ids:
                key_ids.append(key_id)
                obj = cls._register_key_id(api, src, key_id, setter, enc)
                if obj:
                    privacy[key_id] = obj
        return privacy

    @classmethod
    def get_privacy_object(cls, scene_mode: DICT_T) -> RESULT_T:
        """Send GetPrivacyObject API.

        Get all Privacy Objects corresponding to the 'Encryption' in SceneMode.

        Return a dict of PrivacyObject whose key is SceneEncryptionKeyID.

        Parameters
        ----------
        scene_mode : dict
            SceneMode JSON Object.

        Returns
        -------
        bool
            True if successful.
        dict
            Dictionary of the Privacy Object.
        """
        with _logging_time(TIME_LOG, logger, "GetPrivacyObject"):
            api = _ApiComponent(_ApiID.GET_PRIVACY_OBJECT)
            security = cls.security
            if not security.is_available:
                logger.error("no DeviceSecurityObject")
                return False, None
            src = security.device_id
            _setter: _SETTER_FUNC_T = lambda x: (
                x.app_end_point_id,
                x.certificate,
                x.app_access_token,
            )
            mode = _SceneMode()
            mode.json = scene_mode
            if not mode.is_available:
                logger.error("Invalid SceneMode")
                return False, None

            encryptions: List[Optional[_Encryption]] = [
                mode.input_encryption,
                mode.image_config.encryption
                if mode.image_config is not None
                else None,
                mode.video_config.encryption
                if mode.video_config is not None
                else None,
            ]
            for mark_input in mode.mark_inputs:
                encryptions.append(mark_input.encryption)
            for mark_output in mode.mark_outputs:
                encryptions.append(mark_output.encryption)
            if mode.ref_encryptions:
                encryptions.extend(mode.ref_encryptions)
            if mode.mode_encryptions:
                encryptions.extend(mode.mode_encryptions)

            privacy = cls._make_privacy_dictionary(
                _setter, api, src, encryptions
            )
            if not privacy:
                return False, None

            return True, privacy

    @classmethod
    def get_date_time_from_la(cls) -> RESULT_T:
        """Send GetDateTime to NICE LA.

        DateTime is returned if the API request was successful.

        Returns
        -------
        bool
            True if successful.

        datetime
            TrustedTimeResponse["DateTimeStamp"] or None.
        """
        with _logging_time(TIME_LOG, logger, "GetDateTime(LA)"):
            api = _ApiComponent(_ApiID.GET_DATE_TIME_LA)
            # get values from DeviceSecurityObject & ManagementEndPoint
            security = cls.security
            if not security.is_available:
                logger.error("no DeviceSecurityObject")
                return False, None
            endpoint = cls.endpoint
            if not endpoint.is_available:
                logger.error("no ManagementEndPoint")
                return False, None

            src = security.device_id
            dst = endpoint.net_end_point_id
            app = endpoint.app_end_point_id
            crt = endpoint.certificate
            access_token = endpoint.app_access_token

            # only support scheme[0] for now
            endpoint_scheme = endpoint.scheme[0]
            authority = endpoint_scheme.authority
            bearer = endpoint_scheme.access_token

            timestamp = cls._handle_datetime_request(
                api, src, dst, app, crt, access_token, authority, bearer
            )
            if not timestamp:
                return False, None

            return True, timestamp

    @classmethod
    def get_date_time_from_as(cls) -> RESULT_T:
        """Send GetDateTime to NICE AS.

        DateTime is returned if the API request was successful.

        Returns
        -------
        bool
            True if successful.

        datetime
            TrustedTimeResponse["DateTimeStamp"] or None.
        """
        with _logging_time(TIME_LOG, logger, "GetDateTime(AS)"):
            api = _ApiComponent(_ApiID.GET_DATE_TIME_AS)
            # get values from DeviceSecurityObject & ManagementObject
            security = cls.security
            if not security.is_available:
                logger.error("no DeviceSecurityObject")
                return False, None
            management = cls.management
            if not management.is_available:
                logger.error("no ManagementObject")
                return False, None

            src = security.device_id
            dst = management.net_end_point_id
            app = management.app_end_point_id
            crt = management.certificate
            access_token = management.app_access_token

            # only support scheme[0] for now
            management_scheme = management.scheme[0]
            authority = management_scheme.authority
            bearer = management_scheme.access_token

            timestamp = cls._handle_datetime_request(
                api, src, dst, app, crt, access_token, authority, bearer
            )
            if not timestamp:
                return False, None

            return True, timestamp

    @classmethod
    def new_scene_mark(
        cls, version: str, time_stamp: str, scene_mark_id: str, node_id: str
    ) -> SceneMark:
        """Generate new SceneMark.

        Parameters
        ----------
        version : str
            SceneMark["Version"]

        time_stamp : str
            SceneMark["TimeStamp"]

        scene_mark_id : str
            SceneMark["SceneMarkID"]

        node_id : str
            SceneMark["NodeID"]

        Returns
        -------
        SceneMark
            instance of SceneMark class
        """
        return SceneMark(version, time_stamp, scene_mark_id, node_id)

    @classmethod
    def set_scene_mark(
        cls,
        scene_mode: DICT_T,
        scene_mark: DICT_T,
        privacy_dict: Optional[DICT_T] = None,
    ) -> RESULT_T:
        """Send SceneMark to the SceneMarkOutputEndPoint
        specified in SceneMode Object.

        Parameters
        ----------
        scene_mode : dict
            SceneMode JSON Object

        scene_mark : dict
            SceneMark JSON Object

        privacy_dict : dict or None
            dictionary of Privacy Object.

        Returns
        -------
        bool
            True if successful.
        dict
            JSON Object of the response. (empty for now)
        """
        with _logging_time(TIME_LOG, logger, "SetSceneMark"):
            # keep current SceneMode
            copied_scene_mode = copy.deepcopy(scene_mode)
            mode = _SceneMode()
            mode.json = copied_scene_mode
            if not mode.is_available:
                logger.error("Invalid SceneMode")
                return False, None

            if cls._has_storage:
                _Storage.store_scene_mark(scene_mark)

            api = _ApiComponent(_ApiID.SET_SCENE_MARK)
            security = cls.security
            if not security.is_available:
                logger.error("no DeviceSecurityObject")
                return False, None

            objs: DICT_T = dict()
            for output in mode.mark_outputs:
                dst = output.end_point_id

                # only support scheme[0] for now
                scheme = output.scheme[0]
                authority = scheme.authority
                bearer = scheme.access_token

                node = output.node_id
                port = output.port_id

                if output.encryption and output.encryption.required:
                    obj = None
                    try:
                        if not privacy_dict:
                            raise Exception("no privacies parameter")
                        alg = output.encryption.mark_alg
                        enc = output.encryption.mark_enc
                        if alg != "A256KW" or enc != "A256GCM":
                            raise ValueError(f"alg, enc: {alg}, {enc}")
                        key_id = output.encryption.key_id
                        privacy = privacy_dict[key_id]
                        key = privacy["SceneEncryptionKey"]
                        kid = key["kid"]
                        k = _base64url_decode(key["k"])
                        dump = json.dumps(scene_mark).encode()
                        text = _jwe_encrypt(dump, alg, enc, kid, k)
                        if text is not None:
                            obj = cls._handle_text_data_request(
                                api, dst, text, authority, bearer, node, port
                            )
                    except Exception as e:
                        logger.error(e)

                else:
                    obj = cls._handle_json_data_request(
                        api, dst, scene_mark, authority, bearer, node, port
                    )

                if obj is not None:
                    objs[dst] = obj

            if not objs:
                return False, None

            dummy_dict: DICT_T = {}
            return True, dummy_dict

    @classmethod
    def new_scene_data(
        cls,
        version: str,
        data_id: str,
        section: int,
        last_section: int,
        section_base64: str,
        media_format: str,
    ) -> DataSection:
        """Generate new SceneData (DataSection Object).

        Parameters
        ----------
        version : str
            DataSection["Version"]

        data_id : str
            DataSection["DataID"]

        section : int
            DataSection["Section"]

        last_section : int
            DataSection["LastSection"]

        section_base64 : str
            DataSection["SectionBase64"]

        media_format : str
            DataSection["MediaFormat"]

        Returns
        -------
        DataSection
            instance of DataSection class
        """
        return DataSection(
            version,
            data_id,
            section,
            last_section,
            section_base64,
            media_format,
        )

    @classmethod
    def set_scene_data_image(
        cls, scene_mode: DICT_T, scene_data: DICT_T
    ) -> RESULT_T:
        """Send SetSceneData(Image).

        Send the full image as the SceneData to the destination endpoint
        specified in SceneMode Object.

        Parameters
        ----------
        scene_mode : dict
            SceneMode JSON Object

        scene_data : dict
            DataSection JSON Object

        Returns
        -------
        bool
            True if successful.
        dict
            JSON Object of the response. (empty for now)
        """
        with _logging_time(TIME_LOG, logger, "SetSceneData(Image)"):
            # keep current SceneMode
            copied_scene_mode = copy.deepcopy(scene_mode)
            mode = _SceneMode()
            mode.json = copied_scene_mode
            if not mode.is_available:
                logger.error("Invalid SceneMode")
                return False, None

            if cls._has_storage:
                _Storage.store_scene_data(scene_data)

            api = _ApiComponent(_ApiID.SET_SCENE_DATA)
            security = cls.security
            if not security.is_available:
                logger.error("no DeviceSecurityObject")
                return False, None

            if mode.image_config is None:
                return False, None

            objs: DICT_T = dict()
            for destination in mode.image_config.destinations:
                dst = destination.end_point_id

                # only support scheme[0] for now
                scheme = destination.scheme[0]
                authority = scheme.authority
                bearer = scheme.access_token

                node = destination.node_id
                port = destination.port_id

                obj = cls._handle_json_data_request(
                    api, dst, scene_data, authority, bearer, node, port
                )

                if obj is not None:
                    objs[dst] = obj

            if not objs:
                return False, None

            dummy_dict: DICT_T = {}
            return True, dummy_dict

    @classmethod
    def set_scene_data_video(
        cls, scene_mode: DICT_T, scene_data: DICT_T
    ) -> RESULT_T:
        """Send SetSceneData(Video).

        Send the video as the SceneData to the destination endpoint
        specified in SceneMode Object.

        Parameters
        ----------
        scene_mode : dict
            SceneMode JSON Object

        scene_data : dict
            DataSection JSON Object

        Returns
        -------
        bool
            True if successful.
        dict
            JSON Object of the response. (empty for now)
        """
        with _logging_time(TIME_LOG, logger, "SetSceneData(Video)"):
            # keep current SceneMode
            copied_scene_mode = copy.deepcopy(scene_mode)
            mode = _SceneMode()
            mode.json = copied_scene_mode
            if not mode.is_available:
                logger.error("Invalid SceneMode")
                return False, None

            if cls._has_storage:
                _Storage.store_scene_data(scene_data)

            api = _ApiComponent(_ApiID.SET_SCENE_DATA)
            security = cls.security
            if not security.is_available:
                logger.error("no DeviceSecurityObject")
                return False, None

            if mode.video_config is None:
                return False, None

            objs: DICT_T = dict()
            for destination in mode.video_config.destinations:
                dst = destination.end_point_id

                # only support scheme[0] for now
                scheme = destination.scheme[0]
                authority = scheme.authority
                bearer = scheme.access_token

                node = destination.node_id
                port = destination.port_id

                obj = cls._handle_json_data_request(
                    api, dst, scene_data, authority, bearer, node, port
                )

                if obj is not None:
                    objs[dst] = obj

            if not objs:
                return False, None

            dummy_dict: DICT_T = {}
            return True, dummy_dict

    @classmethod
    def set_webapi(cls, webapi: WebAPIBase) -> None:
        """Set the implementation of the HTTPS/POST request.

        Parameters
        ----------
        webapi : The implementation class of the HTTPS/POST derived
         from WebAPIBase.

        Returns
        -------
        None
        """
        _WebAPI.set_webapi(webapi)

    @classmethod
    def set_max_connection(cls, limit: int) -> None:
        """Set maximum number of concurrent HTTPS/POST connections.

        Parameters
        ----------
        limit : int
            Maximum number of connections.
            Zero or negative number means unlimited.
            The default is unlimited.
            It must be set before the server connection.

        Returns
        -------
        None
        """
        _WebAPI.set_max_connection(limit)

    @classmethod
    def set_permanent_path(cls, path: str) -> None:
        """Set path of permanent directory.

        Parameters
        ----------
        path : str
            path of permanent directory.

        Returns
        -------
        None
        """
        cls._permanent_path = path

    """Private functions
    """

    @classmethod
    def _handle_request_encryption(
        cls,
        app: Optional[str],
        crt: Optional[str],
        access_token: Optional[str],
        payload_object: Optional[DICT_T],
        cmf: _CMFRequest,
    ) -> Optional[DICT_T]:
        if cls._jws_sign is None:
            logger.error("jose not initialized")
            return None

        if access_token:
            payload = cmf.make_payload(access_token, payload_object)
            if DUMP_MESSAGE:
                logger.info(
                    f"EncryptionPayload Request - \
                        {json.dumps(payload, indent=2)}"
                )
            plaintext = json.dumps(payload).encode()
            success, jwe = Encrypt(app, crt)(plaintext)
            if not success:
                logger.error("failed to encrypt")
                return None
            cmf.payload = jwe

        request = cmf.make_request(crt)
        if DUMP_MESSAGE:
            logger.info(f"CMFRequest - {json.dumps(request, indent=2)}")
        success, jws = cls._jws_sign(json.dumps(request).encode())
        if not success:
            logger.error("failed to sign")
            return None
        if DUMP_MESSAGE:
            logger.info(
                f"CMFContainer Request - \
                    {json.dumps(cmf.wrap_jws(jws), indent=2)}"
            )
        return cmf.wrap_jws(jws)

    @classmethod
    def _handle_response_encryption(
        cls, cmf: DICT_T
    ) -> Optional[_CMFResponse]:
        if cls._jws_verify is None or cls._jwe_decrypt is None:
            logger.error("jose not initialized")
            return None

        if DUMP_MESSAGE:
            logger.info(f"CMFContainer Response - {json.dumps(cmf, indent=2)}")
        cmf_response = _CMFResponse()
        jws = cmf_response.unwrap_jws(cmf)
        if not jws:
            logger.error("not signed")
            return None
        success, response = cls._jws_verify(jws)
        if not success:
            logger.error("failed to verify")
            return None
        response = json.loads(response)
        if DUMP_MESSAGE:
            logger.info(f"CMFResponse - {json.dumps(response, indent=2)}")
        cmf_response.json = response
        if not cmf_response.is_available:
            logger.error("Invalid CMFResponse")
            return None
        jwe = cmf_response.payload
        if not jwe:
            logger.error("no payload")
            return None
        success, payload = cls._jwe_decrypt(jwe)
        if not success:
            logger.error("failed to decrypt")
            return None
        try:
            cmf_response.payload = json.loads(payload)
            if DUMP_MESSAGE:
                logger.info(
                    f"EncryptionPayload Response - \
                        {json.dumps(cmf_response.payload, indent=2)}"
                )
        except Exception as e:
            logger.error(e)
            return None
        return cmf_response

    @classmethod
    def _handle_management_request(
        cls,
        api: _ApiComponent,
        src: str,
        dst: str,
        app: str,
        crt: Optional[str],
        access_token: Optional[str],
        authority: str,
        bearer: Optional[str],
    ) -> Optional[DICT_T]:
        # check api
        url = api.get_url(authority, dst)
        if url is None:
            return None

        # create CMF
        cmf = _CMFRequest()
        cmf.source_end_point_id = src
        cmf.destination_end_point_id = app
        cmf.date_time_stamp = _datetime_utcnow()
        cmf.command_type = api.get_command_type(dst)
        logger.debug(f"HEAD - {json.dumps(cmf.json, indent=2)}")
        payload_object = None

        cmf_container = cls._handle_request_encryption(
            app, crt, access_token, payload_object, cmf
        )
        if not cmf_container:
            return None
        logger.debug(f"WRAP - {cmf_container.keys()}")

        # send CMF
        api_get_kw: DICT_T = {
            "url": url,
            "body": cmf_container,
            "timeout": TIMEOUT_MANAGEMENT,
            "token": bearer,
            "verify": cls._is_server_auth(),
        }
        response = _WebAPI.post_json(**api_get_kw)
        if response is None:
            return None

        # get response body
        cmf_response = cls._handle_response_encryption(response)
        if cmf_response is None:
            return None

        if not cmf_response.has_valid_end_points(
            cmf.source_end_point_id, cmf.destination_end_point_id
        ):
            logger.error("Invalid EndPointID(s) in CMFResponse")
            return None

        return api.unwrap_payload(cmf_response.payload)

    @classmethod
    def _handle_control_request(
        cls,
        api: _ApiComponent,
        src: str,
        dst: str,
        app: str,
        crt: Optional[str],
        access_token: Optional[str],
        node_id: str,
        authority: str,
        bearer: Optional[str],
        node: str,
    ) -> Optional[DICT_T]:
        # check api
        url = api.get_url(authority, dst, node)
        if url is None:
            return None
        # create CMF
        cmf = _CMFRequest()
        cmf.source_end_point_id = src
        cmf.destination_end_point_id = app
        cmf.date_time_stamp = _datetime_utcnow()
        cmf.command_type = api.get_command_type(dst, node)
        logger.debug(f"HEAD - {json.dumps(cmf.json, indent=2)}")

        # create payload
        payload_object = api.get_payload_node(node_id)
        logger.debug(f"PAYLOAD - {json.dumps(payload_object, indent=2)}")

        cmf_container = cls._handle_request_encryption(
            app, crt, access_token, payload_object, cmf
        )
        if not cmf_container:
            return None
        logger.debug(f"WRAP - {cmf_container.keys()}")

        # send CMF
        response = _WebAPI.post_json(
            url,
            cmf_container,
            timeout=TIMEOUT_MANAGEMENT,
            token=bearer,
            verify=cls._is_server_auth(),
        )
        if response is None:
            return None

        # get response body
        cmf_response = cls._handle_response_encryption(response)
        if cmf_response is None:
            return None

        if not cmf_response.has_valid_end_points(
            cmf.source_end_point_id, cmf.destination_end_point_id
        ):
            logger.error("Invalid EndPointID(s) in CMFResponse")
            return None

        return api.unwrap_payload(cmf_response.payload)

    @classmethod
    def _handle_privacy_request(
        cls,
        api: _ApiComponent,
        src: Optional[str],
        dst: Optional[str],
        app: Optional[str],
        crt: Optional[str],
        access_token: Optional[str],
        key: Optional[str],
        authority: Optional[str],
        bearer: Optional[str],
        node: Optional[str],
    ) -> Optional[DICT_T]:
        # check api
        url = api.get_url(authority, dst, node)
        if url is None:
            return None
        # create CMF
        cmf = _CMFRequest()
        cmf.source_end_point_id = src
        cmf.destination_end_point_id = app
        cmf.date_time_stamp = _datetime_utcnow()
        cmf.command_type = api.get_command_type(dst, node)
        logger.debug(f"HEAD - {json.dumps(cmf.json, indent=2)}")

        # create payload
        payload_object = api.get_payload_key(key)
        logger.debug(f"PAYLOAD - {json.dumps(payload_object, indent=2)}")

        cmf_container = cls._handle_request_encryption(
            app, crt, access_token, payload_object, cmf
        )
        if not cmf_container:
            return None
        logger.debug(f"WRAP - {cmf_container.keys()}")

        # send CMF
        response = _WebAPI.post_json(
            url,
            cmf_container,
            timeout=TIMEOUT_MANAGEMENT,
            token=bearer,
            verify=cls._is_server_auth(),
        )
        if response is None:
            return None

        # get response body
        cmf_response = cls._handle_response_encryption(response)
        if cmf_response is None:
            return None

        if not cmf_response.has_valid_end_points(
            cmf.source_end_point_id, cmf.destination_end_point_id
        ):
            logger.error("Invalid EndPointID(s) in CMFResponse")
            return None

        return api.unwrap_payload(cmf_response.payload)

    @classmethod
    def _handle_datetime_request(
        cls,
        api: _ApiComponent,
        src: Optional[str],
        dst: Optional[str],
        app: Optional[str],
        crt: Optional[Optional[str]],
        access_token: Optional[str],
        authority: Optional[str],
        bearer: Optional[str],
    ) -> Optional[datetime]:
        # check api
        url = api.get_url(authority, dst)
        if url is None:
            return None
        # create CMF
        cmf = _CMFRequest()
        cmf.source_end_point_id = src
        cmf.destination_end_point_id = app
        cmf.date_time_stamp = _datetime_utcnow()
        cmf.command_type = api.get_command_type(dst)
        logger.debug(f"HEAD - {json.dumps(cmf.json, indent=2)}")

        random = _get_random_hex(64)

        # create payload
        payload_object = api.get_payload_random(dst, random)
        logger.debug(f"PAYLOAD - {json.dumps(payload_object, indent=2)}")

        cmf_container = cls._handle_request_encryption(
            app, crt, access_token, payload_object, cmf
        )
        if not cmf_container:
            return None
        logger.debug(f"WRAP - {cmf_container.keys()}")

        # send CMF
        response = _WebAPI.post_json(
            url,
            cmf_container,
            timeout=TIMEOUT_DATETIME,
            token=bearer,
            verify=cls._is_server_auth(),
        )
        if response is None:
            return None

        # get response body
        cmf_response = cls._handle_response_encryption(response)
        if cmf_response is None:
            return None

        if not cmf_response.has_valid_end_points(
            cmf.source_end_point_id, cmf.destination_end_point_id
        ):
            logger.error("Invalid EndPointID(s) in CMFResponse")
            return None

        obj = api.unwrap_payload(cmf_response.payload)
        if obj is None:
            return None

        REQUIRED_KEYS = [
            "Version",
            "EndPointID",
            "ReturnedRandomChallenge",
            "DateTimeStamp",
        ]
        if not _has_required_keys(obj, REQUIRED_KEYS):
            logger.error("Invalid TrustedTimeResponse")
            return None

        returned = obj.get("ReturnedRandomChallenge")
        if random != returned:
            logger.error("Invalid RandomChallenge")
            return None

        try:
            timestamp = obj["DateTimeStamp"]
            return _datetime_decode(timestamp)
        except Exception as e:
            logger.error(e)

        return None

    @classmethod
    def _handle_json_data_request(
        cls,
        api: _ApiComponent,
        dst: str,
        payload: DICT_T,
        authority: str,
        bearer: str,
        node: str,
        port: str,
    ) -> Optional[DICT_T]:
        # check api
        url = api.get_url(authority, dst, node, port)
        if url is None:
            return None
        response = _WebAPI.post_json(
            url,
            payload,
            timeout=TIMEOUT_DATA,
            token=bearer,
            verify=cls._is_server_auth(),
        )
        if response is None:
            return None

        return {}

    @classmethod
    def _handle_text_data_request(
        cls,
        api: _ApiComponent,
        dst: str,
        payload: str,
        authority: str,
        bearer: str,
        node: str,
        port: str,
    ) -> Optional[DICT_T]:
        # check api
        url = api.get_url(authority, dst, node, port)
        if url is None:
            return None
        response = _WebAPI.post_text(
            url,
            payload,
            timeout=TIMEOUT_DATA,
            token=bearer,
            verify=cls._is_server_auth(),
        )
        if response is None:
            return None

        return {}

    @classmethod
    def _create_tls_root_certs(
        cls,
        sec_root_certs: CERTS_T = None,
        mng_root_certs: CERTS_T = None,
        ctrl_root_certs: CERTS_T = None,
    ) -> List[bytes]:
        def __is_update(origin: CERTS_T, new: CERTS_T) -> bool:
            if new and origin != new:
                # exclude empty certificate
                if any(c for c in new if c):
                    return True
            return False

        updated = False
        # update root certificate in security
        if __is_update(cls._sec_root_certs, sec_root_certs):
            cls._sec_root_certs = sec_root_certs
            updated = True

        # update root certificate in management
        if __is_update(cls._mng_root_certs, mng_root_certs):
            cls._mng_root_certs = mng_root_certs
            updated = True

        # update root certificate in control
        if __is_update(cls._ctrl_root_certs, ctrl_root_certs):
            cls._ctrl_root_certs = ctrl_root_certs
            updated = True

        # make a list
        if not updated:
            return []

        def __append_cert(target: List[bytes], certs: CERTS_T) -> None:
            if certs:
                target += [_to_pem(val) for val in certs if val]

        root_certs: List[bytes] = list()
        __append_cert(root_certs, cls._sec_root_certs)
        __append_cert(root_certs, cls._mng_root_certs)
        __append_cert(root_certs, cls._ctrl_root_certs)
        return root_certs
