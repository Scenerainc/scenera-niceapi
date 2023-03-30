from logging import INFO, Logger, getLogger
from typing import Any, Dict, List, Optional

from ..crypto._utility import _check_certificate
from ..util._tools import _has_required_keys, _is_list, _logger_setup
from .common import WebAPIScheme, _is_valid_endpoint

DICT_T = Dict[str, Any]

logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)


class ControlObject:
    """Device Control Object Class"""

    _REQUIRED_KEYS = ["Version", "DeviceID", "ControlEndPoints"]

    def __init__(self) -> None:
        self._initialize()

    def _initialize(self) -> None:
        self._json: Optional[DICT_T] = None
        self._app_end_point_id: Optional[str] = None
        self._app_access_token: Optional[str] = None
        self._certificate: Optional[str] = None
        self._net_end_point_id: Optional[str] = None
        self._node_id: Optional[str] = None
        self._scheme: List[WebAPIScheme] = list()
        self._allowed_tls_root_certificates: Optional[List[str]] = None

    @property
    def is_available(self) -> bool:
        """bool: get availability of ControlObject"""
        return self._json is not None

    @property
    def json(self) -> Optional[DICT_T]:
        """dict: set/get JSON Object of ControlObject"""
        return self._json

    @json.setter
    def json(self, obj: DICT_T) -> None:
        self._initialize()
        try:
            if not _has_required_keys(obj, self._REQUIRED_KEYS):
                raise KeyError("Invalid ControlObject")
            if not _is_list(obj, "ControlEndPoints"):
                raise ValueError("Invalid ControlEndPoints")
            for endpoint in obj["ControlEndPoints"]:
                if not _is_valid_endpoint(endpoint):
                    raise KeyError("Invalid ControlEndPoints")
            control_endpoint = obj["ControlEndPoints"][0]
            app_endpoint = control_endpoint["AppEndPoint"]
            net_endpoint = control_endpoint["NetEndPoint"]
            self._app_end_point_id = app_endpoint["EndPointID"]
            self._app_access_token = app_endpoint.get("AccessToken")

            # AppEndPoint - X.509Certificate
            x509: Optional[List[str]] = app_endpoint.get("X.509Certificate")
            if x509 and isinstance(x509, list):
                if any(not _check_certificate(cert) for cert in x509):
                    logger.error("Invalid X.509Certificate")
                else:
                    self._certificate = x509[0]
            else:
                logger.error("X.509Certificate is not a valid list")

            self._net_end_point_id = net_endpoint["EndPointID"]
            self._node_id = net_endpoint.get("NodeID")
            schemes = net_endpoint["Scheme"]
            for scheme in schemes:
                protocol = scheme["Protocol"]
                authority = scheme["Authority"]
                access_token = scheme.get("AccessToken")
                if protocol == "WebAPI":
                    webapi = WebAPIScheme(authority, access_token)
                    self._scheme.append(webapi)

            # AllowedTLSRootCertificates
            tls_certs: Optional[List[str]] = obj.get(
                "AllowedTLSRootCertificates"
            )
            if isinstance(tls_certs, list):
                if any(not _check_certificate(cert) for cert in tls_certs):
                    logger.error("Invalid AllowedTLSRootCertificates")
                else:
                    self._allowed_tls_root_certificates = tls_certs

            self._json = obj
        except Exception as e:
            logger.error(e)
            self._initialize()

    @property
    def app_end_point_id(self) -> Optional[str]:
        """str: get
        ControlObject["ControlEndPoints"][0]["AppEndPoint"]["EndPointID"]
        """
        return self._app_end_point_id

    @property
    def app_access_token(self) -> Optional[str]:
        """str or None: get
        ControlObject["ControlEndPoints"][0]["AppEndPoint"]["AccessToken"]
        """
        return self._app_access_token

    @property
    def certificate(self) -> Optional[str]:
        """str or None: get
        ControlObject["ControlEndPoints"][0]["AppEndPoint"]
        ["X.509Certificate"][0]
        """
        return self._certificate

    @property
    def net_end_point_id(self) -> Optional[str]:
        """str: get
        ControlObject["ControlEndPoints"][0]["NetEndPoint"]["EndPointID"]
        """
        return self._net_end_point_id

    @property
    def node_id(self) -> Optional[str]:
        """str or None: get
        ControlObject["ControlEndPoints"][0]["NetEndPoint"]["NodeID"]
        """
        return self._node_id

    @property
    def scheme(self) -> List[WebAPIScheme]:
        """list of :obj:`WebAPIScheme`: get
        ControlObject["ControlEndPoints"][0]["NetEndPoint"]["Scheme"]
        """
        return self._scheme

    @property
    def allowed_tls_root_certificates(self) -> Optional[List[str]]:
        """list of str or None: get
        ControlObject["AllowedTLSRootCertificates"]"""
        return self._allowed_tls_root_certificates
