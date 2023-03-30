from logging import INFO, Logger, getLogger
from typing import Any, Dict, List, Optional

from ..crypto._utility import _check_certificate
from ..util._tools import _has_required_keys, _logger_setup
from .common import WebAPIScheme, _is_valid_endpoint

DICT_T = Dict[str, Any]
OPT_LIST_STR_T = Optional[List[str]]
OPT_STR_T = Optional[str]

logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)


class ManagementEndPoint:
    """ManagementEndPoint class"""

    _REQUIRED_KEYS = ["Version", "NICELAEndPoint", "DeviceCertificate"]

    def __init__(self) -> None:
        self._initialize()

    def _initialize(self) -> None:
        self._json: Optional[DICT_T] = None
        self._app_end_point_id: OPT_STR_T = None
        self._app_access_token: OPT_STR_T = None
        self._certificate: OPT_STR_T = None
        self._net_end_point_id: OPT_STR_T = None
        self._scheme: List[WebAPIScheme] = list()
        self._device_certificate: OPT_LIST_STR_T = None

    @property
    def is_available(self) -> bool:
        """bool: get availability of ManagementEndPoint"""
        return self._json is not None

    @property
    def json(self) -> Optional[DICT_T]:
        """dict: set/get JSON Object of ManagementEndPoint"""
        return self._json

    @json.setter
    def json(self, obj: DICT_T) -> None:
        self._initialize()
        try:
            if not _has_required_keys(obj, self._REQUIRED_KEYS):
                raise KeyError("Invalid ManagementEndPoint")
            if not _is_valid_endpoint(obj["NICELAEndPoint"]):
                raise KeyError("Invalid NICELAEndPoint")
            end = obj["NICELAEndPoint"]
            app_endpoint = end["AppEndPoint"]
            net_endpoint = end["NetEndPoint"]
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
            schemes = net_endpoint["Scheme"]
            for scheme in schemes:
                protocol = scheme["Protocol"]
                authority = scheme["Authority"]
                access_token = scheme.get("AccessToken")
                if protocol == "WebAPI":
                    webapi = WebAPIScheme(authority, access_token)
                    self._scheme.append(webapi)

            # DeviceCertificate
            dev_certs: List[str] = obj["DeviceCertificate"]
            if isinstance(dev_certs, list):
                if any(not _check_certificate(cert) for cert in dev_certs):
                    logger.error("Invalid DeviceCertificate")
                else:
                    self._device_certificate = dev_certs
            else:
                logger.error("DeviceCertificate is not a list")

            self._json = obj
        except Exception as e:
            logger.error(e)
            self._initialize()

    @property
    def app_end_point_id(self) -> OPT_STR_T:
        """str: get
        ManagementEndPoint["NICELAEndPoint"]["AppEndPoint"]["EndPointID"]
        """
        return self._app_end_point_id

    @property
    def app_access_token(self) -> OPT_STR_T:
        """str or None: get
        ManagementEndPoint["NICELAEndPoint"]["AppEndPoint"]["AccessToken"]
        """
        return self._app_access_token

    @property
    def certificate(self) -> OPT_STR_T:
        """str or None: get
        ManagementEndPoint["NICELAEndPoint"]["AppEndPoint"]
        ["X.509Certificate"][0]
        """
        return self._certificate

    @property
    def net_end_point_id(self) -> OPT_STR_T:
        """str: get
        ManagementEndPoint["NICELAEndPoint"]["NetEndPoint"]["EndPointID"]
        """
        return self._net_end_point_id

    @property
    def scheme(self) -> List[WebAPIScheme]:
        """list of :obj:`WebAPIScheme`: get
        ManagementEndPoint["NICELAEndPoint"]["NetEndPoint"]["Scheme"]
        """
        return self._scheme

    @property
    def device_certificate(self) -> OPT_LIST_STR_T:
        """list of str or None: get ManagementEndPoint["DeviceCertificate"]"""
        return self._device_certificate
