from logging import INFO, Logger, getLogger
from typing import Any, Dict, List, Optional

from ..crypto._utility import _check_certificate
from ..util._tools import _has_required_keys, _logger_setup
from .common import WebAPIScheme, _is_valid_endpoint

DICT_T = Dict[str, Any]

logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)


class ManagementObject:
    """Device Management Object class"""

    _REQUIRED_KEYS = [
        "Version",
        "DeviceID",
        "NICEAS",
        "AllowedTLSRootCertificates",
    ]
    _NICEAS_KEYS = ["NICEASID", "NICEASEndPoint"]

    def __init__(self) -> None:
        self._initialize()

    def _initialize(self) -> None:
        self._json: Optional[DICT_T] = None
        self._nice_as_id: Optional[str] = None
        self._app_end_point_id: Optional[str] = None
        self._app_access_token: Optional[str] = None
        self._certificate: Optional[str] = None
        self._net_end_point_id: Optional[str] = None
        self._scheme: List[WebAPIScheme] = list()
        self._allowed_tls_root_certificates: Optional[List[str]] = None
        self._device_certificate: Optional[List[str]] = None

    @property
    def is_available(self) -> bool:
        """bool: get availability of ManagementObject"""
        return self._json is not None

    @property
    def json(self) -> Optional[DICT_T]:
        """dict: set/get JSON Object of ManagementObject"""
        return self._json

    @json.setter
    def json(self, obj: DICT_T) -> None:
        self._initialize()
        try:
            if not _has_required_keys(obj, self._REQUIRED_KEYS):
                raise KeyError("Invalid ManagementObject")
            if not _has_required_keys(obj["NICEAS"], self._NICEAS_KEYS):
                raise KeyError("Invalid NICEAS")
            nice_as: DICT_T = obj["NICEAS"]
            if not _is_valid_endpoint(nice_as["NICEASEndPoint"]):
                raise KeyError("Invalid NICEASEndPoint")
            self._nice_as_id = nice_as["NICEASID"]
            nice_as_endpoint = nice_as["NICEASEndPoint"]
            app_endpoint = nice_as_endpoint["AppEndPoint"]
            net_endpoint = nice_as_endpoint["NetEndPoint"]
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
                access_token: Optional[str] = scheme.get("AccessToken")
                if protocol == "WebAPI":
                    webapi = WebAPIScheme(authority, access_token)
                    self._scheme.append(webapi)

            # AllowedTLSRootCertificates
            tls_certs: List[str] = obj["AllowedTLSRootCertificates"]
            if isinstance(tls_certs, list):
                if any(not _check_certificate(cert) for cert in tls_certs):
                    logger.error("Invalid AllowedTLSRootCertificates")
                else:
                    self._allowed_tls_root_certificates = tls_certs
            else:
                logger.error("AllowedTLSRootCertificates is not a list")

            # DeviceCertificate
            dev_certs: Optional[List[str]] = obj.get("DeviceCertificate")
            if isinstance(dev_certs, list):
                if any(not _check_certificate(cert) for cert in dev_certs):
                    logger.error("Invalid DeviceCertificate")
                else:
                    self._device_certificate = dev_certs

            self._json = obj
        except Exception as e:
            logger.error(e)
            self._initialize()

    @property
    def nice_as_id(self) -> Optional[str]:
        """str: get ManagementObject["NICEAS"]["NICEASID"]"""
        return self._nice_as_id

    @property
    def app_end_point_id(self) -> Optional[str]:
        """str: get
        ManagementObject["NICEAS"]["NICEASEndPoint"]["AppEndPoint"]
        ["EndPointID"]
        """
        return self._app_end_point_id

    @property
    def app_access_token(self) -> Optional[str]:
        """str or None: get
        ManagementObject["NICEAS"]["NICEASEndPoint"]["AppEndPoint"]
        ["AccessToken"]
        """
        return self._app_access_token

    @property
    def certificate(self) -> Optional[str]:
        """str or None: get
        ManagementObject["NICEAS"]["NICEASEndPoint"]["AppEndPoint"]
        ["X.509Certificate"][0]
        """
        return self._certificate

    @property
    def net_end_point_id(self) -> Optional[str]:
        """str: get
        ManagementObject["NICEAS"]["NICEASEndPoint"]["NetEndPoint"]
        ["EndPointID"]
        """
        return self._net_end_point_id

    @property
    def scheme(self) -> List[WebAPIScheme]:
        """list of :obj:`WebAPIScheme`: get
        ManagementObject["NICEAS"]["NICEASEndPoint"]["NetEndPoint"]["Scheme"]
        """
        return self._scheme

    @property
    def allowed_tls_root_certificates(self) -> Optional[List[str]]:
        """list of str: get ManagementObject["AllowedTLSRootCertificates"]"""
        return self._allowed_tls_root_certificates

    @property
    def device_certificate(self) -> Optional[List[str]]:
        """list of str or None: get ManagementObject["DeviceCertificate"]"""
        return self._device_certificate
