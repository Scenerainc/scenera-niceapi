from logging import INFO, Logger, getLogger
from typing import Any, Dict, List, Optional, Union

from ..crypto._utility import _check_certificate
from ..util._tools import _has_required_keys, _logger_setup
from .common import WebAPIScheme, _is_valid_net_endpoint

DICT_T = Dict[str, Any]

logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)


class DeviceSecurityObject:
    """DeviceSecurityObject class"""

    _REQUIRED_KEYS = [
        "Version",
        "DeviceCertificate",
        "DeviceID",
        "DevicePassword",
        "DevicePrivateKey",
        "AllowedTLSRootCertificates",
        "NICELARootCertificate",
        "NICELAEndPoint",
    ]

    _PRIVATE_KEYS = ["EncryptionKeyID", "EncryptedKey"]

    def __init__(self) -> None:
        self._initialize()

    def _initialize(self) -> None:
        self._json: Optional[DICT_T] = None
        self._device_id: Optional[str] = None
        self._device_private_key: Union[DICT_T, str, None] = None
        self._device_certificate: Optional[List[str]] = None
        self._nice_la_root_certificate: Optional[List[str]] = None
        self._net_end_point_id: Optional[str] = None
        self._scheme: List[WebAPIScheme] = list()
        self._allowed_tls_root_certificates: Optional[List[str]] = None

    @property
    def is_available(self) -> bool:
        """bool: get availability of DeviceSecurityObject"""
        return self._json is not None

    @property
    def json(self) -> Optional[DICT_T]:
        """dict: set/get JSON Object of DeviceSecurityObject"""
        return self._json

    @json.setter
    def json(self, obj: DICT_T) -> None:
        self._initialize()
        try:
            if not _has_required_keys(obj, self._REQUIRED_KEYS):
                raise KeyError("Invalid DeviceSecurityObject")
            private_key = obj["DevicePrivateKey"]
            if not _has_required_keys(private_key, self._PRIVATE_KEYS):
                raise KeyError("Invalid DevicePrivateKey")
            if not _is_valid_net_endpoint(obj["NICELAEndPoint"]):
                raise KeyError("Invalid NICELAEndPoint")
            self._device_id = obj["DeviceID"]
            # AllowedTLSRootCertificates
            tls_certs: List[str] = obj["AllowedTLSRootCertificates"]
            if tls_certs and isinstance(tls_certs, list):
                if any(not _check_certificate(cert) for cert in tls_certs):
                    logger.error("Invalid AllowedTLSRootCertificates")
                else:
                    self._allowed_tls_root_certificates = tls_certs
            else:
                logger.error("AllowedTLSRootCertificates is not a valid list")
            # NICELARootCertificate
            la_certs: List[str] = obj["NICELARootCertificate"]
            if la_certs and isinstance(la_certs, list):
                if any(not _check_certificate(cert) for cert in la_certs):
                    logger.error("Invalid NICELARootCertificate")
                else:
                    self._nice_la_root_certificate = la_certs
            else:
                logger.error("NICELARootCertificate is not a valid list")
            # DeviceCertificate
            dev_certs: List[str] = obj["DeviceCertificate"]
            if dev_certs and isinstance(dev_certs, list):
                if any(not _check_certificate(cert) for cert in dev_certs):
                    logger.error("Invalid DeviceCertificate")
                else:
                    self._device_certificate = dev_certs
            else:
                logger.error("DeviceCertificate is not a valid list")

            # NICELAEndPoint
            nice_la_endpoint = obj["NICELAEndPoint"]
            self._net_end_point_id = nice_la_endpoint["EndPointID"]
            schemes = nice_la_endpoint["Scheme"]
            for scheme in schemes:
                protocol = scheme["Protocol"]
                authority = scheme["Authority"]
                access_token = scheme.get("AccessToken")
                if protocol == "WebAPI":
                    webapi = WebAPIScheme(authority, access_token)
                    self._scheme.append(webapi)

            self._json = obj

        except Exception as e:
            logger.error(e)
            self._initialize()

    @property
    def device_id(self) -> Optional[str]:
        """str: get DeviceSecurityObject["DeviceID"]"""
        return self._device_id

    @property
    def device_private_key(self) -> Union[DICT_T, str, None]:
        """dict: set/get DevicePrivateKey"""
        return self._device_private_key

    @device_private_key.setter
    def device_private_key(self, key: Union[DICT_T, str]) -> None:
        self._device_private_key = key

    @property
    def device_certificate(self) -> Optional[List[str]]:
        """str: get DeviceSecurityObject["DeviceCertificate"]"""
        return self._device_certificate

    @property
    def nice_la_root_certificate(self) -> Optional[List[str]]:
        """list of str: get
        DeviceSecurityObject["NICELARootCertificate"]
        """
        return self._nice_la_root_certificate

    @property
    def net_end_point_id(self) -> Optional[str]:
        """str: get DeviceSecurityObject["NICELAEndPoint"]["EndPointID"]"""
        return self._net_end_point_id

    @property
    def scheme(self) -> List[WebAPIScheme]:
        """list of :obj:`WebAPIScheme`: get
        DeviceSecurityObject["NICELAEndPoint"]["Scheme"]
        """
        return self._scheme

    @property
    def allowed_tls_root_certificates(self) -> Optional[List[str]]:
        """list of str: get
        DeviceSecurityObject["AllowedTLSRootCertificates"]
        """
        return self._allowed_tls_root_certificates
