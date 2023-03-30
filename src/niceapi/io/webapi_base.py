from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

BODY_T = bytes
JSON_T = Dict[str, Any]
TLS_ROOT_CERTS_T = List[bytes]


class WebAPIBase(ABC):
    """Web API abstract class

    Inherit this class and register its instance by ApiRequest.set_webapi()

    """

    _TIMEOUT = 60

    @abstractmethod
    def post(
        self,
        url: str,
        headers: JSON_T,
        body: BODY_T,
        timeout: int = _TIMEOUT,
        token: Optional[str] = None,
        verify: bool = True,
    ) -> Optional[JSON_T]:
        """HTTP/TLS POST function

        To implement HTTP/TLS POST method.

        Parameters
        ----------
        url : str
            URL string

        headers : dict
            header JSON Object

        body : bytes
            message body bytes

        timeout : int
            timeout value (default: 60)

        token : str
            bearer token

        verify : bool
            True if enabling TLS server authentication

        Returns
        -------
        dict
            JSON response
        """
        pass

    @abstractmethod
    def update_root_cert(
        self, tls_root_certs: Optional[TLS_ROOT_CERTS_T] = None
    ) -> None:
        """Update function of the root certificate

        To implement update of the root certificates.

        Parameters
        ----------
        tls_root_certs : list
            list of PEM bytes

        Returns
        -------
        None
        """
        pass
