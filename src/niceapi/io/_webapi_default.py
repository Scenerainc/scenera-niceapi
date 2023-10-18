import os
import ssl
import time
import traceback
from logging import INFO, Logger, getLogger
from typing import Any, Dict, Optional, Union

import requests
import urllib3
from requests.adapters import HTTPAdapter

# disable warning
from urllib3.exceptions import InsecureRequestWarning
from urllib3.poolmanager import PoolManager
from urllib3.util.ssl_ import create_urllib3_context

from ..util._tools import _file_update, _logger_setup
from .webapi_base import BODY_T, JSON_T, TLS_ROOT_CERTS_T, WebAPIBase

VERIFY_CERT_T = Union[str, bool, None]

urllib3.disable_warnings(InsecureRequestWarning)

CIPHERS: str = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "DHE-RSA-AES256-GCM-SHA384"
)
ROOT_CERT_PATH: str = "tls-root-cert.pem"

logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)


class _TLSAdapter(HTTPAdapter):
    def __init__(self, cert_reqs: ssl.VerifyMode) -> None:
        self.cert_reqs = cert_reqs
        super().__init__()

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = False,
        **pool_kwargs: Any,
    ) -> None:
        context = create_urllib3_context(
            ssl_version=ssl.PROTOCOL_TLSv1_2,
            cert_reqs=self.cert_reqs,
            ciphers=CIPHERS,
        )
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=context,
            **pool_kwargs,
        )


class _WebAPIDefault(WebAPIBase):
    _MAX_REDIRECT = 5
    _MAX_RETRY = 1
    _TIMEOUT = 60
    _VERIFY = ROOT_CERT_PATH

    _SUPPORT_REDIRECT_CODE = [301, 307, 308]

    def post(
        self,
        url: str,
        headers: JSON_T,
        body: BODY_T,
        timeout: int = _TIMEOUT,
        token: Optional[str] = None,
        verify: bool = True,
    ) -> Optional[JSON_T]:
        cert_reqs = ssl.CERT_REQUIRED
        verify_cert: VERIFY_CERT_T = self._VERIFY if verify else False
        if verify is False:
            cert_reqs = ssl.CERT_NONE

        response_json = None
        session = requests.Session()
        adapter = _TLSAdapter(cert_reqs)
        session.mount("https://", adapter)
        for i in range(self._MAX_RETRY):
            try:
                logger.info(f"POST:{url}")
                start_time = time.time()
                response = session.request(
                    "POST",
                    url=url,
                    data=body,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=verify_cert,
                )
                elapsed_time = time.time() - start_time
                command = os.path.basename(url)
                logger.info(f"{response}: {command} took {elapsed_time}s")
                if response.status_code == 200:
                    try:
                        response_json = response.json()
                    except ValueError:
                        response_json = {}
                    break
                elif response.status_code in self._SUPPORT_REDIRECT_CODE:
                    new_response = self._post_redirect(
                        session,
                        url,
                        verify_cert,
                        body,
                        headers,
                        timeout,
                        response,
                    )
                    if new_response.status_code == 200:
                        try:
                            response_json = new_response.json()
                        except ValueError:
                            response_json = {}
                        break
                    else:
                        logger.info(new_response.text)
                else:
                    logger.info(response.text)
            except requests.exceptions.RequestException as e:
                logger.error(f"RequestException: {e}")
            except Exception as e:
                logger.error(traceback.format_exc())
                logger.error(e)

        return response_json

    def update_root_cert(
        self, tls_root_certs: Optional[TLS_ROOT_CERTS_T] = None
    ) -> None:
        # Don't update if root_certs is empty
        if not tls_root_certs:
            return

        # Set data to write
        data = b""
        for cert in tls_root_certs:
            data = data + cert

        # Wite to PEM file
        if data:
            _file_update(path=ROOT_CERT_PATH, data=data)

    def _post_redirect(
        self,
        session: requests.Session,
        url: str,
        verify: VERIFY_CERT_T,
        body: BODY_T,
        headers: Dict[str, Any],
        timeout: int,
        response: requests.Response,
    ) -> requests.Response:
        for i in range(self._MAX_REDIRECT):
            logger.info(response.headers)
            if "Location" in response.headers:
                redirect_url = response.headers["Location"]
                if redirect_url:
                    url = redirect_url
                else:
                    logger.info("no redirect_url")
                    break
            else:
                logger.info("no Location")
                break
            logger.info(f"POST:{url}")
            start_time = time.time()
            response = session.request(
                "POST",
                url=url,
                data=body,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
                verify=verify,
            )
            elapsed_time = time.time() - start_time
            command = os.path.basename(url)
            logger.info(f"{response}: {command} took {elapsed_time}s")
            if response.status_code not in self._SUPPORT_REDIRECT_CODE:
                break
        return response
