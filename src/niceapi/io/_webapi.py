import json
import threading
from logging import DEBUG, Logger, getLogger
from typing import Optional

from ..util._tools import _logger_setup
from .webapi_base import BODY_T, JSON_T, TLS_ROOT_CERTS_T, WebAPIBase

logger: Logger = getLogger(__name__)
_logger_setup(logger, DEBUG)


def _get_webapi_default() -> WebAPIBase:
    # Import of _WebAPIDefault will fail if requests library is not installed
    try:
        from ._webapi_default import _WebAPIDefault

        return _WebAPIDefault()
    except ImportError:
        logger.info("No default WebAPI")

        class _WebAPIDummy(WebAPIBase):
            def post(
                self,
                url: str,
                headers: JSON_T,
                body: BODY_T,
                timeout: int = 1,
                token: Optional[str] = None,
                verify: bool = True,
            ) -> Optional[JSON_T]:
                logger.error("No WebAPI")
                return None

            def update_root_cert(
                self, tls_root_certs: Optional[TLS_ROOT_CERTS_T] = None
            ) -> None:
                logger.error("No WebAPI")

        return _WebAPIDummy()


class _WebAPI:
    _TIMEOUT = 60
    _semaphore: Optional[threading.BoundedSemaphore] = None
    _webapi = _get_webapi_default()

    @classmethod
    def set_max_connection(cls, limit: int) -> None:
        if limit > 0:
            cls._semaphore = threading.BoundedSemaphore(limit)
        else:
            cls._semaphore = None

    @classmethod
    def set_webapi(cls, webapi: WebAPIBase) -> None:
        cls._webapi = webapi

    @classmethod
    def post_json(
        cls,
        url: str,
        body: JSON_T,
        timeout: int = _TIMEOUT,
        token: Optional[str] = None,
        verify: bool = True,
    ) -> Optional[JSON_T]:
        headers = {"Content-type": "application/json"}
        if token:
            headers = {
                "Authorization": "Bearer " + token,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        data = json.dumps(body).encode()
        if cls._semaphore is not None:
            with cls._semaphore:
                response = cls._webapi.post(
                    url, headers, data, timeout, token, verify
                )
        else:
            response = cls._webapi.post(
                url, headers, data, timeout, token, verify
            )
        return response

    @classmethod
    def post_text(
        cls,
        url: str,
        body: str,
        timeout: int = _TIMEOUT,
        token: Optional[str] = None,
        verify: bool = True,
    ) -> Optional[JSON_T]:
        headers = {"Content-type": "text/plain"}
        if token:
            headers = {
                "Authorization": "Bearer " + token,
                "Accept": "application/json",
                "Content-Type": "text/plain",
            }
        data = body.encode()
        if cls._semaphore is not None:
            with cls._semaphore:
                response = cls._webapi.post(
                    url, headers, data, timeout, token, verify
                )
        else:
            response = cls._webapi.post(
                url, headers, data, timeout, token, verify
            )
        return response

    @classmethod
    def update_root_cert(
        cls, tls_root_certs: Optional[TLS_ROOT_CERTS_T] = None
    ) -> None:
        cls._webapi.update_root_cert(tls_root_certs)
