import sys
from abc import ABC, abstractmethod
from typing import Any, Optional, Tuple, Union

if sys.version_info >= (3, 8):  # pragma: no cover
    from typing import Literal

    FAIL_T = Literal[False]
    SUCCESS_T = Literal[True]
else:  # pragma: no cover
    FAIL_T = bool
    SUCCESS_T = bool

JOSE_RETURN_FAIL = Tuple[FAIL_T, None]
JOSE_RETURN_SUCCESS = Tuple[SUCCESS_T, Any]
JOSE_RETURN_T = Union[JOSE_RETURN_FAIL, JOSE_RETURN_SUCCESS]


class JoseFunction(ABC):
    @abstractmethod
    def __call__(self, agr1: Any) -> Any:
        pass


class JWSVerify(JoseFunction):
    """JWS verification abstract class

    Inherit this class and set its instance to the 1st parameter of
    ApiRequestHandler.parse_cmf_container_object().

    """

    def __call__(self, jws: Any) -> Any:
        return self.verify(jws)

    @abstractmethod
    def verify(self, jws: str) -> Optional[JOSE_RETURN_T]:
        """JWS verification abstract function

        To implement verification of the JWS Compact Serialization.

        Parameters
        ----------
        jws : str
            JWS Compact Serialization string

        Returns
        -------
        bool
            True if successful
        bytes
            JWS Payload or None
        """
        pass


class JWSSign(JoseFunction):
    """JWS signing abstract class

    Inherit this class and set its instance to the 1st parameter of
    ApiRequestHandler.make_cmf_container_object().

    """

    def __call__(self, payload: Any) -> Any:
        return self.sign(payload)

    @abstractmethod
    def sign(self, payload: bytes) -> Optional[JOSE_RETURN_T]:
        """JWS signing abstract function

        To implement signing of the presented `bytes`.

        Parameters
        ----------
        payload : bytes
            an arbitrary value

        Returns
        -------
        bool
            True if successful
        str
            JWS Compact Serialization string or None
        """
        pass


class JWEDecrypt(JoseFunction):
    """JWE decrypt abstract class

    Inherit this class and set its instance to the 1st parameter of
    ApiRequestHandler.parse_cmf_request_object().

    """

    def __call__(self, jwe: Any) -> Any:
        return self.decrypt(jwe)

    @abstractmethod
    def decrypt(self, jwe: str) -> Optional[JOSE_RETURN_T]:
        """JWE decryption abstract function

        To implement decryption of the JWE Compact Serialization.

        Parameters
        ----------
        jwe : str
            JWE Compact Serialization string

        Returns
        -------
        bool
           True if successful

        bytes
            Plain data or None
        """
        pass


class JWEEncrypt(JoseFunction):
    """JWE encrypt abstract class

    Inherit this class and set its instance to the 2nd parameter of
    ApiRequestHandler.make_cmf_container_object().

    """

    def __call__(self, plaintext: Any) -> Any:
        return self.encrypt(plaintext)

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> Optional[JOSE_RETURN_T]:
        """JWE encrypt abstract function

        To implement encryption of data `bytes`.

        Parameters
        ----------
        plaintext : bytes
            an arbitrary plain data

        Returns
        -------
        bool
            True if successful
        str
            JWE Compact Serialization string or None
        """
        pass
