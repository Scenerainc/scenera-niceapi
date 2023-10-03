# import base64
import json
from base64 import b64decode
from datetime import datetime
from logging import INFO, Logger, getLogger
from typing import Any, Callable, Dict, List, Optional, Union, cast

from authlib.jose import (
    ECKey,
    JsonWebEncryption,
    JsonWebKey,
    JsonWebSignature,
    RSAKey,
)
from authlib.jose.rfc7517 import AsymmetricKey
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
)

from ..util._tools import _base64url_decode, _logger_setup
from ._utility import _to_b64
from .base import JOSE_RETURN_T, JWEDecrypt, JWEEncrypt, JWSSign, JWSVerify

DICT_T = Dict[str, Any]
SIGN_CRT_T = Union[List[str], str, None]

logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)


def _verifying(key: Any, cert: x509.Certificate) -> None:
    def _rsa_args(C: x509.Certificate) -> List[Any]:
        return [padding.PKCS1v15(), C.signature_hash_algorithm]

    def _ec_args(C: x509.Certificate) -> List[Any]:
        return [ec.ECDSA(C.signature_hash_algorithm)]  # type: ignore

    args = [cert.signature, cert.tbs_certificate_bytes]
    d: Dict[type, Callable[[x509.Certificate], List[Any]]] = {
        rsa.RSAPublicKey: _rsa_args,
        ec.EllipticCurvePublicKey: _ec_args,
    }

    for key_t, func in d.items():
        if isinstance(key, key_t):
            args += func(cert)
            break
    key.verify(*args)


class Verify(JWSVerify):
    """:obj:`JWSVerify` subclass implemented with Authlib

    Users can implement their own subclass with another library

    and set it to the parameter of :obj:`ApiRequestHandler` method
    """

    def __init__(
        self, verify: bool, la_root_cert: Union[str, List[str], None] = None
    ) -> None:
        """Constructor

        Parameters
        ----------
        verify : bool
            True when verifying the trust chain of certificates in x5c.
        la_root_cert : Optional[List[str]]
            NICE LA root certificate. It is mandatory when verify is True.
        """
        self.__verify = verify
        self._la_root_cert_key: Any = None
        if la_root_cert:
            if isinstance(la_root_cert, str):
                root_certificate = x509.load_der_x509_certificate(
                    b64decode(la_root_cert), default_backend()
                )
            if isinstance(la_root_cert, list):
                root_certificate = x509.load_der_x509_certificate(
                    b64decode(la_root_cert[0]), default_backend()
                )
            self._la_root_cert_key = root_certificate.public_key()

    def __get_public_key(self, certs: List[str]) -> Any:
        public_key: Optional[CertificatePublicKeyTypes] = None
        issuer: Optional[x509.Certificate] = None
        target: Optional[x509.Certificate] = None
        first_public_key: Optional[
            CertificatePublicKeyTypes
        ] = x509.load_der_x509_certificate(
            b64decode(certs[0]), default_backend()
        ).public_key()
        try:
            now = datetime.utcnow()
            for c in certs:
                issuer = x509.load_der_x509_certificate(
                    b64decode(c), default_backend()
                )
                before = issuer.not_valid_before
                after = issuer.not_valid_after
                if not (before < now < after):
                    logger.error(
                        f"Out of date! now:{now}, "
                        f"before:{before}, after:{after}"
                    )

                    if not self.__verify:
                        logger.error("Skip expiry of x5c.")
                        return first_public_key

                    return None

                if not public_key:
                    public_key = issuer.public_key()
                else:
                    issuer_key = issuer.public_key()
                    _verifying(issuer_key, target)  # type: ignore

                target = issuer

            _verifying(self._la_root_cert_key, issuer)  # type: ignore

        except Exception as e:
            logger.error(e)
            if not self.__verify:
                logger.error("Skip x5c verification errors.")
                return first_public_key
            return None

        return public_key

    def verify(self, jws: str) -> Optional[JOSE_RETURN_T]:
        """Verify JWS Compact Serialization

        Parameters
        ----------
        jws : str
            JWS Compact Serialization

        Returns
        -------
        bool
            True if successful
        bytes
            JWS Payload or None
        """
        try:
            # deserialize
            try:
                signing_input, _ = jws.rsplit(".", 1)
                protected_segment, _ = signing_input.split(".", 1)
            except ValueError:
                logger.error("jws segments error")
                return False, None

            protected = json.loads(
                _base64url_decode(protected_segment).decode()
            )

            # get public key from certificate
            certs = protected["x5c"]
            public_key = self.__get_public_key(certs)

            # JWS verify
            try:
                jws_token = JsonWebSignature().deserialize_compact(
                    jws, public_key
                )
            except Exception:
                logger.error("JwsVerify error")
                return False, None

            return True, jws_token["payload"]
        except Exception as e:
            logger.error(e)

        return False, None


class Sign(JWSSign):
    """:obj:`JWSSign` subclass implemented with Authlib

    Users can implement their own subclass with another library

    and set it to the parameter of :obj:`ApiRequestHandler` method
    """

    _jws_rsa_algorithm = "PS256"

    def __init__(
        self, kid: str, key: Union[str, DICT_T], crt: SIGN_CRT_T
    ) -> None:
        """Constructor

        Parameters
        ----------
        kid : str
            Key ID

        key: str or dict
            Private key in PEM format

        crt: str or list of str or None
            Certificate in Base64 format
        """
        self._key_id = kid
        self._private_key: AsymmetricKey = JsonWebKey.import_key(key)
        self._certificate: SIGN_CRT_T = crt

    def update_certificate(self, crt: SIGN_CRT_T) -> None:
        """Update certificate for sign

        Parameters
        ----------
        crt : str or list of str
            Certificate in Base64 format

        Returns
        -------
        None
        """
        if crt:
            self._certificate = crt

    def sign(self, payload: bytes) -> JOSE_RETURN_T:
        """Sign data bytes

        Parameters
        ----------
        payload : bytes
            Arbitrary value

        Returns
        -------
        bool
            True if successful
        str
            JWS Compact Serialization string or None
        """
        try:
            # JWS signing
            x5c: Any
            if isinstance(self._certificate, list):
                x5c = self._certificate
            else:
                x5c = [self._certificate]
            protected = {"kid": self._key_id, "x5c": x5c}
            if isinstance(self._private_key, ECKey):
                protected["alg"] = "ES256"
            elif isinstance(self._private_key, RSAKey):
                protected["alg"] = self._jws_rsa_algorithm
            else:
                logger.error("key_type error")
                return False, None

            jws_token: str = (
                JsonWebSignature()
                .serialize_compact(protected, payload, self._private_key)
                .decode()
            )
            return True, jws_token
        except Exception as e:
            logger.error(e)

        return False, None


class Decrypt(JWEDecrypt):
    """:obj:`JWEDecrypt` subclass implemented with Authlib

    Users can implement their own subclass with another library

    and set it to the parameter of :obj:`ApiRequestHandler` method
    """

    def __init__(self, key: Union[str, DICT_T]) -> None:
        """Constructor

        Parameters
        ----------
        key: str or dict
            Private key in PEM format
        """
        self._private_key: AsymmetricKey = JsonWebKey.import_key(key)

    def decrypt(self, jwe: str) -> JOSE_RETURN_T:
        """Decrypt a compact JWE

        Parameters
        ----------
        jwe : str
            JWE Compact Serialization

        Returns
        -------
        bool
           True if successful

        bytes
            Plain data or None
        """
        try:
            # JWE decrypt
            jwe_token = JsonWebEncryption().deserialize_compact(
                jwe, self._private_key
            )
            return True, jwe_token["payload"]
        except Exception as e:
            logger.error(e)

        return False, None


class Encrypt(JWEEncrypt):
    """:obj:`JWEEncrypt` subclass implemented with Authlib

    Users can implement their own subclass with another library

    and set it to the parameter of :obj:`ApiRequestHandler` method
    """

    _jwe_rsa_algorithm = "RSA1_5"

    def __init__(self, kid: Optional[str], crt: Optional[str]) -> None:
        """Constructor

        Parameters
        ----------
        kid: str
            Key ID

        crt: str
            Certificate in Base64 format
        """
        self._key_id = kid
        self._certificate = crt

    def encrypt(self, plaintext: bytes) -> JOSE_RETURN_T:
        """Encrypt data bytes

        Parameters
        ----------
        plaintext : bytes
            Arbitrary plain data

        Returns
        -------
        bool
            True if successful
        str
            JWE Compact Serialization string or None
        """
        try:
            if self._certificate is None:
                logger.error("certificate is None")
                return False, None
            # get public key from certificate
            public_key = x509.load_der_x509_certificate(
                b64decode(self._certificate)
            ).public_key()

            # JWE encryption
            protected = {"enc": "A256GCM", "kid": self._key_id}
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                protected["alg"] = "ECDH-ES+A256KW"
            elif isinstance(public_key, rsa.RSAPublicKey):
                protected["alg"] = self._jwe_rsa_algorithm
            else:
                logger.error("key_type error")
                return False, None
            jwe_token = (
                JsonWebEncryption()
                .serialize_compact(protected, plaintext, public_key)
                .decode()
            )
            return True, jwe_token
        except Exception as e:
            logger.error(e)

        return False, None


class JoseOps:
    """JOSE Operations class

    register key and certificate with key ID, then

    instance of :obj:`Verify`, :obj:`Sign`, :obj:`Decrypt`, and :obj:`Encrypt`

    are set for use with :obj:`ApiRequestHandler`
    """

    def __init__(
        self,
        verify: bool = False,
        la_root_cert: Union[str, List[str], None] = None,
    ) -> None:
        if isinstance(la_root_cert, str):
            la_root_cert = _to_b64(la_root_cert)
        elif isinstance(la_root_cert, list):
            la_root_cert = _to_b64(la_root_cert[0])
        self._jws_verify = Verify(verify, la_root_cert)
        self._jws_sign: DICT_T = dict()
        self._jwe_decrypt: DICT_T = dict()
        self._jwe_encrypt: DICT_T = dict()

    @property
    def verify(self) -> Verify:
        """:obj:`Verify`: get the instance of :obj:`Verify`"""
        return self._jws_verify

    @property
    def sign_ops(self) -> DICT_T:
        """dict: get dictionary whose key is key ID,
        and whose value is the instance of :obj:`Sign`
        """
        return self._jws_sign

    @property
    def decrypt_ops(self) -> DICT_T:
        """dict: get dictionary whose key is key ID,
        and whose value is the instance of :obj:`Decrypt`
        """
        return self._jwe_decrypt

    @property
    def encrypt_ops(self) -> DICT_T:
        """dict: get dictionary whose key is key ID,
        and whose value is the instance of :obj:`Encrypt`
        """
        return self._jwe_encrypt

    def register_la_cert(self, crt: str) -> None:
        self._jws_verify = Verify(True, [_to_b64(crt)])

    def register_local_key_cert(
        self, kid: str, key: Union[str, DICT_T], crt: Union[List[str], str]
    ) -> None:
        """Register the local key and certificate

        Parameters
        ----------
        kid: str
            Key ID

        key: str or dict
            Private key in PEM format

        crt: str
            Certificate in PEM format

        Returns
        -------
        None
        """
        B64 = _to_b64
        signing = [B64(c) for c in crt] if isinstance(crt, list) else B64(crt)

        self._jws_sign[kid] = Sign(kid, key, cast(SIGN_CRT_T, signing))
        self._jwe_decrypt[kid] = Decrypt(key)

    def register_remote_cert(self, kid: str, crt: str) -> None:
        """Register the remote certificate

        Parameters
        ----------
        kid: str
            Key ID

        crt: str
            Certificate in PEM format

        Returns
        -------
        None
        """
        self._jwe_encrypt[kid] = Encrypt(kid, _to_b64(crt))


def _jwe_encrypt(
    data: bytes, alg: str, enc: str, kid: str, key: bytes
) -> Optional[str]:
    """Encrypt by the common key"""
    try:
        protected = {"alg": alg, "enc": enc, "kid": kid}
        jwe_token = JsonWebEncryption().serialize_compact(protected, data, key)
        ciphertext: str = jwe_token.decode()
        return ciphertext
    except Exception as e:
        logger.error(e)

    return None


def _jwe_decrypt(jwe: bytes, key: bytes) -> Optional[str]:
    """Decrypt by the common key"""
    try:
        jwe_token = JsonWebEncryption().deserialize_compact(jwe, key)
        plaintext: str = jwe_token["payload"]
        return plaintext
    except Exception as e:
        logger.error(e)

    return None
