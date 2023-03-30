import base64
import secrets
from logging import INFO, Logger, getLogger
from typing import Optional, Union

from Cryptodome.Cipher import AES
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..util._tools import _logger_setup

logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)


def _check_certificate(cert: Optional[str]) -> bool:
    try:
        if cert:
            x509.load_der_x509_certificate(base64.b64decode(cert))
        return True
    except Exception as e:
        logger.error(e)
    return False


def _to_b64(cert: Union[str, bytes]) -> str:
    if isinstance(cert, bytes):
        cert = cert.decode()
    cert = cert.replace("-----BEGIN CERTIFICATE-----", "")
    cert = cert.replace("-----END CERTIFICATE-----", "")
    cert = cert.replace("\n", "")
    return cert


def _to_pem(cert: str) -> bytes:
    certificate = x509.load_der_x509_certificate(base64.b64decode(cert))
    return certificate.public_bytes(encoding=serialization.Encoding.PEM)


def _get_random_hex(nbytes: int) -> str:
    return secrets.token_hex(nbytes)


def _aes_gcm_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    encryptor = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext: bytes = encryptor.encrypt(plaintext)
    return ciphertext


def _aes_gcm_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    decryptor = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext: bytes = decryptor.decrypt(ciphertext)
    return plaintext
