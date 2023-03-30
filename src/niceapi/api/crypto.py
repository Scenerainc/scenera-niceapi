import json
import struct
from logging import INFO, Logger, getLogger
from typing import Any, Dict, Generator, Optional, Tuple

from ..crypto._utility import _aes_gcm_decrypt, _aes_gcm_encrypt
from ..crypto.jose import _jwe_decrypt, _jwe_encrypt
from ..util._tools import (
    _base64url_decode,
    _logger_setup,
    _TracebackOnException,
)

DICT_T = Dict[str, Any]

logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)


class _TLV:
    FORMAT = "<II"

    @classmethod
    def encode(cls, type_: int, value: bytes) -> Optional[bytes]:
        with _TracebackOnException():
            length = len(value)
            type_length = struct.pack(cls.FORMAT, type_, length)
            return type_length + value
        return None

    @classmethod
    def decode(cls, data: bytes) -> Generator[Tuple[int, bytes], None, None]:
        size = struct.calcsize(cls.FORMAT)
        while data:
            try:
                type_, length = struct.unpack(cls.FORMAT, data[:size])
                value = data[size : size + length]
            except Exception as e:
                logger.error(e)
                break
            yield type_, value
            data = data[size + length :]


class DataCrypto:
    """Crypto class for SceneMark and SceneData encryption"""

    HEADER = 0x0001
    JPEG = 0x0002
    H264 = 0x0003
    H265 = 0x0004
    RAW = 0x0005
    JSON = 0x0006

    @classmethod
    def encrypt(
        cls, data: bytes, privacy: DICT_T, encryption: str
    ) -> Tuple[bool, Optional[bytes]]:
        """Encrypt with PrivacyObject

        Parameters
        ----------
        data : bytes
            data to encrypt

        privacy : dict
            PrivacyObject

        encryption : str
            SceneDataEncryption (only "A256GCM" is suported now)

        Returns
        -------
        bool
            True if successful

        bytes or None
            ciphertext
        """
        with _TracebackOnException():
            key = privacy["SceneEncryptionKey"]
            k = _base64url_decode(key["k"])
            if encryption == "A256GCM":
                iv = _base64url_decode(key["iv"])
                return True, _aes_gcm_encrypt(data, k, iv)
            else:
                logger.error(f"unsupported encryption: {encryption}")
        return False, None

    @classmethod
    def decrypt(
        cls, data: bytes, privacy: DICT_T, encryption: str
    ) -> Tuple[bool, Optional[bytes]]:
        """Decrypt with PrivacyObject

        Parameters
        ----------
        data : bytes
            data to decrypt

        privacy : dict
            PrivacyObject

        encryption : str
            SceneDataEncryption (only "A256GCM" is suported now)

        Returns
        -------
        bool
            True if successful

        bytes or None
            plaintext
        """
        with _TracebackOnException():
            key = privacy["SceneEncryptionKey"]
            k = _base64url_decode(key["k"])
            if encryption == "A256GCM":
                iv = _base64url_decode(key["iv"])
                return True, _aes_gcm_decrypt(data, k, iv)
            else:
                logger.error(f"unsupported encryption: {encryption}")
        return False, None

    @classmethod
    def tlv_encode(
        cls, encryption: DICT_T, type_: int, value: bytes
    ) -> Tuple[bool, Optional[bytes]]:
        """TLV encode

        Parameters
        ----------
        encryption : dict
            SceneMode Encryption (header source)

        type_ : int
            Type of TLV format

        value : bytes
            Value of TLV format (encrypted data)

        Returns
        -------
        bool
            True if successful

        bytes or None
            TLV encoded bytes
        """
        try:
            header = {
                "Encryption": {
                    "SceneEncryptionKeyID": encryption["SceneEncryptionKeyID"],
                    "SceneDataEncryption": encryption["SceneDataEncryption"],
                }
            }
            header_bytes = json.dumps(header).encode()
            tlv_head = _TLV.encode(cls.HEADER, header_bytes)
            tlv_body = _TLV.encode(type_, value)
            if not tlv_head or not tlv_body:
                raise Exception("Failed to encode TLV")
            return True, tlv_head + tlv_body
        except Exception as e:
            logger.error(e)
        return False, None

    @classmethod
    def tlv_decode(
        cls, data: bytes
    ) -> Tuple[bool, Optional[DICT_T], Optional[int], Optional[bytes]]:
        """TLV decode

        Parameters
        ----------
        data : bytes
            TLV encoded bytes

        Returns
        -------
        bool
            True if successful

        dict or None
            SceneDataFileHeader

        int or None
            Type of TLV format

        bytes or None
            Value of TLV format
        """
        header = None
        data_type = None
        data_value = None
        for type_, value in _TLV.decode(data):
            if type_ == cls.HEADER:
                header = json.loads(value.decode())
            elif cls.JPEG <= type_ <= cls.JSON:
                data_type = type_
                data_value = value
            else:
                logger.error(f"unknown type: {type_:0>8x}")
        if header and data_type and data_value:
            return True, header, data_type, data_value
        return False, None, None, None

    @classmethod
    def jwe_encrypt(
        cls, data: bytes, alg: str, enc: str, privacy: DICT_T
    ) -> Tuple[bool, Optional[str]]:
        """Encrypt with PrivacyObject

        Parameters
        ----------
        data : bytes
            data to encrypt

        alg : str
            key management algorithm

        enc : str
            content encryption algorithm

        privacy : dict
            PrivacyObject

        Returns
        -------
        bool
            True if successful

        str or None
            a compact JWE
        """
        with _TracebackOnException():
            key = privacy["SceneEncryptionKey"]
            kid = key["kid"]
            k = _base64url_decode(key["k"])
            encrypted = _jwe_encrypt(data, alg, enc, kid, k)
            if encrypted:
                return True, encrypted
        return False, None

    @classmethod
    def jwe_decrypt(
        cls, data: bytes, privacy: DICT_T
    ) -> Tuple[bool, Optional[str]]:
        """Decrypt with PrivacyObject

        Parameters
        ----------
        data : bytes
            data to decrypt

        privacy : dict
            PrivacyObject

        Returns
        -------
        bool
            True if successful

        str or None
            plaintext
        """
        with _TracebackOnException():
            key = privacy["SceneEncryptionKey"]
            k = _base64url_decode(key["k"])
            decrypted = _jwe_decrypt(data, k)
            if decrypted:
                return True, decrypted
        return False, None
