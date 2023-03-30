import pytest
import copy
import json
from src.niceapi.api.crypto import DataCrypto
from .test_requests import PRIVACY_OBJECT
from .test_mode import SCENE_MODE

@pytest.fixture
def privacy():
    return json.loads(PRIVACY_OBJECT)

@pytest.fixture
def encryption():
    mode = json.loads(SCENE_MODE)
    output = mode["Outputs"][0]
    return output["Encryption"]

class TestDataCrypto:
    """DataCrypto test class."""

    def test_encrypt_decrypt_01(self, privacy, encryption):
        """
        test AES-GCM encryption of SceneData
        """
        data = b"Hello"
        alg = encryption["SceneDataEncryption"]
        success, encrypted = DataCrypto.encrypt(data, privacy, alg)
        assert success == True
        success, decrypted = DataCrypto.decrypt(encrypted, privacy, alg)
        assert success == True
        assert decrypted == data

    def test_encrypt_decrypt_02(self, privacy):
        """
        test JWE encryption of SceneMark
        """
        data = b"Hello"
        success, encrypted = DataCrypto.jwe_encrypt(data, "A256KW", "A256GCM", privacy)
        assert success == True
        success, decrypted = DataCrypto.jwe_decrypt(encrypted, privacy)
        assert success == True
        assert decrypted == data

    def test_encrypt_error(self, privacy, encryption):
        """
        test errors
        """
        a256ctr = copy.deepcopy(encryption)
        a256ctr["SceneDataEncryption"] = "A256CTR"
        success, data = DataCrypto.encrypt(b"", privacy, a256ctr)
        assert success == False
        assert data == None
        success, data = DataCrypto.decrypt(b"", privacy, a256ctr)
        assert success == False
        assert data == None
        no_key = copy.deepcopy(privacy)
        no_key["SceneEncryptionKey"]["k"] = ""
        success, encrypted = DataCrypto.jwe_encrypt(b"", "A256KW", "A256GCM", no_key)
        assert success == False
        assert encrypted == None
        success, decrypted = DataCrypto.jwe_decrypt(b"", no_key)
        assert success == False
        assert decrypted == None

    def test_encode_decode(self, encryption):
        """
        test TLV encode
        """
        type_in = 0x00000003
        value_in = b"Hello"
        encode_result, tlv = DataCrypto.tlv_encode(encryption, type_in, value_in)
        decode_result, header_out, type_out, value_out = DataCrypto.tlv_decode(tlv)
        assert encode_result == True
        assert decode_result == True
        assert type_in == type_out
        assert value_in == value_out
        encryption_out = header_out["Encryption"]
        for k, v in encryption_out.items():
            if k == "SceneEncryptionKeyID":
                assert v == encryption["SceneEncryptionKeyID"]
            elif k == "SceneDataEncryption":
                assert v == encryption["SceneDataEncryption"]
            else:
                assert False, f"wrong property: {k}"

    def test_encode_error(self, encryption):
        """
        test TLV encode error
        """
        type_ = 0x00000003
        value = b"Hello"
        header = DataCrypto.HEADER
        DataCrypto.HEADER = b"abcdefghijklmnopqrstuvwxyz"
        success, tlv = DataCrypto.tlv_encode(encryption, type_, value)
        assert success == False
        assert tlv == None
        DataCrypto.HEADER = header
        type_ = 0x10000000
        encode_result, tlv = DataCrypto.tlv_encode(encryption, type_, value)
        decode_result, header_out, type_out, value_out = DataCrypto.tlv_decode(tlv)
        assert encode_result == True
        assert decode_result == False
        assert header_out == None
        assert type_out == None
        assert value_out == None
        decode_result, header_out, type_out, value_out = DataCrypto.tlv_decode(tlv[:5])
        assert decode_result == False
        assert header_out == None
        assert type_out == None
        assert value_out == None
