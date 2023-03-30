import json
import pytest
from src.niceapi.api.handlers import ApiRequestHandler

class TestApiRequestHandler:
    """ApiRequestHandler test class."""

    def test_parse_cmf_container_object(self):
        """
        test parsing CMFContainer
        """
        CMF_REQUEST = {"SourceEndPointID": "001", "DestinationEndPointID": "002"}
        CMF_CONTAINER = {"SignedCMF": json.dumps(CMF_REQUEST)}
        def verify(jws):
            payload = jws
            return True, payload
        success, src, dst, request = ApiRequestHandler.parse_cmf_container_object(verify, CMF_CONTAINER)
        assert success == True
        assert src == "001"
        assert dst == "002"
        assert request == CMF_REQUEST

    def test_parse_cmf_container_object_error(self):
        """
        test parsing CMFContainer error
        """
        CMF_REQUEST = {"SourceEndPointID": "001", "DestinationEndPointID": "002"}
        CMF_CONTAINER = {"SignedCMF": json.dumps(CMF_REQUEST)}
        def verify(jws):
            return False, None
        success, src, dst, request = ApiRequestHandler.parse_cmf_container_object(verify, CMF_CONTAINER)
        assert success == False
        assert src == None
        assert dst == None
        assert request == None

    def test_parse_cmf_container_object_exception(self):
        """
        test parsing CMFContainer exception
        """
        CMF_REQUEST = {"SourceEndPointID": "001", "DestinationEndPointID": "002"}
        CMF_CONTAINER = {"SignedCMF": json.dumps(CMF_REQUEST)+"AA"} #Invalid Data
        def verify(jws):
            payload = jws
            return True, payload
        success, src, dst, request = ApiRequestHandler.parse_cmf_container_object(verify, CMF_CONTAINER)
        assert success == False
        assert src == None
        assert dst == None
        assert request == None

    def test_parse_cmf_request_object(self):
        """
        test parsing CMFRequest
        """
        CMF_REQUEST = {"Payload": "{\"AccessToken\": \"ABC\", \"PayloadObject\": \"DEF\"}"}
        def decrypt(jwe):
            plaintext = jwe
            return True, plaintext
        success, token, object_ = ApiRequestHandler.parse_cmf_request_object(decrypt, CMF_REQUEST)
        assert success == True
        assert token == "ABC"
        assert object_ == "DEF"

    def test_parse_cmf_request_object_no_payload(self):
        """
        test parsing CMFRequest (no payload)
        """
        CMF_REQUEST = {}
        def decrypt(jwe):
            plaintext = jwe
            return True, plaintext
        success, token, object_ = ApiRequestHandler.parse_cmf_request_object(decrypt, CMF_REQUEST)
        assert success == True
        assert token == None
        assert object_ == None

    def test_parse_cmf_request_object_error(self):
        """
        test parsing CMFRequest error
        """
        CMF_REQUEST = {"Payload": "{\"AccessToken\": \"ABC\", \"PayloadObject\": \"DEF\"}"}
        def decrypt(jwe):
            return False, None
        success, token, object_ = ApiRequestHandler.parse_cmf_request_object(decrypt, CMF_REQUEST)
        assert success == False
        assert token == None
        assert object_ == None

    def test_parse_cmf_request_object_exception(self):
        """
        test parsing CMFRequest exception
        """
        CMF_REQUEST = {"Payload": "{\"AccessToken\": \"ABC\", \"PayloadObject\": \"DEF\"}AA"} #Invalid Data
        def decrypt(jwe):
            plaintext = jwe
            return True, plaintext
        success, token, object_ = ApiRequestHandler.parse_cmf_request_object(decrypt, CMF_REQUEST)
        assert success == False
        assert token == None
        assert object_ == None

    def test_make_cmf_container_object(self):
        """
        test making CMFContainer
        """
        CMF_REQUEST = {
            "SourceEndPointID": "001",
            "DestinationEndPointID": "002"
        }
        CMF_HEADER = {
            "SourceEndPointID": "001",
            "DestinationEndPointID": "002",
            "CommandID": 0
        }
        RESPONSE_OBJ = {"ABC": "DEF"}
        ENCRYPTED_PAYLOAD = {"PayloadObject": RESPONSE_OBJ}
        CMF_RESPONSE = {
            "Version": "1.0",
            "MessageType": "response",
            "SourceEndPointID": "002",
            "DestinationEndPointID": "001",
            "ReplyStatusCode": 0,
            "DateTimeStamp": "2022-02-21T12:34:56.123Z",
            "ReplyStatusMessage": "OK",
            "Payload": json.dumps(ENCRYPTED_PAYLOAD)
        }
        CMF_CONTAINER = {"SignedCMF": json.dumps(CMF_RESPONSE)}
        def sign(payload):
            jws = payload.decode()
            return True, jws
        def encrypt(plaintext):
            ciphertext = plaintext.decode()
            return True, ciphertext
        success, container, response = ApiRequestHandler.make_cmf_container_object(
            sign=sign,
            encrypt=encrypt,
            request=CMF_REQUEST,
            date="2022-02-21T12:34:56.123Z",
            code=0,
            msg="OK",
            obj=RESPONSE_OBJ
        )
        assert success == True
        assert container == CMF_CONTAINER
        assert response == CMF_RESPONSE

    def test_make_cmf_container_object_encrypt_error(self):
        """
        test making CMFContainer encrypt error
        """
        CMF_REQUEST = {
            "SourceEndPointID": "001",
            "DestinationEndPointID": "002"
        }
        RESPONSE_OBJ = {"ABC": "DEF"}
        CMF_RESPONSE = {
            "Version": "1.0",
            "MessageType": "response",
            "SourceEndPointID": "002",
            "DestinationEndPointID": "001",
            "ReplyStatusCode": 0,
            "DateTimeStamp": "2022-02-21T12:34:56.123Z",
            "ReplyStatusMessage": "OK",
            "Payload": json.dumps(RESPONSE_OBJ)
        }
        CMF_CONTAINER = {"SignedCMF": json.dumps(CMF_RESPONSE)}
        def sign(payload):
            jws = payload.decode()
            return True, jws
        def encrypt(plaintext):
            ciphertext = plaintext.decode()
            return False, None
        #import pdb; pdb.set_trace()
        success, container, response = ApiRequestHandler.make_cmf_container_object(
            sign=sign,
            encrypt=encrypt,
            request=CMF_REQUEST,
            date="2022-02-21T12:34:56.123Z",
            code=0,
            msg="OK",
            obj=RESPONSE_OBJ
        )
        assert success == False
        assert container == None
        assert response == None

    def test_make_cmf_container_object_sign_error(self):
        """
        test making CMFContainer sign error
        """
        CMF_REQUEST = {
            "SourceEndPointID": "001",
            "DestinationEndPointID": "002"
        }
        RESPONSE_OBJ = {"ABC": "DEF"}
        CMF_RESPONSE = {
            "Version": "1.0",
            "MessageType": "response",
            "SourceEndPointID": "002",
            "DestinationEndPointID": "001",
            "ReplyStatusCode": 0,
            "DateTimeStamp": "2022-02-21T12:34:56.123Z",
            "ReplyStatusMessage": "OK",
            "Payload": json.dumps(RESPONSE_OBJ)
        }
        CMF_CONTAINER = {"SignedCMF": json.dumps(CMF_RESPONSE)}
        def sign(payload):
            jws = payload.decode()
            return False, None
        def encrypt(plaintext):
            ciphertext = plaintext.decode()
            return True, ciphertext
        #import pdb; pdb.set_trace()
        success, container, response = ApiRequestHandler.make_cmf_container_object(
            sign=sign,
            encrypt=encrypt,
            request=CMF_REQUEST,
            date="2022-02-21T12:34:56.123Z",
            code=0,
            msg="OK",
            obj=RESPONSE_OBJ
        )
        assert success == False
        assert container == None
        assert response == None

    def test_make_cmf_container_object_exception(self):
        """
        test making CMFContainer exception
        """
        CMF_REQUEST = {
            "SourceEndPointID": "001",
            "DestinationEndPointID": "002"
        }
        RESPONSE_OBJ = {"ABC": "DEF"}
        CMF_RESPONSE = {
            "Version": "1.0",
            "MessageType": "response",
            "SourceEndPointID": "002",
            "DestinationEndPointID": "001",
            "ReplyStatusCode": 0,
            "DateTimeStamp": "2022-02-21T12:34:56.123Z",
            "ReplyStatusMessage": "OK",
            "Payload": json.dumps(RESPONSE_OBJ)
        }
        CMF_CONTAINER = {"SignedCMF": json.dumps(CMF_RESPONSE)}
        def sign(payload):
            jws = payload.decode()
            return False, None
        def encrypt(plaintext):
            ciphertext = plaintext.decode()
            return True, ciphertext
        #import pdb; pdb.set_trace()
        success, container, response = ApiRequestHandler.make_cmf_container_object(
            sign=sign,
            encrypt=encrypt,
            request=CMF_REQUEST,
            date="2022-02-21T12:34:56.123Z",
            code=0,
            msg="OK",
            obj={"ABC", "DEF"} #Invalid Data
        )
        assert success == False
        assert container == None
        assert response == None

