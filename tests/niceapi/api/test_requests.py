from enum import Enum
import copy
import json
import os
import pytest
from pytest_mock.plugin import MockerFixture

from .test_security import SECURITY_OBJECT
from .test_endpoint import MANAGEMENT_END_POINT
from .test_management import MANAGEMENT_OBJECT
from .test_control import CONTROL_OBJECT
from .test_mode import SCENE_MODE

from src.niceapi.api._api import _ApiID
__TMP_DICT = {e.name:e.value for e in _ApiID}
__TMP_DICT.update({"BAD_API": 99})
_BadApi:_ApiID = Enum("_BadApi", __TMP_DICT)

DUMMY_CRT = 'MIIDlzCCAn8CFCL6J2nMHEk8bgycTYAi7JBwohp9MA0GCSqGSIb3DQEBCwUAMIGHMQswCQYDVQQGEwJKUDEOMAwGA1UECAwFT3Nha2ExDjAMBgNVBAcMBU9zYWthMQwwCgYDVQQKDANzc3MxDDAKBgNVBAsMA3NzczEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMSIwIAYJKoZIhvcNAQkBFhNzb21lb25lQGV4YW1wbGUuY29tMB4XDTIyMDMyMjAxMzYwNVoXDTMyMDMxOTAxMzYwNVowgYcxCzAJBgNVBAYTAkpQMQ4wDAYDVQQIDAVPc2FrYTEOMAwGA1UEBwwFT3Nha2ExDDAKBgNVBAoMA3NzczEMMAoGA1UECwwDc3NzMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20xIjAgBgkqhkiG9w0BCQEWE3NvbWVvbmVAZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMbsd67QjTaanaB74wcfOlvafcsDT7+aBTyRI36luKhBYUf0zNwJXReeRGrm4uJVL8Lp8+ia3la0rWgzduk/vO5jzOkcjF7urOpezVwwKEnpuxKQr1zHFWzh+W7XN8Zl6Y4PQ1ErKjeNg+sWEKepedkNsoDRLpbu3kXobRIM5bvxGsMwPlBYF1glKPXfS3KWUBSUcX32S0WYlSY+81n4ru2McVVJ1W8ta2KBR2HxFzGnv1jamF97GcG2XS13q3f5BT3iQQi2UUwd7si1db3nh89xkUNsyiupQ1f4TJOD9sIi/r1UfsYdkjcZTiFZ2tuDsxDV2CVgbKfOzdAUGSAsR9AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAIjyPqzWk2Oo9RIpWcjJbSg4UHsJGo6jN9/bXtM4Wu/ngA0ciA0SxVRdAfUjp/IqmmOdQrTJb3/8COhwYEQh67EHFyVpxruXjbuZ7OJVLq7p0Vk2BEUOQJfwlz6FJc7YCnIm8IjqvgOtuwf1P6zJ7Q89FplZg985GuAtJpEGS3LmcQreHs/K5h1FAL4JVG88tfa/bd06tgldbnx+eESsImsj5Wh8eenf0Y0tf50E2Yr4quKeg6Iq/XdeWcNDrwfp3OHGCfsE74C5CVVJ0cI123e0VYN7dnssxXXJ5G+MNJia9zHex3/Q1Ozo/ErwggWZljW2fb44izHoxtui5UoBWXQ='
PRIVACY_OBJECT = """
{
    "Version": "1.0",
    "EndPointID": "END_POINT_ID",
    "PrivacyObjectID": "PRIVACY_OBJECT_ID",
    "StartDateTime": "2020-01-01T00:00:00.000Z",
    "EndDateTime": "2037-12-31T23:59:59.999Z",
    "SceneEncryptionKey": {
	"k": "OTA2M0JERDBGMDY2ODVFNjI5REIxOEQwQkE4NURCMzE",
	"kid": "scene_encryption_key_id",
	"iv": "rZdLTAyzLLCyJan85EFMg8cIPQJA93C0g0-qkCtifTs"
    }
}
"""

class TestApiRequest:
    """ApiRequest test class."""

    def test_set_permanent_path(self):
        """
        set permanent path
        """
        PATH = "/tmp"
        from src.niceapi.api.requests import ApiRequest
        ApiRequest.set_permanent_path(PATH)
        assert ApiRequest._permanent_path == PATH

    def test_set_security_object(self):
        """
        test set_security_object
        """
        from src.niceapi.api.requests import ApiRequest
        assert ApiRequest.security.is_available == False
        security = json.loads(SECURITY_OBJECT)
        security["AllowedTLSRootCertificates"] = [""]
        ApiRequest.set_security_object(security)
        assert ApiRequest.security.is_available == True
        
    def test_set_private_key(self):
        """
        test set_private_key
        """
        from src.niceapi.api.requests import ApiRequest
        key = {"ABC": "DEF"}
        ApiRequest.set_private_key(key)
        assert ApiRequest.security.device_private_key == key
        
    def test_initialize_jose(self):
        """
        test initialize_jose
        """
        key = {
            "crv":"P-256",
            "x":"KgdRMlTkD1A4SmVrKMYyoeEqrpKyadNkvrON706lIDk",
            "y":"seKdkG5Ukygg1fvsm0hNvtnItC11RX_afqfK_v65oec",
            "d":"N1g0K791BJEXQKeJZXiC7pT6PMgQYW5OD-GWWAyUbyY",
            "kty":"EC"
        }
        from src.niceapi.api.requests import ApiRequest
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))

        ApiRequest.security._device_private_key = None
        assert ApiRequest.initialize_jose() == False
        ApiRequest.set_private_key(key)
        assert ApiRequest.initialize_jose() == True

    def test_activate_storage(self):
        """
        test activate_storage
        """
        from src.niceapi.api.requests import ApiRequest
        assert ApiRequest._has_storage == False
        ApiRequest.activate_storage(1024)
        assert ApiRequest._has_storage == True
        from src.niceapi.util._storage import _Storage
        assert _Storage._size == 1024

    def test_get_management_end_point_01(self, mocker: MockerFixture):
        """
        test get_management_end_point
        """
        from src.niceapi.api.requests import ApiRequest
        ApiRequest.security._json = None
        assert ApiRequest.get_management_end_point() == False

        mocker.patch("src.niceapi.api.requests.DeviceSecurityObject.is_available").return_value = True
        ApiRequest.security._nice_la_root_certificate = None 
        assert ApiRequest.get_management_end_point() == False

        #set dummy
        from src.niceapi.api.requests import _WebAPI, Encrypt
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": "XXX"}
        mocker.patch.object(Encrypt, "encrypt").return_value = True, "XXXX"

        #set dummy-jose
        def verify(param):
            encrypted = {"PayloadObject": {"ABC": "DEF"}}
            payload = {"Payload": json.dumps(encrypted)}
            return True, json.dumps(payload)
        def decrypt(param):
            return True, param
        ApiRequest._jws_verify = verify
        ApiRequest._jwe_decrypt = decrypt

        class _StubSign:
            def __call__(self, param):
                return True, param
            def update_certificate(self, param):pass
        ApiRequest._jws_sign = _StubSign()
        mocker.patch("src.niceapi.api.security._check_certificate").return_value = True
        ApiRequest.security.json = json.loads(SECURITY_OBJECT)
        mocker.patch.object(ApiRequest, "_handle_management_request").return_value = json.loads(MANAGEMENT_END_POINT)
        assert ApiRequest.get_management_end_point() == True

        # _handle_management_request return None
        mocker.patch.object(ApiRequest, "_handle_management_request").return_value = None
        assert ApiRequest.get_management_end_point() == False

        #TIME_LOG
        import src.niceapi.api.requests as flag
        flag.TIME_LOG = True
        mocker.patch.object(ApiRequest, "_handle_management_request").return_value = json.loads(MANAGEMENT_END_POINT)
        assert ApiRequest.get_management_end_point() == True
        flag.TIME_LOG = False
        #error 
        ApiRequest.set_security_object(None)
        mocker.patch.object(ApiRequest, "_handle_management_request").reset_mock()
        mocker.patch.object(_WebAPI, "post_json").return_value = {"ABC": "XXX"}
        assert ApiRequest.get_management_end_point() == False

        #delete sign
        mocker.patch.object(ApiRequest, "_handle_management_request").return_value = json.loads(MANAGEMENT_END_POINT)
        sign_bak = ApiRequest._jws_sign
        ApiRequest._jws_sign = None
        ApiRequest.security.json = json.loads(SECURITY_OBJECT)
        assert ApiRequest.get_management_end_point() == True

        ApiRequest._jws_sign = sign_bak
        mocker.resetall()
        mocker.patch("src.niceapi.api.requests.ManagementEndPoint.is_available").reset_mock()
        #delete DeviceSecurityObject
        ApiRequest.set_security_object(None)
        mocker.patch("src.niceapi.api.requests.ManagementEndPoint.is_available").return_value = True
        assert ApiRequest.get_management_end_point() == False

        #recover DeviceSecurityObject
        ApiRequest.security.json = json.loads(SECURITY_OBJECT)
        
    def test_get_management_end_point_02(self, mocker: MockerFixture):
        """
        test get_management_end_point(endpoint.is_available)
        """
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api.common import WebAPIScheme
        mocker.patch.object(ApiRequest, "_handle_management_request").return_value = json.loads('{"Version": "1.0"}')
        mocker.patch("src.niceapi.api.requests.DeviceSecurityObject.is_available").return_value = True
        ApiRequest.security._nice_la_root_certificate = ["XXXXX"]
        ApiRequest.security._scheme = [WebAPIScheme("localhost", "TOKEN")]
        assert ApiRequest.get_management_end_point() == False

    def test_get_management_object_01(self, mocker: MockerFixture):
        """
        test get_management_object(around post)
        """
        from src.niceapi.api.control import ControlObject
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api.requests import _WebAPI
        from src.niceapi.api.requests import Encrypt
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": "XXX"}
        mocker.patch.object(Encrypt, "encrypt").return_value = True, "XXXXX"
        #set dummy jose
        def verify(param):
            management = json.loads(MANAGEMENT_OBJECT)
            management["AllowedTLSRootCertificates"] = [""]
            encrypted = {"PayloadObject": management}
            payload = {"Payload": json.dumps(encrypted)}
            return True, json.dumps(payload)
        def decrypt(param):
            return True, param
        ApiRequest._jws_verify = verify
        ApiRequest._jwe_decrypt = decrypt
        ApiRequest.control._json = None
        ApiRequest.control = ControlObject()

        # #dummy ManagementEndPoint
        ApiRequest.endpoint.json = json.loads(MANAGEMENT_END_POINT)
        class _StubSign:
            def __call__(self, param):
                return True, param
            def update_certificate(self, param):pass
        ApiRequest._jws_sign = _StubSign()

        # check(obj)
        mocker.patch.object(ApiRequest, "_handle_management_request").return_value = None
        assert ApiRequest.get_management_object() == False
        mocker.patch.object(ApiRequest, "_handle_management_request").reset_mock()

        # check(cls.management.is_available)
        mocker.patch.object(ApiRequest, "_handle_management_request").return_value = {"ABC": "XXX"}
        assert ApiRequest.get_management_object() == False
        mocker.patch.object(ApiRequest, "_handle_management_request").reset_mock()

        #TIME_LOG
        mocker.patch("src.niceapi.api.requests.DeviceSecurityObject.is_available").return_value = True
        ApiRequest.security._nice_la_root_certificate = [DUMMY_CRT]
        mocker.patch.object(ApiRequest, "_handle_management_request").return_value = json.loads(MANAGEMENT_OBJECT)
        mocker.patch("src.niceapi.api.requests.ManagementObject.is_available").return_value = True
        ApiRequest.security._allowed_tls_root_certificates = None

        import src.niceapi.api.requests as flag
        flag.TIME_LOG = True
        assert ApiRequest.get_management_object() == True
        flag.TIME_LOG = False
        mocker.resetall()
        
        
    def test_get_management_object_02(self, mocker: MockerFixture):
        """
        test get_management_object
        """
        mocker.resetall()
        # from src.niceapi.api.control import ControlObject
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api.security import DeviceSecurityObject

        # check "security.is_available"
        ApiRequest.security = DeviceSecurityObject()
        assert ApiRequest.get_management_object() == False

        # check "security.nice_la_root_certificate"
        mocker.patch("src.niceapi.api.requests.DeviceSecurityObject.is_available").return_value = True
        ApiRequest.security._nice_la_root_certificate = None
        assert ApiRequest.get_management_object() == False

        # check "endpoint.is_available"
        ApiRequest.security._nice_la_root_certificate = ["XXXX"]
        ApiRequest.endpoint._json = None
        assert ApiRequest.get_management_object() == False

        mocker.patch("src.niceapi.api.requests.DeviceSecurityObject.is_available").reset_mock()
        mocker.resetall()

    def test_get_management_object_03(self, mocker: MockerFixture):
        """
        test get_management_object(check after post)
        """
        mocker.resetall()
        # from src.niceapi.api.control import ControlObject
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api.security import DeviceSecurityObject

        from src.niceapi.api.control import ControlObject
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api.requests import _WebAPI
        from src.niceapi.api.requests import Encrypt
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": "XXX"}
        mocker.patch.object(Encrypt, "encrypt").return_value = True, "XXXXX"
        #set dummy jose
        def verify(param):
            management = json.loads(MANAGEMENT_OBJECT)
            management["AllowedTLSRootCertificates"] = [""]
            encrypted = {"PayloadObject": management}
            payload = {"Payload": json.dumps(encrypted)}
            return True, json.dumps(payload)
        def decrypt(param):
            return True, param
        ApiRequest._jws_verify = verify
        ApiRequest._jwe_decrypt = decrypt
        ApiRequest.control._json = None
        ApiRequest.control = ControlObject()

        # #dummy ManagementEndPoint
        ApiRequest.endpoint.json = json.loads(MANAGEMENT_END_POINT)
        class _StubSign:
            def __call__(self, param):
                return True, param
            def update_certificate(self, param):pass
        ApiRequest._jws_sign = _StubSign()

        mocker.patch("src.niceapi.api.requests.DeviceSecurityObject.is_available").return_value = True
        ApiRequest.security._nice_la_root_certificate = ["XXXX"]
        mocker.patch.object(ApiRequest, "_handle_management_request").return_value = json.loads(MANAGEMENT_OBJECT)
        mocker.patch("src.niceapi.api.requests.ManagementObject.is_available").return_value = True

        assert ApiRequest.get_management_object() == True

        #delete sign
        ApiRequest._jws_sign = None
        assert ApiRequest.get_management_object() == True

        #check allowed_tls_root_certificates
        mocker.patch.object(ApiRequest, "_handle_management_request").reset_mock()
        tmp = json.loads(MANAGEMENT_OBJECT)
        tmp["AllowedTLSRootCertificates"] = [DUMMY_CRT]
        mocker.patch.object(ApiRequest, "_handle_management_request").return_value = tmp
        def verify2(param):
            management = json.loads(MANAGEMENT_OBJECT)
            management["AllowedTLSRootCertificates"] = [DUMMY_CRT]
            encrypted = {"PayloadObject": management}
            payload = {"Payload": json.dumps(encrypted)}
            return True, json.dumps(payload)
        ApiRequest._jws_verify = verify2
        assert ApiRequest.get_management_object() == True

    def test_get_control_object_01(self, mocker: MockerFixture):
        """
        test get_control_object(check before post)
        """
        mocker.resetall()
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api.management import ManagementObject

        # check "security.is_available"
        assert ApiRequest.get_control_object() == False

        # check "management.is_available"
        ApiRequest.management = ManagementObject()
        mocker.patch("src.niceapi.api.requests.DeviceSecurityObject.is_available").return_value = True
        assert ApiRequest.get_control_object() == False

        mocker.patch("src.niceapi.api.requests.DeviceSecurityObject.is_available").reset_mock()
        mocker.resetall()
        

    def test_get_control_object_02(self, mocker: MockerFixture):
        """
        test get_control_object(check post)
        """
        mocker.resetall()
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api.requests import _WebAPI
        from src.niceapi.api.requests import Encrypt
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": "XXX"}
        mocker.patch.object(Encrypt, "encrypt").return_value = True, "XXXX"
        #set dummy jose
        def verify(param):
            encrypted = {"PayloadObject": {"ABC": "DEF"}}
            payload = {
                "Version": "1.0",
                "MessageType": "response",
                "DateTimeStamp": "2020-01-01T00:00:00.000Z",
                "SourceEndPointID": "APP_END_POINT_ID",
                "DestinationEndPointID": "DEVICE_ID",
                "ReplyStatusCode": 0,
                "Payload": json.dumps(encrypted)
            }
            return True, json.dumps(payload)
        def decrypt(param):
            return True, param
        class _StubSign:
            def __call__(self, param):
                return True, param
            def update_certificate(self, param):pass
        ApiRequest._jws_verify = verify
        ApiRequest._jwe_decrypt = decrypt
        ApiRequest._jws_sign = _StubSign()

        #dummy ManagementObject
        man_json = json.loads(MANAGEMENT_OBJECT)
        man_json["NICEAS"]["NICEASEndPoint"]["AppEndPoint"]["X.509Certificate"] = [DUMMY_CRT]
        man_json["AllowedTLSRootCertificates"] = [DUMMY_CRT]
        ApiRequest.management.json = man_json
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))
        assert ApiRequest.get_control_object() == False

        #TIME_LOG
        import src.niceapi.api.requests as flag
        flag.TIME_LOG = True
        assert ApiRequest.get_control_object() == False
        flag.TIME_LOG = False

        #error 
        def verify_no_ids(param):
            encrypted = {"PayloadObject": {"ABC": "DEF"}}
            payload = {"Payload": json.dumps(encrypted)}
            return True, json.dumps(payload)

        ApiRequest._jws_verify = verify_no_ids
        assert ApiRequest.get_control_object() == False
        mocker.resetall()

    def test_get_control_object_03(self, mocker: MockerFixture):
        """
        test get_control_object(check after post)
        """
        mocker.resetall()
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api.requests import _WebAPI
        from src.niceapi.api.requests import Encrypt
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": "XXX"}
        mocker.patch.object(Encrypt, "encrypt").return_value = True, "XXXX"
        #set dummy jose
        def verify(param):
            control = json.loads(CONTROL_OBJECT)
            encrypted = {"PayloadObject": control}
            payload = {
                "Version": "1.0",
                "MessageType": "response",
                "DateTimeStamp": "2020-01-01T00:00:00.000Z",
                "SourceEndPointID": "APP_END_POINT_ID",
                "DestinationEndPointID": "DEVICE_ID",
                "ReplyStatusCode": 0,
                "Payload": json.dumps(encrypted)
            }
            return True, json.dumps(payload)
        def decrypt(param):
            return True, param
        class _StubSign:
            def __call__(self, param):
                return True, param
            def update_certificate(self, param):pass
        ApiRequest._jws_verify = verify
        ApiRequest._jwe_decrypt = decrypt
        ApiRequest._jws_sign = _StubSign()

        #dummy ManagementObject
        man_json = json.loads(MANAGEMENT_OBJECT)
        man_json["NICEAS"]["NICEASEndPoint"]["AppEndPoint"]["X.509Certificate"] = [DUMMY_CRT]
        man_json["AllowedTLSRootCertificates"] = [DUMMY_CRT]
        ApiRequest.management.json = man_json
        mocker.patch("src.niceapi.api.requests.DeviceSecurityObject.is_available").return_value = True
        assert ApiRequest.get_control_object() == True

        #recover DeviceSecurityObject
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))
        mocker.resetall()

    def test_get_scene_mode(self, mocker: MockerFixture):
        """
        test get_scene_mode
        """
        NODE_ID = "001"
        from src.niceapi.api.requests import ApiRequest, Encrypt, _WebAPI
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": "XXX"}
        mocker.patch.object(Encrypt, "encrypt").return_value = True, "XXXX"
        #set dummy jose
        def verify(param):
            payload = {
                "Version": "1.0",
                "MessageType": "response",
                "DateTimeStamp": "2020-01-01T00:00:00.000Z",
                "SourceEndPointID": "APP_END_POINT_ID",
                "DestinationEndPointID": "DEVICE_ID",
                "ReplyStatusCode": 0,
                "Payload": json.dumps({
                    "PayloadObject": {
                        "Version": "1.0",
                        "SceneModeID": "ABC",
                        "NodeID": "1234"
                    }})
            }
            return True, json.dumps(payload)
        def decrypt(param):
            return True, param
        class _StubSign:
            def __call__(self, param):
                return True, param
            def update_certificate(self, param):pass
        ApiRequest._jws_verify = verify
        ApiRequest._jwe_decrypt = decrypt
        ApiRequest._jws_sign = _StubSign()
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))

        #error "control.is_available"
        ApiRequest.control.json = None
        success, _ = ApiRequest.get_scene_mode(NODE_ID)
        assert success == False
        #dummy
        ApiRequest.control.json = json.loads(CONTROL_OBJECT)
        success, _ = ApiRequest.get_scene_mode(NODE_ID)
        assert success == True
        #TIME_LOG
        import src.niceapi.api.requests as flag
        flag.TIME_LOG = True
        success, _ = ApiRequest.get_scene_mode(NODE_ID)
        assert success == True
        flag.TIME_LOG = False
        #invalid IDs
        def verify_invalid1(param):
            return True, json.dumps({
                "Version": "1.0",
                "MessageType": "response",
                "DateTimeStamp": "2020-01-01T00:00:00.000Z",
                "SourceEndPointID": "AAA",
                "DestinationEndPointID": "BBB",
                "ReplyStatusCode": 0,
                "Payload": json.dumps({
                    "PayloadObject": {
                        "Version": "1.0",
                        "SceneModeID": "ABC",
                        "NodeID": "1234"
                    }})
            })
        ApiRequest._jws_verify = verify_invalid1
        success, _ =  ApiRequest.get_scene_mode(NODE_ID)
        assert success == False
        def verify_invalid2(param):
            return True, json.dumps({
                "Version": "1.0",
                "MessageType": "response",
                "DateTimeStamp": "2020-01-01T00:00:00.000Z",
                "SourceEndPointID": "APP_END_POINT_ID",
                "DestinationEndPointID": "DEVICE_ID",
                "ReplyStatusCode": 0,
                "Payload": json.dumps({
                    "PayloadObject": {
                        "SceneModeID": "ABC",
                        "NodeID": "1234"
                    }})
            })
        ApiRequest._jws_verify = verify_invalid2
        success, _ =  ApiRequest.get_scene_mode(NODE_ID)
        assert success == False
        #error 
        mocker.patch.object(_WebAPI, "post_json").return_value = {"ABC": "XXX"}
        success, _ = ApiRequest.get_scene_mode(NODE_ID)
        assert success == False
        #delete DeviceSecurityObject
        ApiRequest.set_security_object(None)
        success, _ = ApiRequest.get_scene_mode(NODE_ID)
        assert success == False

        #recover DeviceSecurityObject
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))

    def test_get_scene_mode_when_control_nodeid_is_empty(self, mocker: MockerFixture):
        """
        test get_scene_mode when control's node_id is empty
        """
        NODE_ID = '999'
        from src.niceapi.api._api import _ApiComponent
        mock_ApiComponent = mocker.patch.object(_ApiComponent, "get_url")
        mock_ApiComponent.return_value = f'https://localhost/1.0/NET_END_POINT_ID/control/{NODE_ID}/GetSceneMode'

        from src.niceapi.api.requests import ApiRequest, Encrypt, _WebAPI
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": "XXX"}
        mocker.patch.object(Encrypt, "encrypt").return_value = True, "XXXX"
        #set dummy jose
        def verify(param):
            return True, json.dumps({
                "Version": "1.0",
                "MessageType": "response",
                "DateTimeStamp": "2020-01-01T00:00:00.000Z",
                "SourceEndPointID": "APP_END_POINT_ID",
                "DestinationEndPointID": "DEVICE_ID",
                "ReplyStatusCode": 0,
                "Payload": json.dumps({
                    "PayloadObject": {
                        "Version": "1.0",
                        "SceneModeID": "ABC",
                        "NodeID": "1234"
                    }})
            })
        def decrypt(param):
            return True, param
        class _StubSign:
            def __call__(self, param):
                return True, param
            def update_certificate(self, param):pass
        ApiRequest._jws_verify = verify
        ApiRequest._jwe_decrypt = decrypt
        ApiRequest._jws_sign = _StubSign()
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))

        control_json = json.loads(CONTROL_OBJECT)
        del control_json["ControlEndPoints"][0]["NetEndPoint"]["NodeID"]
        ApiRequest.control.json = control_json

        success, _ = ApiRequest.get_scene_mode(NODE_ID)

        assert success == True
        mock_ApiComponent.assert_called_with('localhost', 'NET_END_POINT_ID', NODE_ID)

        #recover DeviceSecurityObject
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))
        mocker.resetall()

    def test__make_privacies(self, mocker: MockerFixture):
        """
        for coverage of _make_privacy_dictionary
        """
        mocker.resetall()
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api._api import _ApiComponent, _ApiID
        from src.niceapi.api._mode import _Encryption
        from src.niceapi.api.requests import _SETTER_FUNC_T


        api = _ApiComponent(_ApiID.GET_PRIVACY_OBJECT)
        src = "SRC"
        setter: _SETTER_FUNC_T = lambda x:("DUMMY", "DUMMY", "DUMMY")
        enc_list = [_Encryption({"EncryptionOn":True}), None]

        #check
        result = ApiRequest._make_privacy_dictionary(setter, api, src, enc_list)
        assert len(result) == 0
        #
        mocker.resetall()


    def test_get_privacy_object(self, mocker: MockerFixture):
        """
        test get_privacy_object
        """
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api.requests import _WebAPI
        from src.niceapi.api.requests import Encrypt
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": "XXX"}
        mocker.patch.object(Encrypt, "encrypt").return_value = True, "XXXX"

        #set dummy security
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))
        #set dummy jose
        def verify(param):
            privacy = json.loads(PRIVACY_OBJECT)
            encrypted = {"PayloadObject": privacy}
            payload = {
                "Version": "1.0",
                "MessageType": "response",
                "DateTimeStamp": "2020-01-01T00:00:00.000Z",
                "SourceEndPointID": "APP_END_POINT_ID",
                "DestinationEndPointID": "DEVICE_ID",
                "ReplyStatusCode": 0,
                "Payload": json.dumps(encrypted)
            }
            return True, json.dumps(payload)
        def verify2(param):
            privacy = json.loads(PRIVACY_OBJECT)
            privacy.pop("SceneEncryptionKey")
            encrypted = {"PayloadObject": privacy}
            payload = {
                "Version": "1.0",
                "MessageType": "response",
                "DateTimeStamp": "2020-01-01T00:00:00.000Z",
                "SourceEndPointID": "APP_END_POINT_ID",
                "DestinationEndPointID": "DEVICE_ID",
                "ReplyStatusCode": 0,
                "Payload": json.dumps(encrypted)
            }
            return True, json.dumps(payload)
        def verify_error(param):
            privacy = json.loads(PRIVACY_OBJECT)
            privacy["EndDateTime"] = "2020-01-01T00:00:00.000Z"
            encrypted = {"PayloadObject": privacy}
            payload = {
                "Version": "1.0",
                "MessageType": "response",
                "DateTimeStamp": "2020-01-01T00:00:00.000Z",
                "SourceEndPointID": "APP_END_POINT_ID",
                "DestinationEndPointID": "DEVICE_ID",
                "ReplyStatusCode": 0,
                "Payload": json.dumps(encrypted)
            }
            return True, json.dumps(payload)
        def verify_error2(param):
            privacy = json.loads(PRIVACY_OBJECT)
            privacy.pop("Version")
            encrypted = {"PayloadObject": privacy}
            payload = {
                "Version": "1.0",
                "MessageType": "response",
                "DateTimeStamp": "2020-01-01T00:00:00.000Z",
                "SourceEndPointID": "APP_END_POINT_ID",
                "DestinationEndPointID": "DEVICE_ID",
                "ReplyStatusCode": 0,
                "Payload": json.dumps(encrypted)
            }
            return True, json.dumps(payload)
        def verify_error3(param):
            privacy = json.loads(PRIVACY_OBJECT)
            key = privacy["SceneEncryptionKey"]
            key.pop("k")
            encrypted = {"PayloadObject": privacy}
            payload = {
                "Version": "1.0",
                "MessageType": "response",
                "DateTimeStamp": "2020-01-01T00:00:00.000Z",
                "SourceEndPointID": "APP_END_POINT_ID",
                "DestinationEndPointID": "DEVICE_ID",
                "ReplyStatusCode": 0,
                "Payload": json.dumps(encrypted)
            }
            return True, json.dumps(payload)
        def decrypt(param):
            return True, param
        class _StubSign:
            def __call__(self, param):
                return True, param
            def update_certificate(self, param):pass
        ApiRequest._jws_verify = verify
        ApiRequest._jwe_decrypt = decrypt
        ApiRequest._jws_sign = _StubSign()
        
        mode = json.loads(SCENE_MODE)
        success, _ =  ApiRequest.get_privacy_object(mode)
        assert success == True
        #TIME_LOG
        import src.niceapi.api.requests as flag
        flag.TIME_LOG = True
        success, _ =  ApiRequest.get_privacy_object(mode)
        assert success == True
        flag.TIME_LOG = False
        #ref encryption => False
        ref = mode["Mode"]["SceneModeConfig"][0]["LabelRefDataList"][0]
        ref["RefData"][0]["Encryption"]["EncryptionOn"] = False
        success, _ =  ApiRequest.get_privacy_object(mode)
        assert success == True
        #no ref
        ref.pop("RefData")
        success, _ =  ApiRequest.get_privacy_object(mode)
        assert success == True
        #no mode encryption
        config = mode["Mode"]["SceneModeConfig"][0]
        config.pop("Encryption")
        success, _ =  ApiRequest.get_privacy_object(mode)
        assert success == True
        mode = json.loads(SCENE_MODE)
        #error
        ApiRequest._jws_verify = verify_error
        output = mode["Outputs"][0]
        output.pop("DestinationEndPointList")
        success, _ =  ApiRequest.get_privacy_object(mode)
        assert success == False
        mode = json.loads(SCENE_MODE)
        #no required key error
        ApiRequest._jws_verify = verify_error2
        success, _ =  ApiRequest.get_privacy_object(mode)
        assert success == False
        ApiRequest._jws_verify = verify2
        success, _ =  ApiRequest.get_privacy_object(mode)
        assert success == True
        ApiRequest._jws_verify = verify_error3
        success, _ =  ApiRequest.get_privacy_object(mode)
        assert success == False
        #recover SceneMode
        mode = json.loads(SCENE_MODE)
        #delete ManagementObjcet
        ApiRequest.management.json = {}
        success, _ =  ApiRequest.get_privacy_object(mode)
        assert success == False
        #recover ManagementObject
        ApiRequest.management.json = json.loads(MANAGEMENT_OBJECT)
        """ no expired check now
        ApiRequest._jws_verify = verify_error
        success, _ =  ApiRequest.get_privacy_object(mode)
        assert success == False
        """
        mocker.patch.object(_WebAPI, "post_json").return_value = {"ABC": "XXX"}
        success, _ =  ApiRequest.get_privacy_object(mode)
        assert success == False
        #delete DeviceSecurityObject
        ApiRequest.set_security_object(None)
        success, _ =  ApiRequest.get_privacy_object(mode)
        assert success == False
        #recover DeviceSecurityObject
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))
        
    def test_get_date_time_from_la(self, mocker: MockerFixture):
        """
        test get_date_time_from_la
        """
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api.requests import _WebAPI
        from src.niceapi.api.requests import Encrypt
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": "XXX"}
        mocker.patch.object(Encrypt, "encrypt").return_value = True, "XXXX"
        #set dummy jose
        def verify(param):
            encrypted = {"PayloadObject": {"ABC": "DEF"}}
            payload = {"Payload": json.dumps(encrypted)}
            return True, json.dumps(payload)
        def decrypt(param):
            return True, param
        class _StubSign:
            def __call__(self, param):
                return True, param
            def update_certificate(self, param):pass
        ApiRequest._jws_verify = verify
        ApiRequest._jwe_decrypt = decrypt
        ApiRequest._jws_sign = _StubSign()
        ApiRequest.endpoint.json = None
        success, _ = ApiRequest.get_date_time_from_la()
        assert success == False
        #dummy object
        ApiRequest.endpoint.json = json.loads(MANAGEMENT_END_POINT)
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))
        #dummy encrypt to get random value
        from src.niceapi.api.requests import Encrypt
        random = None
        def request_random(plaintext):
            nonlocal random
            payload = json.loads(plaintext.decode())
            random = payload["PayloadObject"]["RandomChallenge"]
            return True, json.dumps(payload)
        mocker.patch.object(Encrypt, "encrypt").side_effect=request_random
        def verify_direct(param):
            return True, param
        ApiRequest._jws_verify = verify_direct
        def response_random(url, cmf, timeout=1000, token=None, verify=True):
            response = {
                "Version": "1.0",
                "EndPointID": "END_POINT_ID",
                "ReturnedRandomChallenge": random,
                "DateTimeStamp": "2022-02-21T12:34:56.123Z"
            }
            if 'SignedCMF' in cmf:
                encrypted = {"PayloadObject": response}
            else:
                encrypted = response
            payload = {
                "Version": "1.0",
                "MessageType": "response",
                "DateTimeStamp": "2020-01-01T00:00:00.000Z",
                "SourceEndPointID": "APP_END_POINT_ID",
                "DestinationEndPointID": "DEVICE_ID",
                "ReplyStatusCode": 0,
                "Payload": json.dumps(encrypted)
            }
            container = {"SignedCMF": json.dumps(payload)}
            return container
        mocker.patch.object(_WebAPI, "post_json").side_effect=response_random
        success, _ = ApiRequest.get_date_time_from_la()
        assert success == True
        #TIME_LOG
        import src.niceapi.api.requests as flag
        flag.TIME_LOG = True
        success, _ = ApiRequest.get_date_time_from_la()
        assert success == True
        flag.TIME_LOG = False
        #custom
        ApiRequest.custom = True
        success, _ = ApiRequest.get_date_time_from_la()
        assert success == True
        #recover custom
        ApiRequest.custom = False
        #error
        ApiRequest._jws_verify = verify
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": "XXX"}
        success, _ = ApiRequest.get_date_time_from_la()
        assert success == False
        #delete DeviceSecurityObject
        ApiRequest.set_security_object(None)
        success, _ = ApiRequest.get_date_time_from_la()
        assert success == False
        #recover DeviceSecurityObject
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))

    def test_get_date_time_from_as_01(self, mocker: MockerFixture):
        """
        test get_date_time_from_as
        """
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api.requests import _WebAPI
        from src.niceapi.api.requests import Encrypt
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": "XXX"}
        mocker.patch.object(Encrypt, "encrypt").return_value = True, "XXXX"
        #set dummy jose
        def verify(param):
            encrypted = {"PayloadObject": {"ABC": "DEF"}}
            payload = {"Payload": json.dumps(encrypted)}
            return True, json.dumps(payload)
        def decrypt(param):
            return True, param
        ApiRequest._jws_verify = verify
        ApiRequest._jwe_decrypt = decrypt
        ApiRequest.management.json = None
        success, _ = ApiRequest.get_date_time_from_as()
        assert success == False
        #dummy ManagementObject
        ApiRequest.management.json = json.loads(MANAGEMENT_OBJECT)
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))
        #dummy encrypt to get random value
        from src.niceapi.api.requests import Encrypt
        random = None
        def request_random(plaintext):
            nonlocal random
            payload = json.loads(plaintext.decode())
            random = payload["PayloadObject"]["RandomChallenge"]
            return True, json.dumps(payload)
        mocker.patch.object(Encrypt, "encrypt").side_effect=request_random
        def verify_direct(param):
            return True, param
        class _StubSign:
            def __call__(self, param):
                return True, param.decode()
            def update_certificate(self, param):pass
        ApiRequest._jws_verify = verify_direct
        ApiRequest._jws_sign = _StubSign()
        def response_random(url, cmf, timeout=1000, token=None, verify=True):
            response = {
                "Version": "1.0",
                "EndPointID": "END_POINT_ID",
                "ReturnedRandomChallenge": random,
                "DateTimeStamp": "2022-02-21T12:34:56.123Z"
            }
            encrypted = {"PayloadObject": response}
            payload = {
                "Version": "1.0",
                "MessageType": "response",
                "DateTimeStamp": "2020-01-01T00:00:00.000Z",
                "SourceEndPointID": "APP_END_POINT_ID",
                "DestinationEndPointID": "DEVICE_ID",
                "ReplyStatusCode": 0,
                "Payload": json.dumps(encrypted)
            }
            container = {"SignedCMF": json.dumps(payload)}
            return container
        mocker.patch.object(_WebAPI, "post_json").side_effect=response_random
        success, _ = ApiRequest.get_date_time_from_as()
        assert success == True

        #TIME_LOG
        import src.niceapi.api.requests as flag
        flag.TIME_LOG = True
        success, _ = ApiRequest.get_date_time_from_as()
        assert success == True
        flag.TIME_LOG = False

        #check random
        def response_random2(url, cmf, timeout=1000, token=None, verify=True):
            response = {
                "ReturnedRandomChallenge": "XXX",
                "DateTimeStamp": "2022-02-21T12:34:56.123Z"
            }
            encrypted = {"PayloadObject": response}
            payload = {
                "SourceEndPointID": "APP_END_POINT_ID",
                "DestinationEndPointID": "DEVICE_ID",
                "Payload": json.dumps(encrypted)
            }
            container = {"SignedCMF": json.dumps(payload)}
            return container
        mocker.patch.object(_WebAPI, "post_json").side_effect=response_random2
        success, _ = ApiRequest.get_date_time_from_as()
        assert success == False

        #check "not timestamp"
        def response_random3(url, cmf, timeout=1000, token=None, verify=True):
            response = {
                "ReturnedRandomChallenge": random,
                "DateTimeStamp": None
            }
            encrypted = {"PayloadObject": response}
            payload = {
                "SourceEndPointID": "APP_END_POINT_ID",
                "DestinationEndPointID": "DEVICE_ID",
                "Payload": json.dumps(encrypted)
            }
            container = {"SignedCMF": json.dumps(payload)}
            return container
        mocker.patch.object(_WebAPI, "post_json").side_effect=response_random3
        success, _ = ApiRequest.get_date_time_from_as()
        assert success == False

        #recover DeviceSecurityObject
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))

    def test_get_date_time_from_as_02(self, mocker: MockerFixture):
        """
        test get_date_time_from_as(check before post)
        """
        from src.niceapi.api.requests import ApiRequest
        ApiRequest.set_security_object({})

        # check "security.is_available"
        success, _ = ApiRequest.get_date_time_from_as()
        assert success == False

        #recover DeviceSecurityObject
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))


    def test_set_scene_mark(self, mocker: MockerFixture):
        """
        test set_scene_mark
        """
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api.requests import _WebAPI
        mocker.patch.object(_WebAPI, "post_json").return_value = {}
        mocker.patch.object(_WebAPI, "post_text").return_value = {}
        scene_mark = ApiRequest.new_scene_mark(
            version="1.0",
            time_stamp="2022-02-21T12:34:56.123Z",
            scene_mark_id="123",
            node_id="001"
        )
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))
        scene_mode = json.loads(SCENE_MODE)
        privacy = json.loads(PRIVACY_OBJECT)
        kid = privacy["SceneEncryptionKey"]["kid"]
        privacy_dict = {kid: privacy}
        success, _ = ApiRequest.set_scene_mark(scene_mode, scene_mark.json, privacy_dict)
        assert success == True
        #no encryption
        no_enc = copy.deepcopy(scene_mode)
        mark_output = no_enc["Mode"]["SceneMarkOutputList"][0]
        mark_output.pop("Encryption")
        success, _ = ApiRequest.set_scene_mark(no_enc, scene_mark.json, privacy_dict)
        assert success == True
        #invalid alg
        invalid_alg = copy.deepcopy(scene_mode)
        mark_output = invalid_alg["Mode"]["SceneMarkOutputList"][0]
        mark_output["Encryption"]["SceneMarkEncryption"]["JWEAlg"] = "A128KW"
        success, _ = ApiRequest.set_scene_mark(invalid_alg, scene_mark.json, privacy_dict)
        assert success == False
        #invalid key
        invalid_key = copy.deepcopy(privacy)
        invalid_key["SceneEncryptionKey"]["k"] = "abcd"
        invalid_privacy_dict = {kid: invalid_key}
        success, _ = ApiRequest.set_scene_mark(scene_mode, scene_mark.json, invalid_privacy_dict)
        assert success == False
        #test storage
        ApiRequest._has_storage = False
        success, _ = ApiRequest.set_scene_mark(scene_mode, scene_mark.json, privacy_dict)
        ApiRequest._has_storage = True
        assert success == True
        #error
        success, _ = ApiRequest.set_scene_mark(scene_mode, scene_mark.json)
        assert success == False
        mocker.patch.object(_WebAPI, "post_text").return_value = None
        success, _ = ApiRequest.set_scene_mark(scene_mode, scene_mark.json, privacy_dict)
        assert success == False
        #recover WebAPI
        mocker.patch.object(_WebAPI, "post_text").return_value = {}
        output = scene_mode["Outputs"][0]
        output.pop("DestinationEndPointList")
        success, _ = ApiRequest.set_scene_mark(scene_mode, scene_mark.json, privacy_dict)
        assert success == False
        #recover SceneMode
        scene_mode = json.loads(SCENE_MODE)
        #delete DeviceSecurityObject
        ApiRequest.set_security_object(None)
        success, _ = ApiRequest.set_scene_mark(scene_mode, scene_mark.json, privacy_dict)
        assert success == False
        #recover DeviceSecurityObject
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))

    def test_set_scene_data_image(self, mocker: MockerFixture):
        """
        test set_scene_data_image
        """
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api.requests import _WebAPI
        mocker.patch.object(_WebAPI, "post_json").return_value = {}
        scene_data = ApiRequest.new_scene_data(
            version="1.0",
            data_id="123",
            section=1,
            last_section=1,
            section_base64="XXXX",
            media_format="JPEG"
        )
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))
        scene_mode = json.loads(SCENE_MODE)

        #check
        success, _ = ApiRequest.set_scene_data_image(scene_mode, scene_data)
        assert success == True
        #TIME_LOG
        import src.niceapi.api.requests as flag
        flag.TIME_LOG = True
        success, _ = ApiRequest.set_scene_data_image(scene_mode, scene_data)
        assert success == True
        flag.TIME_LOG = False
        #test storage
        ApiRequest._has_storage = False
        success, _ = ApiRequest.set_scene_data_image(scene_mode, scene_data)
        assert success == True
        ApiRequest._has_storage = True

        #error "mode.image_config" 
        del scene_mode["Outputs"][1]
        success, _ = ApiRequest.set_scene_data_image(scene_mode, scene_data)
        assert success == False
        #recover scene_mode
        scene_mode = json.loads(SCENE_MODE)

        #error WebAPI
        mocker.patch.object(_WebAPI, "post_json").return_value = None
        success, _ = ApiRequest.set_scene_data_image(scene_mode, scene_data)
        assert success == False
        #recover WebAPI
        mocker.patch.object(_WebAPI, "post_json").return_value = {}

        #error "not objs"
        output = scene_mode["Outputs"][0]
        output.pop("DestinationEndPointList")
        success, _ = ApiRequest.set_scene_data_image(scene_mode, scene_data)
        assert success == False
        #recover SceneMode
        scene_mode = json.loads(SCENE_MODE)

        #delete DeviceSecurityObject
        ApiRequest.set_security_object(None)
        success, _ = ApiRequest.set_scene_data_image(scene_mode, scene_data)
        assert success == False
        #recover DeviceSecurityObject
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))

    def test_set_scene_data_video(self, mocker: MockerFixture):
        """
        test set_scene_data_video
        """
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api.requests import _WebAPI
        mocker.patch.object(_WebAPI, "post_json").return_value = {}
        scene_data = ApiRequest.new_scene_data(
            version="1.0",
            data_id="123",
            section=1,
            last_section=1,
            section_base64="XXXX",
            media_format="H.264"
        )
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))
        scene_mode = json.loads(SCENE_MODE)

        #check
        success, response = ApiRequest.set_scene_data_video(scene_mode, scene_data)
        assert success == True
        #TIME_LOG
        import src.niceapi.api.requests as flag
        flag.TIME_LOG = True
        success, response = ApiRequest.set_scene_data_video(scene_mode, scene_data)
        flag.TIME_LOG = False
        #test storage
        ApiRequest._has_storage = False
        success, response = ApiRequest.set_scene_data_video(scene_mode, scene_data)
        assert success == True
        ApiRequest._has_storage = True

        #error "mode.video_config" 
        del scene_mode["Outputs"][0]
        success, _ = ApiRequest.set_scene_data_video(scene_mode, scene_data)
        assert success == False
        #recover scene_mode
        scene_mode = json.loads(SCENE_MODE)

        #error WebAPI
        mocker.patch.object(_WebAPI, "post_json").return_value = None
        success, response = ApiRequest.set_scene_data_video(scene_mode, scene_data)
        assert success == False
        #recover WebAPI
        mocker.patch.object(_WebAPI, "post_json").return_value = {}

        #error "not objs"
        output = scene_mode["Outputs"][0]
        output.pop("DestinationEndPointList")
        success, response = ApiRequest.set_scene_data_video(scene_mode, scene_data)
        assert success == False
        #recover SceneMode
        scene_mode = json.loads(SCENE_MODE)

        #delete DeviceSecurityObject
        ApiRequest.set_security_object(None)
        success, response = ApiRequest.set_scene_data_video(scene_mode, scene_data)
        assert success == False
        #recover DeviceSecurityObject
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))

    def test_handle_request_swich_message_comfirm(self):
        """
        test handle_request_swich_message_comfirm
        """
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.cmf._request import _CMFRequest
        cmf = _CMFRequest()
        import src.niceapi.api.requests as flg
        flg.DUMP_MESSAGE = "1"
        def sign(payload):
            return False, None
        sign_bak = ApiRequest._jws_sign
        ApiRequest._jws_sign = sign
        assert ApiRequest._handle_request_encryption(
            crt="XXX",
            app="123",
            access_token=None,
            payload_object=None,
            cmf=cmf
        ) == None
        ApiRequest._jws_sign = sign_bak
        flg.DUMP_MESSAGE = "0"

    def test_handle_request_encryption_error(self, mocker: MockerFixture):
        """
        test __handle_request_encryption error case
        """
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.cmf._request import _CMFRequest
        cmf = _CMFRequest()
        from src.niceapi.api.requests import Encrypt
        mocker.patch.object(Encrypt, "encrypt").return_value = False, None
        assert ApiRequest._handle_request_encryption(
            crt="XXX",
            app="123",
            access_token="XXX",
            payload_object=None,
            cmf=cmf
        ) == None
        def sign(payload):
            return False, None
        sign_bak = ApiRequest._jws_sign
        ApiRequest._jws_sign = sign
        assert ApiRequest._handle_request_encryption(
            crt="XXX",
            app="123",
            access_token=None,
            payload_object=None,
            cmf=cmf
        ) == None
        ApiRequest._jws_sign = None
        assert ApiRequest._handle_request_encryption(
            crt="XXX",
            app="123",
            access_token=None,
            payload_object=None,
            cmf=cmf
        ) == None
        ApiRequest._jws_sign = sign_bak

    def test_handle_response_encryption_error_01(self, mocker: MockerFixture):
        """
        test __handle_response_encryption error case
        """
        from src.niceapi.api.requests import ApiRequest
        cmf = {"Version": "1.0"}
        response = {"SignedCMF": json.dumps(cmf)}
        def verify_ok(jws):
            return True, jws
        def verify_ng(jws):
            return False, None
        ApiRequest._jws_verify = None
        assert ApiRequest._handle_response_encryption(response) == None
        ApiRequest._jws_verify = verify_ng
        assert ApiRequest._handle_response_encryption(response) == None
        ApiRequest._jws_verify = verify_ok
        assert ApiRequest._handle_response_encryption(response) == None
        def decrypt_ok(jwe):
            return True, jwe
        def decrypt_ng(jwe):
            return False, None
        response = {"SignedCMF": json.dumps({
            "Version": "1.0",
            "MessageType": "response",
            "DateTimeStamp": "2020-01-01T00:00:00.000Z",
            "SourceEndPointID": "APP_END_POINT_ID",
            "DestinationEndPointID": "DEVICE_ID",
            "ReplyStatusCode": 0,
            "Payload": "XXX"
        })}
        assert ApiRequest._handle_response_encryption(response) == None
        response_no_payload = {"SignedCMF": json.dumps({
            "Version": "1.0",
            "MessageType": "response",
            "DateTimeStamp": "2020-01-01T00:00:00.000Z",
            "SourceEndPointID": "APP_END_POINT_ID",
            "DestinationEndPointID": "DEVICE_ID",
            "ReplyStatusCode": 0,
        })}
        assert ApiRequest._handle_response_encryption(response_no_payload) == None
        payload = {"ABC": "DEF"}
        cmf = {
            "Version": "1.0",
            "MessageType": "response",
            "DateTimeStamp": "2020-01-01T00:00:00.000Z",
            "SourceEndPointID": "APP_END_POINT_ID",
            "DestinationEndPointID": "DEVICE_ID",
            "ReplyStatusCode": 0,
            "Payload": json.dumps(payload)
        }
        response = {"SignedCMF": json.dumps(cmf)}
        ApiRequest._jwe_decrypt = decrypt_ng
        assert ApiRequest._handle_response_encryption(response) == None
        ApiRequest._jwe_decrypt = decrypt_ok

    def test_handle_management_request_error(self, mocker: MockerFixture):
        """
        test __handle_management_request error case
        """
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api._api import _ApiID, _ApiComponent

        # bad api
        assert ApiRequest._handle_management_request(
            api=_ApiComponent(_BadApi.BAD_API),
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None

        sign_bak = ApiRequest._jws_sign
        def ng_sign(payload):
            return False, None
        ApiRequest._jws_sign = ng_sign
        api = _ApiComponent(_ApiID.GET_MANAGEMENT_END_POINT)
        #delete DeviceSecurityObject
        ApiRequest.set_security_object(None)

        #check(not cmf_container)
        assert ApiRequest._handle_management_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None

        #recover DeviceSecurityObject
        ApiRequest.set_security_object(json.loads(SECURITY_OBJECT))
        assert ApiRequest._handle_management_request(
            api=_ApiComponent(_ApiID.GET_MANAGEMENT_END_POINT),
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None

        from src.niceapi.api.requests import Encrypt, Sign
        mocker.patch.object(Encrypt, "encrypt").return_value = True, "XXX"
        assert ApiRequest._handle_management_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None
        #recover custom
        ApiRequest.custom = False

        assert ApiRequest._handle_management_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None
        ApiRequest._jws_sign = sign_bak

        #decrypt error
        from src.niceapi.api.requests import _WebAPI
        mocker.patch.object(_WebAPI, "post_json").return_value = {}
        decrypt_bak = ApiRequest._jwe_decrypt
        def ng_decrypt(payload):
            return False, None
        ApiRequest._jwe_decrypt = ng_decrypt
        assert ApiRequest._handle_management_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None
        mocker.patch.object(_WebAPI, "post_json").return_value = None
        assert ApiRequest._handle_management_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None
        ApiRequest._jwe_decrypt = decrypt_bak

        payload = {
            "Version": "1.0",
            "MessageType": "response",
            "DateTimeStamp": "2020-01-01T00:00:00.000Z",
            "SourceEndPointID": "123",
            "DestinationEndPointID": "789",
            "ReplyStatusCode": 0,
            "Payload": "{\"ABC\": \"DEF\"}"
        }
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": json.dumps(payload)}
        assert ApiRequest._handle_management_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None

    def test_handle_control_request_error(self, mocker: MockerFixture):
        """
        test __handle_control_request error case
        """
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api._api import _ApiID, _ApiComponent
        # bad api
        assert ApiRequest._handle_control_request(
            api=_ApiComponent(_BadApi.BAD_API),
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token="XXX",
            node_id="001",
            authority="localhost",
            bearer="XXX",
            node="001"
        ) == None


        api = _ApiComponent(_ApiID.GET_SCENE_MODE)
        from src.niceapi.api.requests import Encrypt
        mocker.patch.object(Encrypt, "encrypt").return_value = False, None
        assert ApiRequest._handle_control_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token="XXX",
            node_id="001",
            authority="localhost",
            bearer="XXX",
            node="001"
        ) == None
        mocker.patch.object(Encrypt, "encrypt").return_value = True, "XXX"
        assert ApiRequest._handle_control_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            node_id="001",
            authority="localhost",
            bearer="XXX",
            node="001"
        ) == None
        def sign(payload):
            return True, payload.decode()
        sign_bak = ApiRequest._jws_sign
        ApiRequest._jws_sign = sign
        assert ApiRequest._handle_control_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            node_id="001",
            authority="localhost",
            bearer="XXX",
            node="001"
        ) == None
        ApiRequest._jws_sign = sign_bak

    def test_handle_privacy_request_error(self, mocker: MockerFixture):
        """
        test __handle_privacy_request error case
        """
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api._api import _ApiID, _ApiComponent
        #bad api
        assert ApiRequest._handle_privacy_request(
            api=_ApiComponent(_BadApi.BAD_API),
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token="XXX",
            key="001",
            authority="localhost",
            bearer="XXX",
            node="001"
        ) == None

        api = _ApiComponent(_ApiID.GET_PRIVACY_OBJECT)
        from src.niceapi.api.requests import Encrypt
        mocker.patch.object(Encrypt, "encrypt").return_value = False, None
        assert ApiRequest._handle_privacy_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token="XXX",
            key="001",
            authority="localhost",
            bearer="XXX",
            node="001"
        ) == None
        mocker.patch.object(Encrypt, "encrypt").return_value = True, "XXX"
        assert ApiRequest._handle_privacy_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            key="001",
            authority="localhost",
            bearer="XXX",
            node="001"
        ) == None
        def sign(payload):
            return True, payload.decode()
        sign_bak = ApiRequest._jws_sign
        ApiRequest._jws_sign = sign
        assert ApiRequest._handle_privacy_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            key="001",
            authority="localhost",
            bearer="XXX",
            node="001"
        ) == None
        ApiRequest._jws_sign = sign_bak

        payload = {
            "Version": "1.0",
            "MessageType": "response",
            "DateTimeStamp": "2020-01-01T00:00:00.000Z",
            "SourceEndPointID": "123",
            "DestinationEndPointID": "456",
            "ReplyStatusCode": 0,
            "Payload": "{\"ABC\": \"DEF\"}"
        }
        from src.niceapi.api.requests import _WebAPI
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": json.dumps(payload)}
        assert ApiRequest._handle_privacy_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            key="001",
            authority="localhost",
            bearer="XXX",
            node="001"
        ) == None

    def test_handle_datetime_request_error(self, mocker: MockerFixture):
        """
        test __handle_datetime_request error case
        """
        from src.niceapi.api._api import _ApiID, _ApiComponent
        from src.niceapi.api.requests import _WebAPI, ApiRequest, Encrypt
        #bad api
        assert ApiRequest._handle_datetime_request(
            api=_ApiComponent(_BadApi.BAD_API),
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token="XXX",
            authority="localhost",
            bearer="XXX"
        ) == None

        api = _ApiComponent(_ApiID.GET_DATE_TIME_LA)
        #error "not cmf_container"
        mocker.patch.object(Encrypt, "encrypt").return_value = False, None
        assert ApiRequest._handle_datetime_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token="XXX",
            authority="localhost",
            bearer="XXX"
        ) == None

        def sign(payload):
            return True, payload.decode()
        sign_bak = ApiRequest._jws_sign
        ApiRequest._jws_sign = sign

        #error "response is None"
        mocker.patch.object(Encrypt, "encrypt").return_value = True, "XXX"
        assert ApiRequest._handle_datetime_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None

        #error "cmf_response is None"
        payload = {"Payload": "XXX"}
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": json.dumps(payload)}
        assert ApiRequest._handle_datetime_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None

        # obj is None
        payload = {
            "Version": "1.0",
            "MessageType": "response",
            "DateTimeStamp": "2020-01-01T00:00:00.000Z",
            "SourceEndPointID": "789",
            "DestinationEndPointID": "123",
            "ReplyStatusCode": 0,
            "Payload": "{\"PayloadObject\": null}"
        }
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": json.dumps(payload)}
        assert ApiRequest._handle_datetime_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None

        # invalid src dst id
        payload = {
            "Version": "1.0",
            "MessageType": "response",
            "DateTimeStamp": "2020-01-01T00:00:00.000Z",
            "SourceEndPointID": "123",
            "DestinationEndPointID": "789",
            "ReplyStatusCode": 0,
            "Payload": "{\"PayloadObject\": null}"
        }
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": json.dumps(payload)}
        assert ApiRequest._handle_datetime_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None

        # invalid datetimestamp
        random = "xyz"
        datetime = {
            "Version": "1.0",
            "EndPointID": "END_POINT_ID",
            "ReturnedRandomChallenge": random,
            "DateTimeStamp": "123"
        }
        payload = {
            "Version": "1.0",
            "MessageType": "response",
            "DateTimeStamp": "2020-01-01T00:00:00.000Z",
            "SourceEndPointID": "789",
            "DestinationEndPointID": "123",
            "ReplyStatusCode": 0,
            "Payload": json.dumps({"PayloadObject": datetime})
        }
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": json.dumps(payload)}
        mocker.patch('src.niceapi.api.requests._get_random_hex', return_value=random)
        assert ApiRequest._handle_datetime_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None

        #invalid random
        datetime["ReturnedRandomChallenge"] = "abc"
        payload = {
            "Version": "1.0",
            "MessageType": "response",
            "DateTimeStamp": "2020-01-01T00:00:00.000Z",
            "SourceEndPointID": "789",
            "DestinationEndPointID": "123",
            "ReplyStatusCode": 0,
            "Payload": json.dumps({"PayloadObject": datetime})
        }
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": json.dumps(payload)}
        mocker.patch('src.niceapi.api.requests._get_random_hex', return_value=random)
        assert ApiRequest._handle_datetime_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None

        # no required key
        datetime.pop("Version")
        payload = {
            "Version": "1.0",
            "MessageType": "response",
            "DateTimeStamp": "2020-01-01T00:00:00.000Z",
            "SourceEndPointID": "789",
            "DestinationEndPointID": "123",
            "ReplyStatusCode": 0,
            "Payload": json.dumps({"PayloadObject": datetime})
        }
        mocker.patch.object(_WebAPI, "post_json").return_value = {"SignedCMF": json.dumps(payload)}
        assert ApiRequest._handle_datetime_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None

        #no SignedCMF
        """
        def response_random2(url, cmf, timeout=1000, token=None, verify=True):
            response = {
                "ReturnedRandomChallenge": random,
                "DateTimeStamp": None
            }
            encrypted = {"PayloadObject": response}
            payload = {"Payload": json.dumps(encrypted)}
            container = {"SignedCMF": json.dumps(payload)}
            return container
        mocker.patch.object(_WebAPI, "post_json").side_effect=response_random2
        """

        #error "obj is None"
        """
        mocker.patch.object(ApiRequest, "_handle_response_encryption").return_value = {}
        assert ApiRequest._handle_datetime_request(
            api=api,
            src="123",
            dst="456",
            app="789",
            crt="XXX",
            access_token=None,
            authority="localhost",
            bearer="XXX"
        ) == None
        """

        #recovery
        ApiRequest._jws_sign = sign_bak
        mocker.resetall()

    def test_create_tls_root_certs(self, mocker: MockerFixture):
        """
        test __create_tls_root_certs
        """
        from src.niceapi.api.requests import ApiRequest
        def _to_pem(param):
            return param
        mocker.patch("src.niceapi.api.requests._to_pem").side_effect = _to_pem
        certs = ApiRequest._create_tls_root_certs(
            sec_root_certs=["ABC", ""],
            mng_root_certs=["DEF","GHI", ""],
            ctrl_root_certs=["JKL", ""]
        )
        assert certs == ["ABC", "DEF", "GHI", "JKL"]
        # no update
        certs = ApiRequest._create_tls_root_certs(
            sec_root_certs=[""],
            mng_root_certs=[""],
            ctrl_root_certs=[""]
        )
        assert certs == []
        # updated but empty mng_root & ctrl_root
        ApiRequest._sec_root_certs = None
        ApiRequest._mng_root_certs = None
        ApiRequest._ctrl_root_certs = None
        certs = ApiRequest._create_tls_root_certs(
            sec_root_certs=["ABC"],
            mng_root_certs=[""],
            ctrl_root_certs=[""]
        )
        assert certs == ["ABC"]
        # updated but empty sec
        ApiRequest._sec_root_certs = None
        ApiRequest._mng_root_certs = None
        ApiRequest._ctrl_root_certs = None
        certs = ApiRequest._create_tls_root_certs(
            sec_root_certs=[],
            mng_root_certs=["DEF"],
            ctrl_root_certs=[""]
        )
        assert certs == ["DEF"]

    def test_set_webapi(self, mocker: MockerFixture):
        """
        set custom WebAPI
        """
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.io.webapi_base import WebAPIBase
        class WebAPICustom(WebAPIBase):
            def post(self, url, headers, body, timeout=5, token=None, verify=True):
                return {"SignedCMF": {"Custom": True}}
            def update_root_cert(self, tls_root_certs=None):
                return None

        ApiRequest.set_webapi(WebAPICustom())

        from src.niceapi.api.requests import Encrypt
        mocker.patch.object(Encrypt, "encrypt").return_value = True, "XXXX"
        #set dummy jose
        def verify(param):
            assert param == {"Custom": True}
            encrypted = {"PayloadObject": {"ABC": "DEF"}}
            payload = {
                "Version": "1.0",
                "MessageType": "response",
                "DateTimeStamp": "2020-01-01T00:00:00.000Z",
                "SourceEndPointID": "END_POINT_ID",
                "DestinationEndPointID": "DEVICE_ID",
                "ReplyStatusCode": 0,
                "Payload": json.dumps(encrypted)
            }
            return True, json.dumps(payload)
        def decrypt(param):
            return True, param
        class _StubSign:
            def __call__(self, param):
                return True, param.decode()
            def update_certificate(self, param):pass
        ApiRequest._jws_verify = verify
        ApiRequest._jwe_decrypt = decrypt
        ApiRequest._jws_sign = _StubSign()
        mocker.patch("src.niceapi.api.security._check_certificate").return_value = True
        mocker.patch("src.niceapi.api.requests.ManagementEndPoint.is_available").return_value = True
        ApiRequest.security.json = json.loads(SECURITY_OBJECT)
        assert ApiRequest.get_management_end_point() == True

    def test_set_max_connection(self):
        """
        set maximum number of connection
        """
        LIMIT = 100
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.io._webapi import _WebAPI
        ApiRequest.set_max_connection(LIMIT)
        assert _WebAPI._semaphore._initial_value == LIMIT

    def test_handle_json_data_request_error(self, mocker):
        """
        test __handle_json_data_request error case
        """
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api._api import _ApiID, _ApiComponent
        #bad api
        assert ApiRequest._handle_json_data_request(
            api=_ApiComponent(_BadApi.BAD_API),
            dst="123",
            payload={},
            authority="localhost",
            bearer="XXX",
            node="NODE",
            port="PORT"
        ) == None

    def test_handle_text_data_request_error(self, mocker):
        """
        test __handle_text_data_request error case
        """
        from src.niceapi.api.requests import ApiRequest
        from src.niceapi.api._api import _ApiID, _ApiComponent
        #bad api
        assert ApiRequest._handle_text_data_request(
            api=_ApiComponent(_BadApi.BAD_API),
            dst="123",
            payload={},
            authority="localhost",
            bearer="XXX",
            node="NODE",
            port="PORT"
        ) == None
