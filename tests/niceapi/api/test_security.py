import json
import pytest
from src.niceapi.api.security import DeviceSecurityObject

SECURITY_OBJECT = """
{
  "Version": "1.0",
  "DeviceID": "DEVICE_ID",
  "DevicePassword": "PASSWORD",
  "DevicePrivateKey": {
    "EncryptionKeyID": "KEY_ID",
    "EncryptedKey": "XXXXX"
  },
  "NICELARootCertificate": ["XXXXX"],
  "MasterIssuerID": "ISSUER_ID",
  "NICELAEndPoint": {
    "APIVersion": "1.0",
    "EndPointID": "END_POINT_ID",
    "Scheme": [
      {
        "Protocol": "WebAPI",
        "Authority": "localhost",
        "AccessToken": "BEARER",
        "Role": "Client"
      }
    ]
  },
  "AllowedTLSRootCertificates": [
    "XXXXX"
  ],
  "DeviceCertificate": [
    "XXXXX"
  ]
}
"""

@pytest.fixture
def security_object():
    security = DeviceSecurityObject()
    security.json = json.loads(SECURITY_OBJECT)
    return security

class TestDeviceSecurityObject:
    """DeviceSecurityObject test class."""

    def test_if_available(self, security_object):
        """
        test if available
        """
        assert security_object.is_available == True

    def test_if_not_available(self):
        """
        test before setting json
        """
        security_object = DeviceSecurityObject()
        assert security_object.is_available == False

    def test_property_json(self, security_object):
        """
        test the getter of json
        """
        assert security_object.json == json.loads(SECURITY_OBJECT)

    def test_setter_json(self):
        """
        test the setter of json
        """
        security_object = DeviceSecurityObject()
        test_obj = json.loads(SECURITY_OBJECT)
        endpoint = test_obj["NICELAEndPoint"]
        endpoint["Scheme"][0]["Protocol"] = "MQTTScheme"
        security_object.json = test_obj
        assert security_object.is_available == True
        test_obj["AllowedTLSRootCertificates"] = "XXX"
        security_object.json = test_obj
        assert security_object.is_available == True
        security_object.json = {"ABC": "DEF"}
        assert security_object.is_available == False

    def test_setter_json_error(self):
        """
        test the setter of json error
        """
        security_object = DeviceSecurityObject()
        test_obj = json.loads(SECURITY_OBJECT)
        private_key = test_obj["DevicePrivateKey"]
        # remove required parameter
        private_key.pop("EncryptionKeyID")
        security_object.json = test_obj
        assert security_object.is_available == False
        test_obj = json.loads(SECURITY_OBJECT)
        net_endpoint = test_obj["NICELAEndPoint"]
        # remove required parameter
        net_endpoint.pop("EndPointID")
        security_object.json = test_obj
        assert security_object.is_available == False

    def test_property_device_id(self, security_object):
        """
        test the getter of device_id
        """
        assert security_object.device_id == "DEVICE_ID"

    def test_setter_device_id(self, security_object):
        """
        test if there is no setter of device_id
        """
        with pytest.raises(AttributeError):
            security_object.device_id = "XXXXX"

    def test_property_device_private_key(self, security_object):
        """
        test the setter/getter of device_private_key
        """
        security_object.device_private_key = "XXX"
        assert security_object.device_private_key == "XXX"

    def test_property_device_certificate(self, mocker):
        """
        test the getter of device_certificate
        """
        mocker.patch("src.niceapi.api.security._check_certificate").return_value = True
        test_obj = json.loads(SECURITY_OBJECT)
        security_object = DeviceSecurityObject()
        security_object.json = test_obj
        assert security_object.device_certificate == ["XXXXX"]

    def test_str_device_certificate(self, mocker):
        """
        test string of device_certificate
        """
        mocker.patch("src.niceapi.api.security._check_certificate").return_value = True
        test_obj = json.loads(SECURITY_OBJECT)
        test_obj["DeviceCertificate"] = "XXXXX"
        security_object = DeviceSecurityObject()
        security_object.json = test_obj
        assert security_object.device_certificate == None

    def test_setter_device_certificate(self, mocker):
        """
        test if there is no setter of device_certificate
        """
        mocker.patch("src.niceapi.api.security._check_certificate").return_value = True
        test_obj = json.loads(SECURITY_OBJECT)
        security_object = DeviceSecurityObject()
        security_object.json = test_obj
        with pytest.raises(AttributeError):
            security_object.device_certificate = ["XXXXX"]
    
    def test_property_nice_la_root_certificate(self, mocker):
        """
        test the getter of nice_la_root_certificate
        """
        mocker.patch("src.niceapi.api.security._check_certificate").return_value = True
        test_obj = json.loads(SECURITY_OBJECT)
        security_object = DeviceSecurityObject()
        security_object.json = test_obj
        assert security_object.nice_la_root_certificate == ["XXXXX"]

    def test_str_nice_la_root_certificate(self, mocker):
        """
        test string of nice_la_root_certificate
        """
        mocker.patch("src.niceapi.api.security._check_certificate").return_value = True
        test_obj = json.loads(SECURITY_OBJECT)
        test_obj["NICELARootCertificate"] = "XXXXX"
        security_object = DeviceSecurityObject()
        security_object.json = test_obj
        assert security_object.nice_la_root_certificate == None

    def test_setter_nice_la_root_certificate(self, mocker):
        """
        test if there is no setter of nice_la_root_certificate
        """
        mocker.patch("src.niceapi.api.security._check_certificate").return_value = True
        test_obj = json.loads(SECURITY_OBJECT)
        security_object = DeviceSecurityObject()
        security_object.json = test_obj
        with pytest.raises(AttributeError):
            security_object.nice_la_root_certificate = "XXXXX"

    def test_property_net_end_point_id(self, security_object):
        """
        test the getter of net_end_point_id
        """
        assert security_object.net_end_point_id == "END_POINT_ID"

    def test_setter_net_end_point_id(self, security_object):
        """
        test if there is no setter of net_end_point_id
        """
        with pytest.raises(AttributeError):
            security_object.net_end_point_id = "END_POINT_ID"

    def test_property_scheme(self, security_object):
        """
        test the getter of scheme
        """
        scheme = security_object.scheme[0]
        assert  scheme.authority == "localhost" and scheme.access_token =="BEARER"

    def test_setter_scheme(self, security_object):
        """
        test if there is no setter of scheme
        """
        with pytest.raises(AttributeError):
            security_object.scheme = None

    def test_property_allowed_tls_root_certificates(self, mocker):
        """
        test the getter of allowed_tls_root_certificates
        """
        mocker.patch("src.niceapi.api.security._check_certificate").return_value = True
        test_obj = json.loads(SECURITY_OBJECT)
        security_object = DeviceSecurityObject()
        security_object.json = test_obj
        assert security_object.allowed_tls_root_certificates == ["XXXXX"]

    def test_setter_allowed_tls_root_certificates(self, mocker):
        """
        test if there is no setter of allowed_tls_root_certificates
        """
        mocker.patch("src.niceapi.api.security._check_certificate").return_value = True
        test_obj = json.loads(SECURITY_OBJECT)
        security_object = DeviceSecurityObject()
        security_object.json = test_obj
        with pytest.raises(AttributeError):
            security_object.allowed_tls_root_certificates = ["XXXXX"]
