import json
import pytest
from src.niceapi.api.management import ManagementObject

MANAGEMENT_OBJECT = """
{
  "Version": "1.0",
  "DeviceID": "DEVICE_ID",
  "NICEAS": {
    "NICEASID": "AS_ID",
    "NICEASName": "Scenera NICE Account Service",
    "NICEASEndPoint": {
      "AppEndPoint": {
        "APIVersion": "1.0",
        "EndPointID": "APP_END_POINT_ID",
        "X.509Certificate": ["XXXXX"],
        "AccessToken": "ACCESS_TOKEN"
      },
      "NetEndPoint": {
        "APIVersion": "1.0",
        "EndPointID": "NET_END_POINT_ID",
        "Scheme": [
          {
            "Protocol": "WebAPI",
            "Authority": "localhost",
            "Role": "Client",
            "AccessToken": "BEARER"
          }
        ]
      }
    }
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
def management_object():
    management = ManagementObject()
    management.json = json.loads(MANAGEMENT_OBJECT)
    return management

class TestManagementObject:
    """ManagementObject test class."""

    def test_if_available(self, management_object):
        """
        test if available
        """
        assert management_object.is_available == True

    def test_if_not_available(self):
        """
        test before setting json
        """
        management_object = ManagementObject()
        assert management_object.is_available == False

    def test_property_json(self, management_object):
        """
        test the getter of json
        """
        assert management_object.json == json.loads(MANAGEMENT_OBJECT)

    def test_setter_json(self):
        """
        test the setter of json
        """
        management_object = ManagementObject()
        test_obj = json.loads(MANAGEMENT_OBJECT)
        endpoint = test_obj["NICEAS"]["NICEASEndPoint"]
        app_endpoint = endpoint["AppEndPoint"]
        app_endpoint.pop("X.509Certificate")
        net_endpoint = endpoint["NetEndPoint"]
        net_endpoint["Scheme"][0]["Protocol"] = "MQTTScheme"
        test_obj.pop("DeviceCertificate")
        management_object.json = test_obj
        assert management_object.is_available == True
        test_obj["AllowedTLSRootCertificates"] = "XXX"
        management_object.json = test_obj
        assert management_object.is_available == True

    def test_setter_json_error(self):
        """
        test the setter of json error
        """
        management_object = ManagementObject()
        test_obj = json.loads(MANAGEMENT_OBJECT)
        niceas = test_obj["NICEAS"]
        # remove required parameter
        niceas.pop("NICEASID")
        management_object.json = test_obj
        assert management_object.is_available == False
        test_obj = json.loads(MANAGEMENT_OBJECT)
        app_endpoint = test_obj["NICEAS"]["NICEASEndPoint"]["AppEndPoint"]
        # remove required parameter
        app_endpoint.pop("APIVersion")
        management_object.json = test_obj
        assert management_object.is_available == False

    def test_property_nice_as_id(self, management_object):
        """
        test the getter of app_end_point_id
        """
        assert management_object.nice_as_id == "AS_ID"

    def test_setter_nice_as_id(self, management_object):
        """
        test if there is no setter of app_end_point_id
        """
        with pytest.raises(AttributeError):
            management_object.nice_as_id = "XXXXX"

    def test_property_app_end_point_id(self, management_object):
        """
        test the getter of app_end_point_id
        """
        assert management_object.app_end_point_id == "APP_END_POINT_ID"

    def test_setter_app_end_point_id(self, management_object):
        """
        test if there is no setter of app_end_point_id
        """
        with pytest.raises(AttributeError):
            management_object.app_end_point_id = "XXXXX"

    def test_property_app_access_token(self, management_object):
        """
        test the getter of app_access_token
        """
        assert management_object.app_access_token == "ACCESS_TOKEN"

    def test_setter_app_access_token(self, management_object):
        """
        test if there is no setter of app_access_token
        """
        with pytest.raises(AttributeError):
            management_object.app_access_token = "XXXXX"

    def test_property_certificate(self, mocker):
        """
        test the getter of certificate
        """
        mocker.patch("src.niceapi.api.management._check_certificate").return_value = True
        test_obj = json.loads(MANAGEMENT_OBJECT)
        management_object = ManagementObject()
        management_object.json = test_obj
        assert management_object.certificate == "XXXXX"

    def test_setter_certificate(self, management_object):
        """
        test if there is no setter of certificate
        """
        with pytest.raises(AttributeError):
            management_object.certificate = "XXXXX"

    def test_property_net_end_point_id(self, management_object):
        """
        test the getter of net_end_point_id
        """
        assert management_object.net_end_point_id == "NET_END_POINT_ID"

    def test_setter_net_end_point_id(self, management_object):
        """
        test if there is no setter of net_end_point_id
        """
        with pytest.raises(AttributeError):
            management_object.net_end_point_id = "XXXXX"

    def test_property_scheme(self, management_object):
        """
        test the getter of scheme
        """
        scheme = management_object.scheme[0]
        assert  scheme.authority == "localhost" and scheme.access_token =="BEARER"

    def test_setter_scheme(self, management_object):
        """
        test if there is no setter of scheme
        """
        with pytest.raises(AttributeError):
            management_object.scheme = None

    def test_property_allowed_tls_root_certificates(self, mocker):
        """
        test the getter of allowed_tls_root_certificates
        """
        mocker.patch("src.niceapi.api.management._check_certificate").return_value = True
        test_obj = json.loads(MANAGEMENT_OBJECT)
        management_object = ManagementObject()
        management_object.json = test_obj
        assert management_object.allowed_tls_root_certificates == ["XXXXX"]

    def test_setter_allowed_tls_root_certificates(self, mocker):
        """
        test if there is no setter of allowed_tls_root_certificates
        """
        mocker.patch("src.niceapi.api.management._check_certificate").return_value = True
        test_obj = json.loads(MANAGEMENT_OBJECT)
        management_object = ManagementObject()
        management_object.json = test_obj
        with pytest.raises(AttributeError):
            management_object.allowed_tls_root_certificates = ["XXXXX"]

    def test_property_device_certificate(self, mocker):
        """
        test the getter of device_certificate
        """
        mocker.patch("src.niceapi.api.management._check_certificate").return_value = True
        test_obj = json.loads(MANAGEMENT_OBJECT)
        management_object = ManagementObject()
        management_object.json = test_obj
        assert management_object.device_certificate == ["XXXXX"]

    def test_setter_device_certificate(self, mocker):
        """
        test if there is no setter of device_certificate
        """
        mocker.patch("src.niceapi.api.management._check_certificate").return_value = True
        test_obj = json.loads(MANAGEMENT_OBJECT)
        management_object = ManagementObject()
        management_object.json = test_obj
        with pytest.raises(AttributeError):
            management_object.device_certificate = ["XXXXX"]

