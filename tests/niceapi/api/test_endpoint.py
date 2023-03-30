import json
import pytest
from src.niceapi.api.endpoint import ManagementEndPoint

MANAGEMENT_END_POINT = """
{
  "Version": "1.0",
  "NICELAEndPoint": {
    "AppEndPoint": {
      "APIVersion": "1.0",
      "EndPointID": "APP_END_POINT_ID",
      "AccessToken": "ACCESS_TOKEN",
      "X.509Certificate": ["XXXXX"]
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
  },
  "DeviceCertificate": [
    "XXXXX"
  ]
}
"""

@pytest.fixture
def management_endpoint():
    endpoint = ManagementEndPoint()
    endpoint.json = json.loads(MANAGEMENT_END_POINT)
    return endpoint

class TestControlObject:
    """ControlObject test class."""

    def test_if_available(self, management_endpoint):
        """
        test if available
        """
        assert management_endpoint.is_available == True

    def test_if_not_available(self):
        """
        test before setting json
        """
        management_endpoint = ManagementEndPoint()
        assert management_endpoint.is_available == False

    def test_property_json(self, management_endpoint):
        """
        test the getter of json
        """
        assert management_endpoint.json == json.loads(MANAGEMENT_END_POINT)

    def test_setter_json(self):
        """
        test the setter of json
        """
        management_endpoint = ManagementEndPoint()
        test_json = json.loads(MANAGEMENT_END_POINT)
        la_endpoint = test_json["NICELAEndPoint"]
        app_endpoint = la_endpoint["AppEndPoint"]
        app_endpoint.pop("X.509Certificate")
        net_endpoint = la_endpoint["NetEndPoint"]
        net_endpoint["Scheme"][0]["Protocol"] = "MQTTScheme"
        management_endpoint.json = test_json
        assert management_endpoint.is_available == True
        test_json = json.loads(MANAGEMENT_END_POINT)
        management_endpoint.json = test_json
        assert management_endpoint.is_available == True

    def test_setter_json_error(self):
        """
        test the setter of json error
        """
        management_endpoint = ManagementEndPoint()
        test_json = json.loads(MANAGEMENT_END_POINT)
        app_endpoint = test_json["NICELAEndPoint"]["AppEndPoint"]
        # remove required parameter
        app_endpoint.pop("APIVersion")
        management_endpoint.json = test_json
        assert management_endpoint.is_available == False
        management_endpoint.json = {"ABC": "DEF"}
        assert management_endpoint.is_available == False

    def test_property_app_end_point_id(self, management_endpoint):
        """
        test the getter of app_end_point_id
        """
        assert management_endpoint.app_end_point_id == "APP_END_POINT_ID"

    def test_setter_app_end_point_id(self, management_endpoint):
        """
        test if there is no setter of app_end_point_id
        """
        with pytest.raises(AttributeError):
            management_endpoint.app_end_point_id = "XXXXX"

    def test_property_app_access_token(self, management_endpoint):
        """
        test the getter of app_access_token
        """
        assert management_endpoint.app_access_token == "ACCESS_TOKEN"

    def test_setter_app_access_token(self, management_endpoint):
        """
        test if there is no setter of app_access_token
        """
        with pytest.raises(AttributeError):
            management_endpoint.app_access_token = "XXXXX"

    def test_property_certificate(self, mocker):
        """
        test the getter of certificate
        """
        mocker.patch("src.niceapi.api.endpoint._check_certificate").return_value = True
        test_obj = json.loads(MANAGEMENT_END_POINT)
        management_endpoint = ManagementEndPoint()
        management_endpoint.json = test_obj
        assert management_endpoint.certificate == "XXXXX"

    def test_setter_certificate(self, management_endpoint):
        """
        test if there is no setter of certificate
        """
        with pytest.raises(AttributeError):
            management_endpoint.certificate = "XXXXX"

    def test_property_net_end_point_id(self, management_endpoint):
        """
        test the getter of net_end_point_id
        """
        assert management_endpoint.net_end_point_id == "NET_END_POINT_ID"

    def test_setter_net_end_point_id(self, management_endpoint):
        """
        test if there is no setter of net_end_point_id
        """
        with pytest.raises(AttributeError):
            management_endpoint.net_end_point_id = "XXXXX"

    def test_property_scheme(self, management_endpoint):
        """
        test the getter of scheme
        """
        scheme = management_endpoint.scheme[0]
        assert  scheme.authority == "localhost" and scheme.access_token =="BEARER"

    def test_setter_scheme(self, management_endpoint):
        """
        test if there is no setter of scheme
        """
        with pytest.raises(AttributeError):
            management_endpoint.scheme = ["XXXXX"]

    def test_property_device_certificate(self, mocker):
        """
        test the getter of device_certificate
        """
        mocker.patch("src.niceapi.api.endpoint._check_certificate").return_value = True
        test_obj = json.loads(MANAGEMENT_END_POINT)
        management_endpoint = ManagementEndPoint()
        management_endpoint.json = test_obj
        assert management_endpoint.device_certificate == ["XXXXX"]
        test_obj["DeviceCertificate"] = "XXXXX"
        management_endpoint.json = test_obj
        assert management_endpoint.device_certificate == None

    def test_setter_device_certificate(self, mocker):
        """
        test if there is no setter of device_certificate
        """
        mocker.patch("src.niceapi.api.endpoint._check_certificate").return_value = True
        test_obj = json.loads(MANAGEMENT_END_POINT)
        management_endpoint = ManagementEndPoint()
        management_endpoint.json = test_obj
        with pytest.raises(AttributeError):
            management_endpoint.device_certificate = ["XXXXX"]

