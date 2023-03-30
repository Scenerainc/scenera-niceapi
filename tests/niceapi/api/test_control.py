import json
import pytest
from src.niceapi.api.control import ControlObject

CONTROL_OBJECT = """
{
  "Version": "1.0",
  "DeviceID": "DEVICE_ID",
  "ControlEndPoints": [
    {
      "AppEndPoint": {
        "APIVersion": "1.0",
        "EndPointID": "APP_END_POINT_ID",
        "X.509Certificate": [
          "XXXXX"
        ],
        "AccessToken": "ACCESS_TOKEN"
      },
      "NetEndPoint": {
        "APIVersion": "1.0",
        "EndPointID": "NET_END_POINT_ID",
        "NodeID": "0001",
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
  ],
  "AllowedTLSRootCertificates": ["XXXXX"]
}
"""

@pytest.fixture
def control_object():
    control = ControlObject()
    control.json = json.loads(CONTROL_OBJECT)
    return control

class TestControlObject:
    """ControlObject test class."""

    def test_if_available(self, control_object):
        """
        test if available
        """
        assert control_object.is_available == True

    def test_if_not_available(self):
        """
        test before setting json
        """
        control_object = ControlObject()
        assert control_object.is_available == False

    def test_property_json(self, control_object):
        """
        test the getter of json
        """
        assert control_object.json == json.loads(CONTROL_OBJECT)

    def test_setter_json(self):
        """
        test the setter of json
        """
        control_object = ControlObject()
        test_obj = json.loads(CONTROL_OBJECT)
        endpoint = test_obj["ControlEndPoints"][0]
        app_endpoint = endpoint["AppEndPoint"]
        app_endpoint.pop("X.509Certificate")
        net_endpoint = endpoint["NetEndPoint"]
        net_endpoint["Scheme"][0]["Protocol"] = "MQTTScheme"
        control_object.json = test_obj
        assert control_object.is_available == True

    def test_setter_json_error(self):
        """
        test the setter of json error
        """
        control_object = ControlObject()
        test_obj = json.loads(CONTROL_OBJECT)
        endpoint = test_obj["ControlEndPoints"][0]
        # remove array
        test_obj["ControlEndPoints"] = endpoint
        control_object.json = test_obj
        assert control_object.is_available == False
        test_obj = json.loads(CONTROL_OBJECT)
        app_endpoint = test_obj["ControlEndPoints"][0]["AppEndPoint"]
        app_endpoint.pop("APIVersion")
        control_object.json = test_obj
        assert control_object.is_available == False
        control_object.json = {"ABC", "DEF"}
        assert control_object.is_available == False

    def test_property_app_end_point_id(self, control_object):
        """
        test the getter of app_end_point_id
        """
        assert control_object.app_end_point_id == "APP_END_POINT_ID"

    def test_setter_app_end_point_id(self, control_object):
        """
        test if there is no setter of app_end_point_id
        """
        with pytest.raises(AttributeError):
            control_object.app_end_point_id = "XXXXX"

    def test_property_app_access_token(self, control_object):
        """
        test the getter of app_access_token
        """
        assert control_object.app_access_token == "ACCESS_TOKEN"

    def test_setter_app_access_token(self, control_object):
        """
        test if there is no setter of app_access_token
        """
        with pytest.raises(AttributeError):
            control_object.app_access_token = "XXXXX"

    def test_property_certificate(self, mocker):
        """
        test the getter of certificate
        """
        mocker.patch("src.niceapi.api.control._check_certificate").return_value = True
        test_obj = json.loads(CONTROL_OBJECT)
        control_object = ControlObject()
        control_object.json = test_obj
        assert control_object.certificate == "XXXXX"

    def test_setter_certificate(self, control_object):
        """
        test if there is no setter of certificate
        """
        with pytest.raises(AttributeError):
            control_object.certificate = "XXXXX"

    def test_property_net_end_point_id(self, control_object):
        """
        test the getter of net_end_point_id
        """
        assert control_object.net_end_point_id == "NET_END_POINT_ID"

    def test_setter_net_end_point_id(self, control_object):
        """
        test if there is no setter of net_end_point_id
        """
        with pytest.raises(AttributeError):
            control_object.net_end_point_id = "XXXXX"

    def test_property_node_id(self, control_object):
        """
        test the getter of node_id
        """
        assert control_object.node_id == "0001"

    def test_setter_node_id(self, control_object):
        """
        test if there is no setter of node_id
        """
        with pytest.raises(AttributeError):
            control_object.node_id = "XXXXX"

    def test_property_scheme(self, control_object):
        """
        test the getter of scheme
        """
        scheme = control_object.scheme[0]
        assert  scheme.authority == "localhost" and scheme.access_token =="BEARER"

    def test_setter_scheme(self, control_object):
        """
        test if there is no setter of scheme
        """
        with pytest.raises(AttributeError):
            control_object.scheme = ["XXXXX"]

    def test_property_allowed_tls_root_certificates(self, mocker):
        """
        test the getter of allowed_tls_root_certificates
        """
        mocker.patch("src.niceapi.api.control._check_certificate").return_value = True
        test_obj = json.loads(CONTROL_OBJECT)
        control_object = ControlObject()
        control_object.json = test_obj
        assert control_object.allowed_tls_root_certificates == ["XXXXX"]
        test_obj.pop("AllowedTLSRootCertificates")
        print(json.dumps(test_obj, indent=2))
        control_object.json = test_obj
        assert control_object.allowed_tls_root_certificates == None

    def test_setter_allowed_tls_root_certificates(self, mocker):
        """
        test if there is no setter of allowed_tls_root_certificates
        """
        mocker.patch("src.niceapi.api.control._check_certificate").return_value = True
        test_obj = json.loads(CONTROL_OBJECT)
        control_object = ControlObject()
        control_object.json = test_obj
        with pytest.raises(AttributeError):
            control_object.allowed_tls_root_certificates = ["XXXXX"]

