import json
import pytest
from src.niceapi.api.common import WebAPIScheme, _is_valid_net_endpoint, _is_valid_endpoint

AUTHORITY = "localhost"
ACCESS_TOKEN = "ABCDEFG"
ENDPOINT = """
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
"""

@pytest.fixture
def scheme():
    return WebAPIScheme(AUTHORITY, ACCESS_TOKEN)
    
class TestCommon:
    """Common test class."""

    def test_property_authority(self, scheme):
        """
        test the getter of authority
        """
        assert scheme.authority == AUTHORITY

    def test_setter_authority(self, scheme):
        """
        test if there is no setter of authority
        """
        with pytest.raises(AttributeError):
            scheme.authority = "test.com"

    def test_property_access_token(self, scheme):
        """
        test the getter of access_token
        """
        assert scheme.access_token == ACCESS_TOKEN

    def test_setter_access_token(self, scheme):
        """
        test if there is no setter of access_token
        """
        with pytest.raises(AttributeError):
            scheme.access_token = "XXXXX"

    def test_is_valid_endpoint(self):
        """
        test lack of required key
        """
        endpoint = json.loads(ENDPOINT)
        # remove required key
        endpoint.pop("NetEndPoint")
        assert _is_valid_endpoint(endpoint) == False
        endpoint = json.loads(ENDPOINT)
        net_endpoint = endpoint["NetEndPoint"]
        scheme = net_endpoint["Scheme"][0]
        # remove array
        net_endpoint["Scheme"] = scheme
        assert _is_valid_endpoint(endpoint) == False
        endpoint = json.loads(ENDPOINT)
        net_endpoint = endpoint["NetEndPoint"]
        scheme = net_endpoint["Scheme"][0]
        # remove required key
        scheme.pop("Protocol")
        assert _is_valid_endpoint(endpoint) == False
