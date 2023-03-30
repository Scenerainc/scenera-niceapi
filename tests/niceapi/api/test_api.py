import pytest
from src.niceapi.api._api import _ApiID, _ApiComponent

class TestApiComponent:
    """_ApiComponent test class."""

    def test_property_api(self):
        """
        test the getter of api
        """
        api_component = _ApiComponent(_ApiID.GET_MANAGEMENT_END_POINT)
        assert api_component.api == _ApiID.GET_MANAGEMENT_END_POINT

    def test_setter_api(self):
        """
        test if there is no setter of api
        """
        api_component = _ApiComponent(_ApiID.GET_MANAGEMENT_END_POINT)
        with pytest.raises(AttributeError):
            api_component.api = _ApiID.GET_CONTROL_OBJECT

    def test_command_type_management(self):
        """
        test CommandType generation for management
        """
        ENDPOINT = "UUID"
        COMMAND_TYPE = f"/1.0/{ENDPOINT}/management/GetManagementObject"
        api_component = _ApiComponent(_ApiID.GET_MANAGEMENT_OBJECT)
        assert api_component.get_command_type(ENDPOINT) == COMMAND_TYPE

    def test_command_type_scenemode(self):
        """
        test CommandType generation for SceneMode
        """
        ENDPOINT = "UUID"
        NODE_ID = "0001"
        COMMAND_TYPE = f"/1.0/{ENDPOINT}/control/{NODE_ID}/GetSceneMode"
        api_component = _ApiComponent(_ApiID.GET_SCENE_MODE)
        assert api_component.get_command_type(ENDPOINT, NODE_ID) == COMMAND_TYPE

    def test_command_type_data(self):
        """
        test CommandType generation for data (no need anymore)
        """
        ENDPOINT = "UUID"
        COMMAND_TYPE = "SetSceneMark"
        api_component = _ApiComponent(_ApiID.SET_SCENE_MARK)
        assert api_component.get_command_type(ENDPOINT) == COMMAND_TYPE

    def test_command_type_error(self):
        """
        test CommandType generation error
        """
        ENDPOINT = "UUID"
        api_component = _ApiComponent(None)
        assert api_component.get_command_type(ENDPOINT) is None

    def test_payload_node(self):
        """
        test Payload generation of NodeID
        """
        NODE_ID = "01"
        PAYLOAD = {"Version": "1.0", "NodeID": NODE_ID}
        api_component = _ApiComponent(_ApiID.GET_SCENE_MODE)
        assert api_component.get_payload_node(NODE_ID) == PAYLOAD

    def test_payload_key(self):
        """
        test Payload generation of SceneEncryptionKeyID
        """
        KEY_ID = "01"
        PAYLOAD = {"Version": "1.0", "SceneEncryptionKeyID": KEY_ID}
        api_component = _ApiComponent(_ApiID.GET_PRIVACY_OBJECT)
        assert api_component.get_payload_key(KEY_ID) == PAYLOAD

    def test_payload_random(self):
        """
        test Payload generation of random
        """
        ENDPOINT = "UUID"
        RANDOM = "XXXXX"
        PAYLOAD = {"Version": "1.0", "EndPointID": ENDPOINT, "RandomChallenge": RANDOM}
        api_component = _ApiComponent(_ApiID.GET_DATE_TIME_LA)
        assert api_component.get_payload_random(ENDPOINT, RANDOM) == PAYLOAD

    def test_unwrap_payload(self):
        """
        test Payload unwrapping
        """
        OBJECT = {"ABC": "DEF"}
        PAYLOAD = {"PayloadObject": OBJECT}
        api_component = _ApiComponent(_ApiID.GET_MANAGEMENT_END_POINT)
        assert api_component.unwrap_payload(PAYLOAD) == OBJECT

    def test_unwrap_payload_error(self):
        """
        test Payload unwrapping error
        """
        BODY = "XXXXX"
        PAYLOAD = {"Payload": BODY}
        api_component = _ApiComponent(_ApiID.GET_MANAGEMENT_END_POINT)
        assert api_component.unwrap_payload(PAYLOAD) is None

    def test_get_url_when_authority_is_none(self):
        """
        test get_url wehen authority is None
        """
        AUTHORITY = None
        ENDPOINT = "UUID"
        api_component = _ApiComponent(_ApiID.GET_MANAGEMENT_END_POINT)

        assert api_component.get_url(AUTHORITY, ENDPOINT) is None

    def test_url_within_https_url_scheme(self):
        """
        test URL generation of management when authority is https url scheme
        """
        AUTHORITY = "https://localhost/"
        ENDPOINT = "UUID"
        URL = f"https://localhost/1.0/{ENDPOINT}/management/GetManagementEndPoint"
        api_component = _ApiComponent(_ApiID.GET_MANAGEMENT_END_POINT)

        assert api_component.get_url(AUTHORITY, ENDPOINT) == URL

    def test_url_within_http_url_scheme(self):
        """
        test URL generation of management when authority is http url scheme
        """
        AUTHORITY = "http://localhost/"
        ENDPOINT = "UUID"
        URL = f"https://localhost/1.0/{ENDPOINT}/management/GetManagementEndPoint"
        api_component = _ApiComponent(_ApiID.GET_MANAGEMENT_END_POINT)

        assert api_component.get_url(AUTHORITY, ENDPOINT) == URL

    def test_url_authority_with_or_without_a_slash_at_the_end(self):
        """
        test URL generation with checking slash.
        """
        ENDPOINT = "UUID"
        URL = f"https://localhost/1.0/{ENDPOINT}/management/GetManagementEndPoint"
        api_component = _ApiComponent(_ApiID.GET_MANAGEMENT_END_POINT)

        assert api_component.get_url("http://localhost/", ENDPOINT) == URL
        assert api_component.get_url("http://localhost", ENDPOINT) == URL
        assert api_component.get_url("localhost/", ENDPOINT) == URL
        assert api_component.get_url("localhost", ENDPOINT) == URL

    def test_url_authority_with_or_without_a_additional_path_at_the_end(self):
        """
        test URL generation with checking additional path.
        """
        ENDPOINT = "UUID"
        URL = f"https://localhost/ABC/1.0/{ENDPOINT}/management/GetManagementEndPoint"
        api_component = _ApiComponent(_ApiID.GET_MANAGEMENT_END_POINT)

        assert api_component.get_url("http://localhost/ABC/", ENDPOINT) == URL
        assert api_component.get_url("http://localhost/ABC", ENDPOINT) == URL
        assert api_component.get_url("localhost/ABC/", ENDPOINT) == URL
        assert api_component.get_url("localhost/ABC", ENDPOINT) == URL

    def test_url_management(self):
        """
        test URL generation of management
        """
        AUTHORITY = "localhost"
        ENDPOINT = "UUID"
        URL = f"https://{AUTHORITY}/1.0/{ENDPOINT}/management/GetManagementEndPoint"
        api_component = _ApiComponent(_ApiID.GET_MANAGEMENT_END_POINT)
        assert api_component.get_url(AUTHORITY, ENDPOINT) == URL

    def test_url_control(self):
        """
        test URL generation of control
        """
        AUTHORITY = "localhost"
        ENDPOINT = "UUID"
        NODE_ID = "001"
        URL = f"https://{AUTHORITY}/1.0/{ENDPOINT}/control/{NODE_ID}/GetSceneMode"
        api_component = _ApiComponent(_ApiID.GET_SCENE_MODE)
        assert api_component.get_url(AUTHORITY, ENDPOINT, NODE_ID) == URL

    def test_url_mark(self):
        """
        test URL generation of SceneMark
        """
        AUTHORITY = "localhost"
        ENDPOINT = "UUID"
        NODE_ID = "001"
        PORT_ID = "002"
        URL = f"https://{AUTHORITY}/1.0/{ENDPOINT}/data/{NODE_ID}/{PORT_ID}/SetSceneMark"
        api_component = _ApiComponent(_ApiID.SET_SCENE_MARK)
        assert api_component.get_url(AUTHORITY, ENDPOINT, NODE_ID, PORT_ID) == URL

    def test_url_data(self):
        """
        test URL generation of SceneData
        """
        AUTHORITY = "localhost"
        ENDPOINT = "UUID"
        NODE_ID = "001"
        PORT_ID = "002"
        URL = f"https://{AUTHORITY}/1.0/{ENDPOINT}/data/{NODE_ID}/{PORT_ID}/SetSceneData"
        api_component = _ApiComponent(_ApiID.SET_SCENE_DATA)
        assert api_component.get_url(AUTHORITY, ENDPOINT, NODE_ID, PORT_ID) == URL

    def test_url_error(self):
        """
        test URL generation error
        """
        AUTHORITY = "localhost"
        ENDPOINT = "UUID"
        NODE_ID = "001"
        PORT_ID = None
        api_component = _ApiComponent(None)
        assert api_component.get_url(AUTHORITY, ENDPOINT, NODE_ID, PORT_ID) is None
        api_component = _ApiComponent(_ApiID.SET_SCENE_MARK)
        assert api_component.get_url(AUTHORITY, ENDPOINT, NODE_ID, PORT_ID) is None
        api_component = _ApiComponent(_ApiID.SET_SCENE_DATA)
        assert api_component.get_url(AUTHORITY, ENDPOINT, NODE_ID, PORT_ID) is None
