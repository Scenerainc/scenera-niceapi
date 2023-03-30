import json
import pytest
from src.niceapi.api.mark import SceneMark

@pytest.fixture
def mark_object():
    mark = SceneMark(
        version="1.0",
        time_stamp="2022-02-21T12:34:56.123Z",
        scene_mark_id="001",
        node_id="002",
    )
    return mark

class TestSceneMark:
    """SceneMark test class."""

    def test_property_json(self, mark_object):
        """
        test the getter of json
        """
        assert mark_object.json == {
            "Version": "1.0",
            "TimeStamp": "2022-02-21T12:34:56.123Z",
            "SceneMarkID": "001",
            "NodeID": "002"
        }

    def test_set_version_number_detected(self):
        """
        test set_version_number (DetectedObject)
        """
        detected = SceneMark.DetectedObject()
        detected.set_version_number(1.0)
        assert detected.json["VersionNumber"] == 1.0

    def test_set_nice_item_type(self):
        """
        test set_nice_item_type (DetectedObject)
        """
        detected = SceneMark.DetectedObject()
        detected.set_nice_item_type("Human")
        assert detected.json["NICEItemType"] == "Human"

    def test_set_custom_item_type(self):
        """
        test set_custom_item_type (DetectedObject)
        """
        detected = SceneMark.DetectedObject()
        detected.set_custom_item_type("Dog")
        assert detected.json["CustomItemType"] == "Dog"

    def test_set_item_id(self):
        """
        test set_item_id (DetectedObject)
        """
        detected = SceneMark.DetectedObject()
        detected.set_item_id("123")
        assert detected.json["ItemID"] == "123"

    def test_set_probability(self):
        """
        test set_probability (DetectedObject)
        """
        detected = SceneMark.DetectedObject()
        detected.set_probability(99.999)
        assert detected.json["Probability"] == 99.999

    def test_set_analysis(self):
        """
        test set_analysis (DetectedObject)
        """
        detected = SceneMark.DetectedObject()
        detected.set_analysis(mode="Label", analysis_id="001", description="Yolo v3", status="Detected")
        assert detected.json["Analysis"] == {
            "SceneMode": "Label",
            "CustomAnalysisID": "001",
            "AnalysisDescription": "Yolo v3",
            "ProcessingStatus": "Detected"
        }
        detected.set_analysis()
        assert detected.json["Analysis"] == {}

    def test_add_attribute(self):
        """
        test add_attribute (DetectedObject)
        """
        detected = SceneMark.DetectedObject()
        detected.add_attribute()
        assert detected.json["Attributes"] == []
        detected.add_attribute(attribute="ABC", probability=88.888, algorithm_id="123")
        assert detected.json["Attributes"][0] == {
            "Attribute": "ABC",
            "ProbabilityofAttribute": 88.888,
            "AlgorithmID": "123"
        }
        detected.add_attribute(attribute="DEF", probability=77.777, algorithm_id="456")
        assert detected.json["Attributes"][1] == {
            "Attribute": "DEF",
            "ProbabilityofAttribute": 77.777,
            "AlgorithmID": "456"
        }
        detected = SceneMark.DetectedObject()
        detected.add_attribute(attribute="ABC", probability=88.888, algorithm_id="123")
        assert detected.json["Attributes"][0] == {
            "Attribute": "ABC",
            "ProbabilityofAttribute": 88.888,
            "AlgorithmID": "123"
        }

    def test_set_bounding_box(self):
        """
        test set_bounding_box (DetectedObject)
        """
        detected = SceneMark.DetectedObject()
        detected.set_bounding_box(1,2,3,4)
        assert detected.json["BoundingBox"] == {
            "XCoordinate": 1,
            "YCoordinate": 2,
            "Width": 3,
            "Height": 4
        }

    def test_set_thumbnail_scene_data_id(self):
        """
        test set_thumbnail_scene_data_id (DetectedObject)
        """
        detected = SceneMark.DetectedObject()
        detected.set_thumbnail_scene_data_id("001")
        assert detected.json["ThumbnailSceneDataID"] == "001"

    def test_set_version_number_analysis(self):
        """
        test set_version_number (Analysis)
        """
        analysis = SceneMark.Analysis()
        analysis.set_version_number(1.0)
        assert analysis.json["VersionNumber"] == 1.0

    def test_set_scene_mode(self):
        """
        test set_scene_mode (Analysis)
        """
        analysis = SceneMark.Analysis()
        analysis.set_scene_mode("Label")
        assert analysis.json["SceneMode"] == "Label"

    def test_set_custom_analysis_id(self):
        """
        test set_custom_analysis_id (Analysis)
        """
        analysis = SceneMark.Analysis()
        analysis.set_custom_analysis_id("123")
        assert analysis.json["CustomAnalysisID"] == "123"

    def test_set_analysis_description(self):
        """
        test set_analysis_description (Analysis)
        """
        analysis = SceneMark.Analysis()
        analysis.set_analysis_description("Yolo v3")
        assert analysis.json["AnalysisDescription"] == "Yolo v3"

    def test_set_processing_status(self):
        """
        test set_processing_status (Analysis)
        """
        analysis = SceneMark.Analysis()
        analysis.set_processing_status("Detect")
        assert analysis.json["ProcessingStatus"] == "Detect"

    def test_add_detected_object(self):
        """
        test add_detected_object (Analysis)
        """
        analysis = SceneMark.Analysis()
        detected = analysis.new_detected_object()
        detected.set_nice_item_type("Human")
        analysis.add_detected_object(detected)
        detected = analysis.new_detected_object()
        detected.set_item_id("123")
        analysis.add_detected_object(detected)
        assert analysis.json["DetectedObjects"][0] == {"NICEItemType": "Human"}
        assert analysis.json["DetectedObjects"][1] == {"ItemID": "123"}

    def test_set_source_node_id(self):
        """
        test set_source_node_id (SceneData)
        """
        scenedata = SceneMark.SceneData(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False,
        )
        scenedata.set_source_node_id("123")
        assert scenedata.json["SourceNodeID"] == "123"

    def test_set_source_node_description(self):
        """
        test set_source_node_description (SceneData)
        """
        scenedata = SceneMark.SceneData(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False,
        )
        scenedata.set_source_node_description("Bridge")
        assert scenedata.json["SourceNodeDescription"] == "Bridge"

    def test_set_duration(self):
        """
        test set_duration (SceneData)
        """
        scenedata = SceneMark.SceneData(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False,
        )
        scenedata.set_duration("10")
        assert scenedata.json["Duration"] == "10"

    def test_set_data_type(self):
        """
        test set_data_type (SceneData)
        """
        scenedata = SceneMark.SceneData(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False,
        )
        scenedata.set_data_type("RGBStill")
        assert scenedata.json["DataType"] == "RGBStill"

    def test_set_status(self):
        """
        test set_status (SceneData)
        """
        scenedata = SceneMark.SceneData(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False,
        )
        scenedata.set_status("Upload in Progress")
        assert scenedata.json["Status"] == "Upload in Progress"

    def test_set_media_format(self):
        """
        test set_media_format (SceneData)
        """
        scenedata = SceneMark.SceneData(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False,
        )
        scenedata.set_media_format("JPEG")
        assert scenedata.json["MediaFormat"] == "JPEG"

    def test_set_resolution(self):
        """
        test set_resolution (SceneData)
        """
        scenedata = SceneMark.SceneData(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False,
        )
        scenedata.set_resolution(123, 456)
        assert scenedata.json["Resolution"] == {"Width": 123, "Height": 456}
        scenedata.set_resolution("123", "456")
        assert scenedata.json["Resolution"] == {"Width": 123, "Height": 456}

    def test_set_scene_data_uri(self):
        """
        test set_scene_data_uri (SceneData)
        """
        scenedata = SceneMark.SceneData(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False,
        )
        scenedata.set_scene_data_uri("localhost")
        assert scenedata.json["SceneDataURI"] == "localhost"

    def test_set_embedded_scene_data(self):
        """
        test set_embedded_scene_data (SceneData)
        """
        scenedata = SceneMark.SceneData(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False,
        )
        scenedata.set_embedded_scene_data("XXX")
        assert scenedata.json["EmbeddedSceneData"] == "XXX"

    def test_set_destination_id(self, mark_object):
        """
        test set_destination_id
        """
        mark_object.set_destination_id("123")
        assert mark_object.json["DestinationID"] == "123"

    def test_set_scene_mark_status(self, mark_object):
        """
        test set_scene_mark_status
        """
        mark_object.set_scene_mark_status("Active")
        assert mark_object.json["SceneMarkStatus"] == "Active"

    def test_set_port_id(self, mark_object):
        """
        test set_port_id
        """
        mark_object.set_port_id("001")
        assert mark_object.json["PortID"] == "001"

    def test_set_data_pipeline_instance_id(self, mark_object):
        """
        test set_data_pipeline_instance_id
        """
        mark_object.set_data_pipeline_instance_id("001")
        assert mark_object.json["VersionControl"]["DataPipelineInstanceID"] == "001"
        mark_object.set_data_pipeline_instance_id("002")
        assert mark_object.json["VersionControl"]["DataPipelineInstanceID"] == "002"

    def test_add_version_list(self, mark_object):
        """
        test add_version_list
        """
        mark_object.set_data_pipeline_instance_id("001")
        mark_object.add_version_list(
            version_number=1.0,
            date_time_stamp="2022-02-21T12:34:56.123Z",
            node_id="001")
        mark_object.add_version_list(
            version_number=1.0,
            date_time_stamp="2022-02-21T12:34:56.123Z",
            node_id="002")
        assert mark_object.json["VersionControl"]["DataPipelineInstanceID"] == "001"
        assert mark_object.json["VersionControl"]["VersionList"][0] == {
            "VersionNumber": 1.0,
            "DateTimeStamp": "2022-02-21T12:34:56.123Z",
            "NodeID": "001"
        }
        assert mark_object.json["VersionControl"]["VersionList"][1] == {
            "VersionNumber": 1.0,
            "DateTimeStamp": "2022-02-21T12:34:56.123Z",
            "NodeID": "002"
        }
        mark_object.json.pop("VersionControl")
        assert mark_object.json.get("VersionControl") is None
        mark_object.add_version_list(
            version_number=1.0,
            date_time_stamp="2022-02-21T12:34:56.123Z",
            node_id="003")
        assert mark_object.json["VersionControl"]["VersionList"][0] == {
            "VersionNumber": 1.0,
            "DateTimeStamp": "2022-02-21T12:34:56.123Z",
            "NodeID": "003"
        }

    def test_add_thumbnail_list(self, mark_object):
        """
        test add_thumbnail_list
        """
        mark_object.add_thumbnail_list(
            version_number=1.0,
            scene_data_id="001")
        mark_object.add_thumbnail_list(
            version_number=1.0,
            scene_data_id="002")
        assert mark_object.json["ThumbnailList"][0] == {
            "VersionNumber": 1.0,
            "SceneDataID": "001"
        }
        assert mark_object.json["ThumbnailList"][1] == {
            "VersionNumber": 1.0,
            "SceneDataID": "002"
        }

    def test_add_analysis(self, mark_object):
        """
        test add_analysis
        """
        analysis = mark_object.new_analysis()
        analysis.set_processing_status("Detect")
        mark_object.add_analysis(analysis)
        analysis = mark_object.new_analysis()
        analysis.set_processing_status("Motion")
        mark_object.add_analysis(analysis)
        assert mark_object.json["AnalysisList"][0]["ProcessingStatus"] == "Detect"
        assert mark_object.json["AnalysisList"][1]["ProcessingStatus"] == "Motion"

    def test_add_scene_data(self, mark_object):
        """
        test add_scene_data
        """
        scenedata = mark_object.new_scene_data(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False
        )
        scenedata.set_data_type("RGBStill")
        mark_object.add_scene_data(scenedata)
        scenedata = mark_object.new_scene_data(
            scene_data_id="456",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False
        )
        scenedata.set_data_type("RGBVideo")
        mark_object.add_scene_data(scenedata)
        assert mark_object.json["SceneDataList"][0]["DataType"] == "RGBStill"
        assert mark_object.json["SceneDataList"][1]["DataType"] == "RGBVideo"

    def test_new_webapi_scheme(self, mark_object):
        """
        test new_webapi_scheme
        """
        scenedata = mark_object.new_scene_data(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False
        )
        webapi = scenedata.new_webapi_scheme("localhost")
        assert webapi == {"Protocol": "WebAPI", "Authority": "localhost"}
        webapi = scenedata.new_webapi_scheme("localhost", "ABC")
        assert webapi == {"Protocol": "WebAPI", "Authority": "localhost", "AccessToken": "ABC"}
        webapi = scenedata.new_webapi_scheme("localhost", "ABC", "Client")
        assert webapi == {"Protocol": "WebAPI", "Authority": "localhost", "AccessToken": "ABC", "Role": "Client"}

    def test_new_app_end_point(self, mark_object):
        """
        test new_app_end_point
        """
        scenedata = mark_object.new_scene_data(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False
        )
        endpoint = scenedata.new_app_end_point("1.0", "012")
        assert endpoint == {"APIVersion": "1.0", "EndPointID": "012"}
        endpoint = scenedata.new_app_end_point("1.0", "012", ["XXX"])
        assert endpoint == {"APIVersion": "1.0", "EndPointID": "012", "X.509Certificate": ["XXX"]}
        endpoint = scenedata.new_app_end_point("1.0", "012", ["XXX"], "ABC")
        assert endpoint == {"APIVersion": "1.0", "EndPointID": "012", "X.509Certificate": ["XXX"], "AccessToken": "ABC"}

    def test_new_net_end_point(self, mark_object):
        """
        test new_net_end_point
        """
        scenedata = mark_object.new_scene_data(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False
        )
        webapi = scenedata.new_webapi_scheme("localhost")
        endpoint = scenedata.new_net_end_point("1.0", "123", [webapi])
        assert endpoint == {"APIVersion": "1.0", "EndPointID": "123", "Scheme":[{"Protocol": "WebAPI", "Authority": "localhost"}]}
        endpoint = scenedata.new_net_end_point("1.0", "123", [webapi], "001")
        assert endpoint == {"APIVersion": "1.0", "EndPointID": "123", "Scheme":[{"Protocol": "WebAPI", "Authority": "localhost"}], "NodeID": "001"}
        endpoint = scenedata.new_net_end_point("1.0", "123", [webapi], "001", "002")
        assert endpoint == {
            "APIVersion": "1.0",
            "EndPointID": "123",
            "Scheme":[{"Protocol": "WebAPI", "Authority": "localhost"}],
            "NodeID": "001",
            "PortID": "002"
        }

    def test_set_encryption_on(self, mark_object):
        """
        test set_encryption_on
        """
        scenedata = mark_object.new_scene_data(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False
        )
        scenedata.set_encryption_on(True)
        mark_object.add_scene_data(scenedata)
        assert mark_object.json["SceneDataList"][0]["Encryption"]["EncryptionOn"] == True

    def test_set_encryption_key_id(self, mark_object):
        """
        test set_encryption_key_id
        """
        scenedata = mark_object.new_scene_data(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False
        )
        scenedata.set_encryption_key_id("KEY ID")
        mark_object.add_scene_data(scenedata)
        assert mark_object.json["SceneDataList"][0]["Encryption"]["SceneEncryptionKeyID"] == "KEY ID"

    def test_set_encryption_privacy_server(self, mark_object):
        """
        test set_encryption_privacy_server
        """
        scenedata = mark_object.new_scene_data(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False
        )
        webapi = scenedata.new_webapi_scheme("localhost")
        net_end = scenedata.new_net_end_point("1.0", "123", [webapi])
        scenedata.set_encryption_privacy_server(net_end)
        mark_object.add_scene_data(scenedata)
        assert mark_object.json["SceneDataList"][0]["Encryption"]["PrivacyServerEndPoint"] == {
            "NetEndPoint": {
                "APIVersion": "1.0",
                "EndPointID": "123",
                "Scheme":[{"Protocol": "WebAPI", "Authority": "localhost"}]
            }
        }

        app_end = scenedata.new_app_end_point("1.0", "012")
        scenedata.set_encryption_privacy_server(net_end, app_end)
        mark_object.add_scene_data(scenedata)
        assert mark_object.json["SceneDataList"][0]["Encryption"]["PrivacyServerEndPoint"] == {
            "AppEndPoint": {
                "APIVersion": "1.0",
                "EndPointID": "012"
            },
            "NetEndPoint": {
                "APIVersion": "1.0",
                "EndPointID": "123",
                "Scheme":[{"Protocol": "WebAPI", "Authority": "localhost"}]
            }
        }

    def test_set_encryption(self, mark_object):
        """
        test set_encryption
        """
        scenedata = mark_object.new_scene_data(
            scene_data_id="123",
            time_stamp="2022-02-21T12:34:56.123Z",
            encryption=False
        )
        ENCRYPTION = {"EncryptionOn": False}
        scenedata.set_encryption(ENCRYPTION)
        mark_object.add_scene_data(scenedata)
        assert mark_object.json["SceneDataList"][0]["Encryption"] == ENCRYPTION
