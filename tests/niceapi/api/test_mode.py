import json
import pytest
from src.niceapi.api._mode import _SceneMode

SCENE_MODE = """
{
  "Version": "1.0",
  "SceneModeID": "SCENE_MODE_ID",
  "NodeID": "NODE_ID",
  "Inputs": [
    {
      "Type": "Video",
      "VideoEndPoint": {
        "VideoURI": "0"
      }
    },
    {
      "EndPoint": {
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
      },
      "Encryption": {
        "EncryptionOn": true,
        "SceneEncryptionKeyID": "scene_encryption_key_id",
        "PrivacyServerEndPoint": {
          "AppEndPoint": {
            "APIVersion": "1.0",
            "EndPointID": "APP_END_POINT_ID",
            "X.509Certificate": ["XXXXX"],
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
      }
    }
  ],
  "Outputs": [
    {
      "Type": "Video",
      "PortID": "PORT_ID",
      "DestinationEndPointList": [
        {
          "AppEndPoint": {
            "APIVersion": "1.0",
            "EndPointID": "APP_END_POINT_ID",
            "AccessToken": "ACCESS_TOKEN"
          },
          "NetEndPoint": {
            "APIVersion": "1.0",
            "EndPointID": "NET_END_POINT_ID",
            "NodeID": "0001",
            "PortID": "4001",
            "Scheme": [
              {
                "Protocol": "WebAPI",
                "Authority": "localhost",
                "AccessToken": "BEARER",
                "Role": "Client"
              }
            ]
          }
        }
      ],
      "Resolution": {
        "Height": 100,
        "Width": 100
      },
      "Encryption": {
        "EncryptionOn": true,
        "SceneEncryptionKeyID": "scene_encryption_key_id",
        "SceneDataEncryption": "A256GCM",
        "PrivacyServerEndPoint": {
          "AppEndPoint": {
            "APIVersion": "1.0",
            "EndPointID": "APP_END_POINT_ID",
            "X.509Certificate": ["XXXXX"],
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
      }
    },
    {
      "Type": "Image",
      "PortID": "PORT_ID",
      "DestinationEndPointList": [
        {
          "AppEndPoint": {
            "APIVersion": "1.0",
            "EndPointID": "APP_END_POINT_ID",
            "AccessToken": "ACCESS_TOKEN"
          },
          "NetEndPoint": {
            "APIVersion": "1.0",
            "EndPointID": "NET_END_POINT_ID",
            "NodeID": "0001",
            "PortID": "4002",
            "Scheme": [
              {
                "Protocol": "WebAPI",
                "Authority": "localhost",
                "AccessToken": "BEARER",
                "Role": "Client"
              }
            ]
          }
        }
      ],
      "Encryption": {
        "EncryptionOn": true,
        "SceneEncryptionKeyID": "scene_encryption_key_id",
        "SceneDataEncryption": "A256GCM",
        "PrivacyServerEndPoint": {
          "AppEndPoint": {
            "APIVersion": "1.0",
            "EndPointID": "APP_END_POINT_ID",
            "X.509Certificate": ["XXXXX"],
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
      }
    },
    {
      "Type": "Audio",
      "PortID": "PORT_ID",
      "DestinationEndPointList": [
        {
          "AppEndPoint": {
            "APIVersion": "1.0",
            "EndPointID": "APP_END_POINT_ID",
            "AccessToken": "ACCESS_TOKEN"
          },
          "NetEndPoint": {
            "APIVersion": "1.0",
            "EndPointID": "NET_END_POINT_ID",
            "NodeID": "0001",
            "PortID": "4002",
            "Scheme": [
              {
                "Protocol": "WebAPI",
                "Authority": "localhost",
                "AccessToken": "BEARER",
                "Role": "Client"
              }
            ]
          }
        }
      ]
    }
  ],
  "Mode": {
    "SceneMode": "Label",
    "SceneModeConfig": [
      {
        "CustomAnalysisStage": "People Detection",
        "LabelRefDataList": [
          {
            "LabelName": "Smile",
            "ProcessingStage": "Detect",
            "RefDataList": [
              {
                "RefDataID": "123"
              }
            ],
            "RefData": [
              {
                "RefDataID": "123",
                "RefData": "XXX",
                "Encryption": {
                  "EncryptionOn": true,
                  "SceneEncryptionKeyID": "scene_encryption_key_id",
                  "PrivacyServerEndPoint": {
                    "AppEndPoint": {
                      "APIVersion": "1.0",
                      "EndPointID": "APP_END_POINT_ID",
                      "X.509Certificate": ["XXXXX"],
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
                }
              }
            ]
          }
        ],
        "AnalysisThreshold": 0.7,
        "Scheduling": [
          {
            "SchedulingType": "ScheduledWeekDay",
            "StartTime": "0:00",
            "EndTime": "0:30"
          },
          {
            "SchedulingType": "ScheduledWeekDay",
            "StartTime": "23:00",
            "EndTime": "23:30"
          }
        ],
        "Encryption": {
          "EncryptionOn": true,
          "SceneEncryptionKeyID": "scene_encryption_key_id",
          "SceneDataEncryption": "A256GCM",
          "PrivacyServerEndPoint": {
            "AppEndPoint": {
              "APIVersion": "1.0",
              "EndPointID": "APP_END_POINT_ID",
              "X.509Certificate": ["XXXXX"],
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
        }
      }
    ],
    "SceneMarkInputList": [
      {
        "SceneMarkInputEndPoint": {
          "APIVersion": "1.0",
          "EndPointID": "NET_END_POINT_ID",
          "NodeID": "0001",
          "PortID": "4003",
          "Scheme": [
            {
              "Protocol": "WebAPI",
              "Authority": "localhost",
              "AccessToken": "BEARER",
              "Role": "Client"
            }
          ]
        },
        "Encryption": {
          "EncryptionOn": true,
          "SceneEncryptionKeyID": "scene_encryption_key_id",
          "PrivacyServerEndPoint": {
            "AppEndPoint": {
              "APIVersion": "1.0",
              "EndPointID": "APP_END_POINT_ID",
              "X.509Certificate": ["XXXXX"],
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
        }
      }
    ],
    "SceneMarkOutputList": [
      {
        "SceneMarkOutputEndPoint": {
          "APIVersion": "1.0",
          "EndPointID": "NET_END_POINT_ID",
          "NodeID": "0001",
          "PortID": "4004",
          "Scheme": [
            {
              "Protocol": "WebAPI",
              "Authority": "localhost",
              "AccessToken": "BEARER",
              "Role": "Client"
            }
          ]
        },
        "Encryption": {
          "EncryptionOn": true,
          "SceneEncryptionKeyID": "scene_encryption_key_id",
          "SceneMarkEncryption": {
            "JWEAlg": "A256KW",
            "JWEEnc": "A256GCM"
          },
          "PrivacyServerEndPoint": {
            "AppEndPoint": {
              "APIVersion": "1.0",
              "EndPointID": "APP_END_POINT_ID",
              "X.509Certificate": ["XXXXX"],
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
        }
      }
    ]
  }
}
"""
SCENE_MODE_ERROR = """
{
  "Version": "1.0",
  "SceneModeID": "SCENE_MODE_ID",
  "NodeID": "NODE_ID",
  "Inputs": [
    {
      "Type": "Video",
      "VideoEndPoint": {
        "VideoURI": "0"
      }
    }
  ],
  "Outputs": [
    {
      "Type": "Video",
      "PortID": "PORT_ID",
      "DestinationEndPointList": [
        {
          "AppEndPoint": {
            "APIVersion": "1.0",
            "EndPointID": "APP_END_POINT_ID",
            "AccessToken": "ACCESS_TOKEN"
          },
          "NetEndPoint": {
            "APIVersion": "1.0",
            "EndPointID": "NET_END_POINT_ID",
            "NodeID": "0001",
            "PortID": "4001",
            "Scheme": [
              {
                "Protocol": "WebAPI",
                "Authority": "localhost",
                "AccessToken": "BEARER",
                "Role": "Client"
              }
            ]
          }
        }
      ],
      "Encryption": {
        "EncryptionOn": true,
        "SceneEncryptionKeyID": "scene_encryption_key_id",
        "PrivacyServerEndPoint": {
          "AppEndPoint": {
            "APIVersion": "1.0",
            "EndPointID": "APP_END_POINT_ID",
            "X.509Certificate": "XXXXX",
            "AccessToken": "ACCESS_TOKEN"
          },
          "NetEndPoint": {
             "EndPointID": "NET_END_POINT_ID",
            "NodeID": "0001",
            "Scheme": [
              {
                "Authority": "localhost",
                "Role": "Client",
                "AccessToken": "BEARER"
              }
            ]
          }
        }
      }
    }
  ],
  "Mode": {
    "SceneMode": "Label",
    "SceneModeConfig": [
      {
      }
    ],
    "SceneMarkOutputList": [
      {
      }
    ]
  }
}
"""

@pytest.fixture
def scene_mode():
    mode = _SceneMode()
    mode.json = json.loads(SCENE_MODE)
    return mode

class TestSceneMode:
    """SceneMode test class."""

    def test_if_available(self, scene_mode):
        """
        test if available
        """
        assert scene_mode.is_available == True

    def test_if_not_available(self):
        """
        test before setting json
        """
        scene_mode = _SceneMode()
        assert scene_mode.is_available == False

    def test_property_json(self, scene_mode):
        """
        test the getter of json
        """
        assert scene_mode.json == json.loads(SCENE_MODE)

    def test_setter_json(self):
        """
        test the setter of json
        """
        scene_mode = _SceneMode()
        test_obj = json.loads(SCENE_MODE)
        output_list0 = test_obj["Mode"]["SceneMarkOutputList"][0]
        output_list0["SceneMarkOutputEndPoint"]["Scheme"][0]["Protocol"] = "MQTTScheme"
        scene_mode.json = test_obj
        assert scene_mode.is_available == True
        mode = test_obj["Mode"]
        mode.pop("SceneMarkOutputList")
        scene_mode.json = test_obj
        assert scene_mode.is_available == True
        test_obj = json.loads(SCENE_MODE)
        test_obj["Inputs"][0]["Type"] = "Image"
        net_endpoint = test_obj["Outputs"][0]["DestinationEndPointList"][0]["NetEndPoint"]
        net_endpoint["Scheme"][0]["Protocol"] = "MQTTScheme"
        input_list0 = test_obj["Mode"]["SceneMarkInputList"][0]
        input_list0["SceneMarkInputEndPoint"]["Scheme"][0]["Protocol"] = "MQTTScheme"
        input_list0.pop("Encryption")
        scene_mode.json = test_obj
        assert scene_mode.is_available == True
        test_obj = json.loads(SCENE_MODE)
        encryption = test_obj["Inputs"][1]["Encryption"]
        app_endpoint = encryption["PrivacyServerEndPoint"]["AppEndPoint"]
        # remove required key
        app_endpoint.pop("APIVersion")
        scene_mode.json = test_obj
        assert scene_mode.is_available == True
        test_obj = json.loads(SCENE_MODE)
        config = test_obj["Mode"]["SceneModeConfig"][0]
        config.pop("Encryption")
        scene_mode.json = test_obj
        assert scene_mode.mode_encryptions is None
        test_obj = json.loads(SCENE_MODE)
        config = test_obj["Mode"]["SceneModeConfig"][0]
        refs = config["LabelRefDataList"][0]
        # remove list
        refs.pop("RefDataList")
        scene_mode.json = test_obj
        assert scene_mode.is_available == True

    def test_lack_of_version(self):
        """
        test lack of version
        """
        scene_mode = _SceneMode()
        scene_mode.json = {"Mode": {"SceneMode": "Label"}}
        assert scene_mode.is_available == False

    def test_lack_of_api_version(self):
        """
        test lack of api version
        """
        scene_mode = _SceneMode()
        test_obj = json.loads(SCENE_MODE)
        net_endpoint = test_obj["Inputs"][1]["EndPoint"]
        # remove required key
        net_endpoint.pop("APIVersion")
        scene_mode.json = test_obj
        assert scene_mode.is_available == False

    def test_lack_of_type(self):
        """
        test lack of type
        """
        scene_mode = _SceneMode()
        test_obj = json.loads(SCENE_MODE)
        output0 = test_obj["Outputs"][0]
        # remove required key
        output0.pop("Type")
        scene_mode.json = test_obj
        assert scene_mode.is_available == False

    def test_non_list(self):
        """
        test non-list
        """
        scene_mode = _SceneMode()
        test_obj = json.loads(SCENE_MODE)
        endpoint = test_obj["Outputs"][0]["DestinationEndPointList"][0]
        # remove list
        test_obj["Outputs"][0]["DestinationEndPointList"] = endpoint
        scene_mode.json = test_obj
        assert scene_mode.is_available == False

    def test_lack_of_app_endpoint(self):
        """
        test lack of app endpoint
        """
        scene_mode = _SceneMode()
        test_obj = json.loads(SCENE_MODE)
        endpoint = test_obj["Outputs"][0]["DestinationEndPointList"][0]
        # remove required key
        endpoint.pop("AppEndPoint")
        scene_mode.json = test_obj
        assert scene_mode.is_available == False

    def test_lack_of_height(self):
        """
        test lack of height
        """
        scene_mode = _SceneMode()
        test_obj = json.loads(SCENE_MODE)
        resolution = test_obj["Outputs"][0]["Resolution"]
        # remove required key
        resolution.pop("Height")
        scene_mode.json = test_obj
        assert scene_mode.is_available == False

    def test_lack_of_scenemode(self):
        """
        test lack of secenemode
        """
        scene_mode = _SceneMode()
        test_obj = json.loads(SCENE_MODE)
        mode = test_obj["Mode"]
        # remove required key
        mode.pop("SceneMode")
        scene_mode.json = test_obj
        assert scene_mode.is_available == False

    def test_config_non_list(self):
        """
        test config non-list
        """
        scene_mode = _SceneMode()
        test_obj = json.loads(SCENE_MODE)
        config = test_obj["Mode"]["SceneModeConfig"][0]
        # remove list
        test_obj["Mode"]["SceneModeConfig"] = config
        scene_mode.json = test_obj
        assert scene_mode.is_available == False

    def test_config_label_ref_data_list(self):
        """
        test config LabelRefDataList
        """
        scene_mode = _SceneMode()
        test_obj = json.loads(SCENE_MODE)
        config = test_obj["Mode"]["SceneModeConfig"][0]
        refs = config["LabelRefDataList"][0]
        # remove list
        config["LabelRefDataList"] = refs
        scene_mode.json = test_obj
        assert scene_mode.is_available == False
        test_obj = json.loads(SCENE_MODE)
        config = test_obj["Mode"]["SceneModeConfig"][0]
        refs = config["LabelRefDataList"][0]
        # remove required key
        refs.pop("LabelName")
        scene_mode.json = test_obj
        assert scene_mode.is_available == False
        test_obj = json.loads(SCENE_MODE)
        config = test_obj["Mode"]["SceneModeConfig"][0]
        data = config["LabelRefDataList"][0]["RefDataList"][0]
        # remove list
        config["LabelRefDataList"][0]["RefDataList"] = data
        scene_mode.json = test_obj
        assert scene_mode.is_available == False
        test_obj = json.loads(SCENE_MODE)
        config = test_obj["Mode"]["SceneModeConfig"][0]
        data = config["LabelRefDataList"][0]["RefDataList"][0]
        # remove required key
        data.pop("RefDataID")
        scene_mode.json = test_obj
        assert scene_mode.is_available == False
        test_obj = json.loads(SCENE_MODE)
        config = test_obj["Mode"]["SceneModeConfig"][0]
        data = config["LabelRefDataList"][0]["RefData"][0]
        # remove list
        config["LabelRefDataList"][0]["RefData"] = data
        scene_mode.json = test_obj
        assert scene_mode.is_available == False
        test_obj = json.loads(SCENE_MODE)
        config = test_obj["Mode"]["SceneModeConfig"][0]
        data = config["LabelRefDataList"][0]["RefData"][0]
        # remove required key
        data.pop("RefDataID")
        scene_mode.json = test_obj
        assert scene_mode.is_available == False

    def test_config_scheduling(self):
        """
        test config Scheduling
        """
        scene_mode = _SceneMode()
        test_obj = json.loads(SCENE_MODE)
        config = test_obj["Mode"]["SceneModeConfig"][0]
        schedule = config["Scheduling"][0]
        # remove list
        config["Scheduling"] = schedule
        scene_mode.json = test_obj
        assert scene_mode.is_available == False
        test_obj = json.loads(SCENE_MODE)
        config = test_obj["Mode"]["SceneModeConfig"][0]
        schedule = config["Scheduling"][0]
        # remove required key
        schedule.pop("SchedulingType")
        scene_mode.json = test_obj
        assert scene_mode.is_available == False

    def test_mark_input(self):
        """
        test SceneMarkInputList
        """
        scene_mode = _SceneMode()
        test_obj = json.loads(SCENE_MODE)
        mark_input = test_obj["Mode"]["SceneMarkInputList"][0]
        # remove required key
        mark_input.pop("SceneMarkInputEndPoint")
        scene_mode.json = test_obj
        assert scene_mode.is_available == True
        test_obj = json.loads(SCENE_MODE)
        endpoint = test_obj["Mode"]["SceneMarkInputList"][0]["SceneMarkInputEndPoint"]
        # remove required key
        endpoint.pop("APIVersion")
        scene_mode.json = test_obj
        assert scene_mode.is_available == False

    def test_mark_output(self):
        """
        test SceneMarkOutputList
        """
        scene_mode = _SceneMode()
        test_obj = json.loads(SCENE_MODE)
        endpoint = test_obj["Mode"]["SceneMarkOutputList"][0]["SceneMarkOutputEndPoint"]
        # remove required key
        endpoint.pop("APIVersion")
        scene_mode.json = test_obj
        assert scene_mode.is_available == False

    def test_property_video_url(self, scene_mode):
        """
        test the getter of video_url
        """
        assert scene_mode.video_url == "0"

    def test_setter_video_url(self, scene_mode):
        """
        test if there is no setter of video_url
        """
        with pytest.raises(AttributeError):
            scene_mode.video_url = "1"

    def test_property_input_encryption(self, scene_mode):
        """
        test the getter of input_encryption
        """
        encryption = scene_mode.input_encryption
        assert encryption.required == True
        assert encryption.key_id == "scene_encryption_key_id"
        assert encryption.app_end_point_id == "APP_END_POINT_ID"
        assert encryption.app_access_token == "ACCESS_TOKEN"
        assert encryption.certificate == "XXXXX"
        assert encryption.net_end_point_id == "NET_END_POINT_ID"
        assert encryption.node_id =="0001"
        scheme =  encryption.scheme[0]
        assert scheme.authority == "localhost"
        assert scheme.access_token == "BEARER"

    def test_setter_input_encryption(self, scene_mode):
        """
        test if there is no setter of input_encryption
        """
        with pytest.raises(AttributeError):
            scene_mode.input_encryption = None

    def test_property_image_config(self, scene_mode):
        """
        test the getter of image_config
        """
        image_config = scene_mode.image_config
        destination = image_config.destinations[0]
        assert destination.end_point_id == "NET_END_POINT_ID"
        assert destination.node_id == "0001"
        assert destination.port_id == "4002"
        scheme = destination.scheme[0]
        assert scheme.authority == "localhost"
        assert scheme.access_token == "BEARER"
        encryption = image_config.encryption
        assert encryption.required == True
        assert encryption.key_id == "scene_encryption_key_id"
        assert encryption.data_alg == "A256GCM"
        assert encryption.app_end_point_id == "APP_END_POINT_ID"
        assert encryption.app_access_token == "ACCESS_TOKEN"
        assert encryption.certificate == "XXXXX"
        assert encryption.net_end_point_id == "NET_END_POINT_ID"
        assert encryption.node_id =="0001"
        scheme =  encryption.scheme[0]
        assert scheme.authority == "localhost"
        assert scheme.access_token == "BEARER"

    def test_setter_image_config(self, scene_mode):
        """
        test if there is no setter of image_config
        """
        from src.niceapi.api._mode import _OutputConfiguration
        config = _OutputConfiguration()
        with pytest.raises(AttributeError):
            scene_mode.image_config = config

    def test_property_video_config(self, scene_mode):
        """
        test the getter of video_config
        """
        video_config = scene_mode.video_config
        destination = video_config.destinations[0]
        assert destination.end_point_id == "NET_END_POINT_ID"
        assert destination.node_id == "0001"
        assert destination.port_id == "4001"
        scheme = destination.scheme[0]
        assert scheme.authority == "localhost"
        assert scheme.access_token == "BEARER"
        encryption = video_config.encryption
        assert encryption.required == True
        assert encryption.key_id == "scene_encryption_key_id"
        assert encryption.data_alg == "A256GCM"
        assert encryption.app_end_point_id == "APP_END_POINT_ID"
        assert encryption.app_access_token == "ACCESS_TOKEN"
        assert encryption.certificate == "XXXXX"
        assert encryption.net_end_point_id == "NET_END_POINT_ID"
        assert encryption.node_id =="0001"
        scheme =  encryption.scheme[0]
        assert scheme.authority == "localhost"
        assert scheme.access_token == "BEARER"

    def test_setter_video_config(self, scene_mode):
        """
        test if there is no setter of video_config
        """
        from src.niceapi.api._mode import _OutputConfiguration
        config = _OutputConfiguration()
        with pytest.raises(AttributeError):
            scene_mode.video_config = config

    def test_property_mark_inputs(self, scene_mode):
        """
        test the getter of mark_inputs
        """
        mark_input = scene_mode.mark_inputs[0]
        assert mark_input.end_point_id == "NET_END_POINT_ID"
        assert mark_input.node_id == "0001"
        assert mark_input.port_id == "4003"
        scheme = mark_input.scheme[0]
        assert scheme.authority == "localhost"
        assert scheme.access_token == "BEARER"
        encryption = mark_input.encryption
        assert encryption.required == True
        assert encryption.key_id == "scene_encryption_key_id"
        assert encryption.app_end_point_id == "APP_END_POINT_ID"
        assert encryption.app_access_token == "ACCESS_TOKEN"
        assert encryption.certificate == "XXXXX"
        assert encryption.net_end_point_id == "NET_END_POINT_ID"
        assert encryption.node_id =="0001"
        scheme =  encryption.scheme[0]
        assert scheme.authority == "localhost"
        assert scheme.access_token == "BEARER"

    def test_setter_mark_inputs(self, scene_mode):
        """
        test if there is no setter of mark_output_end_point_id
        """
        from src.niceapi.api._mode import _SceneMarkInput
        mark_input = _SceneMarkInput()
        with pytest.raises(AttributeError):
            scene_mode.mark_inputs = [mark_input]

    def test_property_mark_outputs(self, scene_mode):
        """
        test the getter of mark_outputs
        """
        mark_output = scene_mode.mark_outputs[0]
        assert mark_output.end_point_id == "NET_END_POINT_ID"
        assert mark_output.node_id == "0001"
        assert mark_output.port_id == "4004"
        scheme = mark_output.scheme[0]
        assert scheme.authority == "localhost"
        assert scheme.access_token == "BEARER"
        encryption = mark_output.encryption
        assert encryption.required == True
        assert encryption.key_id == "scene_encryption_key_id"
        assert encryption.mark_alg == "A256KW"
        assert encryption.mark_enc == "A256GCM"
        assert encryption.app_end_point_id == "APP_END_POINT_ID"
        assert encryption.app_access_token == "ACCESS_TOKEN"
        assert encryption.certificate == "XXXXX"
        assert encryption.net_end_point_id == "NET_END_POINT_ID"
        assert encryption.node_id =="0001"
        scheme =  encryption.scheme[0]
        assert scheme.authority == "localhost"
        assert scheme.access_token == "BEARER"

    def test_setter_mark_outputs(self, scene_mode):
        """
        test if there is no setter of mark_output_end_point_id
        """
        from src.niceapi.api._mode import _SceneMarkOutput
        mark_output = _SceneMarkOutput()
        with pytest.raises(AttributeError):
            scene_mode.mark_outputs = [mark_output]

    def test_property_ref_encryptions(self, scene_mode):
        """
        test the getter of ref_encryptions
        """
        encryption = scene_mode.ref_encryptions[0]
        assert encryption.required == True
        assert encryption.key_id == "scene_encryption_key_id"
        assert encryption.app_end_point_id == "APP_END_POINT_ID"
        assert encryption.app_access_token == "ACCESS_TOKEN"
        assert encryption.certificate == "XXXXX"
        assert encryption.net_end_point_id == "NET_END_POINT_ID"
        assert encryption.node_id =="0001"
        scheme =  encryption.scheme[0]
        assert scheme.authority == "localhost"
        assert scheme.access_token == "BEARER"
        no_mark = json.loads(SCENE_MODE)
        no_mark.pop("Mode")
        mode = _SceneMode()
        mode.json = no_mark
        assert mode.ref_encryptions == None

    def test_setter_ref_encryptions(self, scene_mode):
        """
        test if there is no setter of ref_encryptions
        """
        with pytest.raises(AttributeError):
            scene_mode.ref_encryptions = None

    def test_encryption(self):
        """
        test initialization of Encryption
        """
        from src.niceapi.api._mode import _Encryption
        ENCRYPTION_OFF = {"EncryptionOn": False}
        encryption = _Encryption(ENCRYPTION_OFF)
        assert encryption.required == False
        ENCRYPTION_ON = """
        {
          "EncryptionOn": true,
          "PrivacyServerEndPoint": {
            "NetEndPoint": {
              "APIVersion": "1.0",
              "EndPointID": "NET_END_POINT_ID",
              "Scheme": [
                {
                  "Protocol": "MQTTScheme",
                  "Authority": "localhost"
                }
              ]
            }
          }
        }
        """
        encryption = _Encryption(json.loads(ENCRYPTION_ON))
        assert encryption.required == True

    def test_encryption_error(self):
        """
        test encryption error
        """
        mode = _SceneMode()
        mode.json = json.loads(SCENE_MODE_ERROR)
        assert mode.video_config.encryption.scheme == []
