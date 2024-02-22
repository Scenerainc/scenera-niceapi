from logging import INFO, Logger, getLogger
from typing import Any, Dict, List, Optional, Union

from ..util._tools import _logger_setup

DICT_T = Dict[str, Any]


logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)


class SceneMark:
    """SceneMark class

    use ApiRequest.new_scene_mark() for instantiation
    """

    def __init__(
        self,
        version: str,
        time_stamp: str,
        scene_mark_id: str,
        node_id: str,
    ) -> None:
        """Constructor

        Parameters
        ----------
        version : str
            value of SceneMark["Version"]

        time_stamp : str
            value of SceneMark["TimeStamp"]

        scene_mark_id : str
            value of SceneMark["SceneMarkID"]

        node_id : str
            value of SceneMark["NodeID"]

        """
        self._json: DICT_T = {
            "Version": version,
            "TimeStamp": time_stamp,
            "SceneMarkID": scene_mark_id,
            "NodeID": node_id,
        }

    @property
    def json(self) -> DICT_T:
        """dict: get JSON Object of SceneMark"""
        return self._json

    class DetectedObject:
        """SceneMark["AnalysisList"][N]["DetectedObjects"] element class

        Examples
        --------

        (1) Instantiate

            * scene_mark = ApiRequest.new_scene_mark(...)
            * analysis = scene_mark.new_analysis()
            * detected = analysis.new_detected_object()

        (2) Setup Instance

            * detected.set_nice_item_type("Human")
            * etc.

        (3) Register Instance

            * analysis.add_detected_object(detected)
        """

        def __init__(self) -> None:
            self._json: DICT_T = dict()

        @property
        def json(self) -> DICT_T:
            """dict: get JSON Object of SceneMark.DetectedObject"""
            return self._json

        def set_version_number(self, version_number: int) -> None:
            """Set DetectedObject["VersionNumber"]

            Parameters
            ----------
            version_number : int
                value of VersionNumber

            Returns
            -------
            None
            """
            self._json["VersionNumber"] = version_number

        def set_nice_item_type(self, nice_item_type: str) -> None:
            """Set DetectedObject["NICEItemType"]

            Parameters
            ----------
            nice_item_type : str
                value of NICEItemType

            Returns
            -------
            None
            """
            self._json["NICEItemType"] = nice_item_type

        def set_custom_item_type(self, custom_item_type: str) -> None:
            """Set DetectedObject["CustomItemType"]

            Parameters
            ----------
            custom_item_type : str
                value of CustomItemType

            Returns
            -------
            None
            """
            self._json["CustomItemType"] = custom_item_type

        def set_item_id(self, item_id: str) -> None:
            """Set DetectedObject["ItemID"]

            Parameters
            ----------
            item_id : str
                value of ItemID

            Returns
            -------
            None
            """
            self._json["ItemID"] = item_id

        def set_probability(self, probability: float) -> None:
            """Set DetectedObject["Probability"]

            Parameters
            ----------
            probability : float
                value of Probability

            Returns
            -------
            None
            """
            self._json["Probability"] = probability

        def set_analysis(
            self,
            mode: Optional[str] = None,
            analysis_id: Optional[str] = None,
            description: Optional[str] = None,
            status: Optional[str] = None,
        ) -> None:
            """Set DetectedObject["Analysis"]

            Parameters
            ----------
            mode : str
                value of Analysis["SceneMode"]

            analysis_id : str
                value of Analysis["CustomAnalysisID"]

            description : str
                value of Analysis["AnalysisDescription"]

            status : str
                value of Analysis["ProcessingStatus"]
                that is
                "Motion", "Detect", "Recognize", or "Characterize"

            Returns
            -------
            None
            """
            obj = dict()
            if mode:
                obj["SceneMode"] = mode
            if analysis_id:
                obj["CustomAnalysisID"] = analysis_id
            if description:
                obj["AnalysisDescription"] = description
            if status:
                obj["ProcessingStatus"] = status
            self._json["Analysis"] = obj

        def add_attribute(
            self,
            attribute: Optional[str] = None,
            probability: Optional[float] = None,
            algorithm_id: Optional[str] = None,
        ) -> None:
            """Add DetectedObject["Attributes"] element

            Parameters
            ----------
            attribute : str
                value of Attribute["Attribute"]

            probability : float
                value of Attribute["ProbabilityofAttribute"]

            algorithm_id : str
                value of Attribute["AlgorithmID"]

            Returns
            -------
            None
            """
            obj: DICT_T = dict()
            if attribute:
                obj["Attribute"] = attribute
            if probability:
                obj["ProbabilityofAttribute"] = probability
            if algorithm_id:
                obj["AlgorithmID"] = algorithm_id
            if obj:
                if "Attributes" in self._json:
                    self._json["Attributes"].append(obj)
                else:
                    self._json["Attributes"] = [obj]
            else:
                self._json["Attributes"] = []

        def set_bounding_box(
            self, x: int, y: int, width: int, height: int
        ) -> None:
            """Set DetectedObject["BoundingBox"]

            Parameters
            ----------
            x : int
                value of BoundingBox["XCoordinate"]

            y : int
                value of BoundingBox["YCoordinate"]

            width : int
                value of BoundingBox["Width"]

            height : int
                value of BoundingBox["Height"]

            Returns
            -------
            None
            """
            self._json["BoundingBox"] = {
                "XCoordinate": x,
                "YCoordinate": y,
                "Width": width,
                "Height": height,
            }

        def set_thumbnail_scene_data_id(
            self, thumbnail_scene_data_id: str
        ) -> None:
            """Set DetectedObject["ThumbnailSceneDataID"]

            Parameters
            ----------
            thumbnail_scene_data_id : str
                value of ThumbnailSceneDataID

            Returns
            -------
            None
            """
            self._json["ThumbnailSceneDataID"] = thumbnail_scene_data_id

    class Analysis:
        """SceneMark["AnalysisList"] element class

        Examples
        --------

        (1) Instantiate

            * scene_mark = ApiRequest.new_scene_mark(...)
            * analysis = scene_mark.new_analysis()

        (2) Setup Instance

            * analysis.set_version_number(1.0)
            * etc.

        (3) Register Instance

            * scene_mark.add_analysis(analysis)
        """

        def __init__(self) -> None:
            self._json: DICT_T = dict()

        @property
        def json(self) -> DICT_T:
            """dict: get JSON Object of SceneMark.Analysis"""
            return self._json

        def set_version_number(self, version_number: int) -> None:
            """Set Analysis["VersionNumber"]

            Parameters
            ----------
            version_number : int
                value of VersionNumber

            Returns
            -------
            None
            """
            self._json["VersionNumber"] = version_number
            
        def set_event_type(self, event_type: str) -> None:
            """Set Analysis["EventType"]

            Parameters
            ----------
            event_type : str
                EventType

            Returns
            -------
            None
            """
            self._json["EventType"] = event_type

        def set_scene_mode(self, scene_mode: str) -> None:
            """Set Analysis["SceneMode"]

            Parameters
            ----------
            scene_mode : str
                SceneMode

            Returns
            -------
            None
            """
            self._json["SceneMode"] = scene_mode

        def set_custom_analysis_id(self, custom_analysis_id: str) -> None:
            """Set Analysis["CustomAnalysisID"]

            Parameters
            ----------
            custom_analysis_id : str
                value of CustomAnalysisID

            Returns
            -------
            None
            """
            self._json["CustomAnalysisID"] = custom_analysis_id

        def set_analysis_description(self, analysis_description: str) -> None:
            """Set Analysis["AnalysisDescription"]

            Parameters
            ----------
            analysis_description : str
                value of AnalysisDescription

            Returns
            -------
            None
            """
            self._json["AnalysisDescription"] = analysis_description

        def set_processing_status(self, processing_status: str) -> None:
            """Set Analysis["ProcessingStatus"]

            Parameters
            ----------
            processing_status : str
                "Motion", "Detect", "Recognize", or "Characterize"

            Returns
            -------
            None
            """
            self._json["ProcessingStatus"] = processing_status

        def new_detected_object(self) -> "SceneMark.DetectedObject":
            """Generate Analysis["DetectedObjects"] element

            Returns
            -------
            SceneMark.DetectedObject
                empty SceneMark.DetectedObject
            """
            return SceneMark.DetectedObject()

        def add_detected_object(
            self, detected_object: "SceneMark.DetectedObject"
        ) -> None:
            """Add an element to Analysis["DetectedObjects"]

            Parameters
            ----------
            detected_object : SceneMark.DetectedObject
                SceneMark.DetectedObject generated by new_detected_object()

            Returns
            -------
            None
            """
            if "DetectedObjects" in self._json:
                self._json["DetectedObjects"].append(detected_object.json)
            else:
                self._json["DetectedObjects"] = [detected_object.json]

    class SceneData:
        """SceneMark["SceneDataList"] element class

        Examples
        --------

        (1) Instantiate

            * scene_mark = ApiRequest.new_scene_mark(...)
            * scene_data = scene_mark.new_scene_data(...)

        (2) Setup Instance

            * scene_data.set_version_number(1.0)
            * etc.

        (3) Register Instance

            * scene_mark.add_scene_data(scene_data)
        """

        def __init__(
            self,
            scene_data_id: str,
            time_stamp: str,
            encryption: bool,
        ) -> None:
            """Constructor

            Parameters
            ----------
            scene_data_id : str
                value of SceneData["SceneDataID"]

            time_stamp : str
                value of SceneData["TimeStamp"]

            encryption : bool
                value of SceneData["Encryption"]["EncryptionOn"]

            Returns
            -------
            None
            """
            self._json: DICT_T = {
                "SceneDataID": scene_data_id,
                "TimeStamp": time_stamp,
                "Encryption": {"EncryptionOn": encryption},
            }

        @property
        def json(self) -> DICT_T:
            """dict: get JSON Object of SceneMark.SceneData"""
            return self._json

        def set_source_node_id(self, source_node_id: str) -> None:
            """Set SceneData["SourceNodeID"]

            Parameters
            ----------
            source_node_id : str
                value of SourceNodeID

            Returns
            -------
            None
            """
            self._json["SourceNodeID"] = source_node_id

        def set_source_node_description(
            self, source_node_description: str
        ) -> None:
            """Set SceneData["SourceNodeDescription"]

            Parameters
            ----------
            source_node_description : str
                value of SourceNodeDescription

            Returns
            -------
            None
            """
            self._json["SourceNodeDescription"] = source_node_description

        def set_duration(self, duration: str) -> None:
            """Set SceneData["Duration"]

            Parameters
            ----------
            duration : str
                value of Duration

            Returns
            -------
            None
            """
            self._json["Duration"] = duration

        def set_data_type(self, data_type: str) -> None:
            """Set SceneData["DataType"]

            Parameters
            ----------
            data_type : str
                value of DataType

            Returns
            -------
            None
            """
            self._json["DataType"] = data_type

        def set_status(self, status: str) -> None:
            """Set SceneData["Status"]

            Parameters
            ----------
            status : str
                value of Status

            Returns
            -------
            None
            """
            self._json["Status"] = status

        def set_media_format(self, media_format: str) -> None:
            """Set SceneData["MediaFormat"]

            Parameters
            ----------
            media_format : str
                value of MediaFormat

            Returns
            -------
            None
            """
            self._json["MediaFormat"] = media_format

        def set_resolution(self, width: int, height: int) -> None:
            """Set SceneData["Resolution"]

            Parameters
            ----------
            width : int
                value of Resolution["Width"]

            height : int
                value of Resolution["Height"]

            Returns
            -------
            None
            """
            inner_width: Union[int, str] = width
            inner_height: Union[int, str] = height
            if isinstance(width, str):
                inner_width = int(width)
            if isinstance(height, str):
                inner_height = int(height)
            self._json["Resolution"] = {
                "Width": inner_width,
                "Height": inner_height,
            }

        def set_scene_data_uri(self, scene_data_uri: str) -> None:
            """Set SceneData["SceneDataURI"]

            Parameters
            ----------
            scene_data_uri : str
                value of SceneDataURI

            Returns
            -------
            None
            """
            self._json["SceneDataURI"] = scene_data_uri

        def set_embedded_scene_data(self, embedded_scene_data: str) -> None:
            """Set SceneData["EmbeddedSceneData"]

            Parameters
            ----------
            embedded_scene_data : str
                value of EmbeddedSceneData

            Returns
            -------
            None
            """
            self._json["EmbeddedSceneData"] = embedded_scene_data

        def new_webapi_scheme(
            self,
            authority: str,
            access_token: Optional[str] = None,
            role: Optional[str] = None,
        ) -> DICT_T:
            """Generate JSON Object of WebAPI Scheme

            Parameters
            ----------
            authority : str
                value of WebAPIScheme["Authority"]

            access_token : str
                value of WebAPIScheme["AccessToken"]

            role : str
                value of WebAPIScheme["Role"]

            Returns
            -------
            dict
                JSON Object of WebAPI Scheme
            """
            json_obj = {
                "Protocol": "WebAPI",
                "Authority": authority,
            }
            if access_token is not None:
                json_obj["AccessToken"] = access_token
            if role is not None:
                json_obj["Role"] = role
            return json_obj

        def new_app_end_point(
            self,
            version: str,
            end_point_id: str,
            certificate: Optional[List[str]] = None,
            access_token: Optional[str] = None,
        ) -> DICT_T:
            """Generate JSON Object of AppEndPoint

            Parameters
            ----------
            version : str
                value of AppEndPoint["APIVersion"]

            end_point_id : str
                value of AppEndPoint["EndPointID"]

            certificate : list of str
                value of AppEndPoint["X.509Certificate"]

            access_token : str
                value of AppEndPoint["AccessToken"]

            Returns
            -------
            dict
                JSON Object of AppEndPoint
            """
            json_obj: DICT_T = {
                "APIVersion": version,
                "EndPointID": end_point_id,
            }
            if certificate is not None:
                json_obj["X.509Certificate"] = certificate
            if access_token is not None:
                json_obj["AccessToken"] = access_token
            return json_obj

        def new_net_end_point(
            self,
            version: str,
            end_point_id: str,
            scheme: List[DICT_T],
            node_id: Optional[str] = None,
            port_id: Optional[str] = None,
        ) -> DICT_T:
            """Generate JSON Object of NetEndPoint

            Parameters
            ----------
            version : str
                value of NetEndPoint["APIVersion"]

            end_point_id : str
                value of NetEndPoint["EndPointID"]

            scheme : list of dict
                value of NetEndPoint["Scheme"]

            node_id : str
                value of NetEndPoint["NodeID"]

            port_id : str
                value of NetEndPoint["PortID"]

            Returns
            -------
            dict
                JSON Object of NetEndPoint
            """
            json_obj = {
                "APIVersion": version,
                "EndPointID": end_point_id,
                "Scheme": scheme,
            }
            if node_id is not None:
                json_obj["NodeID"] = node_id
            if port_id is not None:
                json_obj["PortID"] = port_id
            return json_obj

        def set_encryption_on(self, encrypt: bool) -> None:
            """Set SceneData["Encryption"]["EncryptionOn"]

            Parameters
            ----------
            encrypt : bool
                value of Encryption["EncryptionOn"]

            Returns
            -------
            None
            """
            self._json["Encryption"]["EncryptionOn"] = encrypt

        def set_encryption_key_id(self, key_id: str) -> None:
            """Set SceneData["Encryption"]["SceneEncryptionKeyID"]

            Parameters
            ----------
            key_id : str
                value of Encryption["SceneEncryptionKeyID"]

            Returns
            -------
            None
            """
            self._json["Encryption"]["SceneEncryptionKeyID"] = key_id

        def set_encryption_privacy_server(
            self, net_end_point: DICT_T, app_end_point: Optional[DICT_T] = None
        ) -> None:
            """Set SceneData["Encryption"]["PrivacyServerEndPoint"]

            Parameters
            ----------
            net_end_point : dict
                value of Encryption["PrivacyServerEndPoint"]["NetEndPoint"]

            app_end_point : dict
                value of Encryption["PrivacyServerEndPoint"]["AppEndPoint"]

            Returns
            -------
            None
            """
            if app_end_point is None:
                self._json["Encryption"]["PrivacyServerEndPoint"] = {
                    "NetEndPoint": net_end_point,
                }
            else:
                self._json["Encryption"]["PrivacyServerEndPoint"] = {
                    "AppEndPoint": app_end_point,
                    "NetEndPoint": net_end_point,
                }

        def set_encryption(self, encryption: DICT_T) -> None:
            """Set SceneData["Encryption"]

            Parameters
            ----------
            encryption : dict
                value of SceneData["Encryption"]

            Returns
            -------
            None
            """
            self._json["Encryption"] = encryption

    """End of Internal Class Definition
    """

    def set_destination_id(self, destination_id: str) -> None:
        """Set SceneMark["DestinationID"]

        Parameters
        ----------
        destination_id : str
            value of DestinationID

        Returns
        -------
        None
        """
        self._json["DestinationID"] = destination_id

    def set_scene_mark_status(self, scene_mark_status: str) -> None:
        """Set SceneMark["SceneMarkStatus"]

        Parameters
        ----------
        scene_mark_status : str
            "Removed", "Active", or "Processed"

        Returns
        -------
        None
        """
        self._json["SceneMarkStatus"] = scene_mark_status

    def set_port_id(self, port_id: str) -> None:
        """Set SceneMark["PortID"]

        Parameters
        ----------
        port : str
            port ID

        Returns
        -------
        None
        """
        self._json["PortID"] = port_id

    def set_data_pipeline_instance_id(
        self, data_pipeline_instance_id: str
    ) -> None:
        """Set SceneMark["VersionControl"]["DataPipelineInstanceID"]

        Parameters
        ----------
        data_pipeline_instance_id : str
            value of DataPipelineInstanceID

        Returns
        -------
        None
        """
        if "VersionControl" in self._json:
            self._json["VersionControl"][
                "DataPipelineInstanceID"
            ] = data_pipeline_instance_id
        else:
            self._json["VersionControl"] = {
                "DataPipelineInstanceID": data_pipeline_instance_id
            }

    def add_version_list(
        self, version_number: int, date_time_stamp: str, node_id: str
    ) -> None:
        """Add a JSON object to SceneMark["VersionControl"]["VersionList"]

        Parameters
        ----------
        version_number : int
            value of VersionNumber

        date_time_stamp : str
            value of DateTimeStamp

        node_id : str
            value of NodeID

        Returns
        -------
        None
        """
        item = {
            "VersionNumber": version_number,
            "DateTimeStamp": date_time_stamp,
            "NodeID": node_id,
        }
        if "VersionControl" in self._json:
            control = self._json["VersionControl"]
            if "VersionList" in control:
                control["VersionList"].append(item)
            else:
                control["VersionList"] = [item]
        else:
            self._json["VersionControl"] = {"VersionList": [item]}

    def add_thumbnail_list(
        self, version_number: int, scene_data_id: str
    ) -> None:
        """Add a JSON object to SceneMark["ThumbnailList"]

        Parameters
        ----------
        version_number : int
            value of VersionNumber

        scene_data_id : str
            value of SceneDataID

        Returns
        -------
        None
        """
        item = {"VersionNumber": version_number, "SceneDataID": scene_data_id}
        if "ThumbnailList" in self._json:
            self._json["ThumbnailList"].append(item)
        else:
            self._json["ThumbnailList"] = [item]

    def new_analysis(self) -> "SceneMark.Analysis":
        """Generate SceneMark["AnalysisList"] element

        Returns
        -------
        SceneMark.Analysis
            empty SceneMark.Analysis
        """
        return SceneMark.Analysis()

    def add_analysis(self, analysis: "SceneMark.Analysis") -> None:
        """Add an element to SceneMark["AnalysisList"]

        Parameters
        ----------
        analysis : SceneMark.Analysis
            SceneMark.Analysis generated by new_analysis()

        Returns
        -------
        None
        """
        if "AnalysisList" in self._json:
            self._json["AnalysisList"].append(analysis.json)
        else:
            self._json["AnalysisList"] = [analysis.json]

    def new_scene_data(
        self, scene_data_id: str, time_stamp: str, encryption: bool
    ) -> SceneData:
        """Generate SceneMark["SceneDataList"] element

        Parameters
        ----------
        scene_data_id : str
            value of SceneData["SceneDataID"]

        time_stamp : str
            value of SceneData["TimeStamp"]

        encryption : bool
            value of SceneData["Encryption"]["EncryptionOn"]

        Returns
        -------
        SceneMark.SceneData
            new SceneMark.SceneData
        """
        return SceneMark.SceneData(scene_data_id, time_stamp, encryption)

    def add_scene_data(self, scene_data: SceneData) -> None:
        """Add an element to SceneMark["SceneDataList"]

        Parameters
        ----------
        scene_data : SceneMark.SceneData
            SceneMark.SceneData generated by new_scene_data()

        Returns
        -------
        None
        """
        if "SceneDataList" in self._json:
            self._json["SceneDataList"].append(scene_data.json)
        else:
            self._json["SceneDataList"] = [scene_data.json]
