"""Test for CMFRequest."""
from src.niceapi.cmf._request import _CMFRequest
import json


class TestCMFRequest:
    """CMFRequest test class."""
   
    __VERSION = '1.0'
    __MESSAGE_TYPE = 'request'
    __PAYLOAD = 'payload'
    __SOURCE_END_POINT_ID = 'source_end_point_id'
    __DESTINATION_END_POINT_ID = 'destination_end_point_id'
    __DATE_TIME_STAMP = '2022-02-21T03:25:57.771Z'
    __COMMAND_ID = 0
    __COMMAND_TYPE = 'command_type'
    __JSON = {
        'Version': __VERSION,
        'MessageType': __MESSAGE_TYPE,
        'SourceEndPointID': __SOURCE_END_POINT_ID,
        'DestinationEndPointID': __DESTINATION_END_POINT_ID,
        'CommandType': __COMMAND_TYPE,
        'DateTimeStamp': __DATE_TIME_STAMP,
        'Payload': __PAYLOAD,
    }
    __JSON_HEADER = {
        'Version': __VERSION,
        'MessageType': __MESSAGE_TYPE,
        'SourceEndPointID': __SOURCE_END_POINT_ID,
        'DestinationEndPointID': __DESTINATION_END_POINT_ID,
        'CommandType': __COMMAND_TYPE,
        'DateTimeStamp': __DATE_TIME_STAMP,
    }
    __ACCESS_TOKEN = 'access_token'

    __CERTIFICATE = 'certificate'

    __JWS = 'jws'

    def createCMFRequest(self, date_time_stamp=None,
                         payload=None, command_id=None, json=__JSON):
        cmf = _CMFRequest()
        cmf.source_end_point_id = self.__SOURCE_END_POINT_ID
        cmf.destination_end_point_id = self.__DESTINATION_END_POINT_ID
        cmf.date_time_stamp = date_time_stamp
        cmf.command_type = self.__COMMAND_TYPE
        cmf.payload = payload
        cmf.command_id = command_id
        cmf.json = json
        return cmf

    def test_property_01(self):
        """
        property is set correctly.
        """
        # test
        cmf = self.createCMFRequest(date_time_stamp=self.__DATE_TIME_STAMP,
                                    payload=self.__PAYLOAD, command_id=self.__COMMAND_ID, json=self.__JSON)

        # check
        assert cmf.version == self.__VERSION
        assert cmf.message_type == self.__MESSAGE_TYPE
        assert cmf.source_end_point_id == self.__SOURCE_END_POINT_ID
        assert cmf.destination_end_point_id == self.__DESTINATION_END_POINT_ID
        assert cmf.date_time_stamp == self.__DATE_TIME_STAMP
        assert cmf.command_type == self.__COMMAND_TYPE
        assert cmf.payload == self.__PAYLOAD
        assert cmf.json == self.__JSON

    def test_property_02(self, mocker):
        """
        If date time, payload is None,
        property is set correctly.
        """
        # mock set
        date_time = '2022-02-21T05:00:00.771Z'
        mocker.patch('src.niceapi.cmf._request._datetime_utcnow', return_value=date_time)

        # test
        test_json = self.__JSON
        del test_json["DateTimeStamp"], test_json["Payload"]
        cmf = self.createCMFRequest(json=test_json)

        # check
        assert cmf.version == self.__VERSION
        assert cmf.message_type == self.__MESSAGE_TYPE
        assert cmf.source_end_point_id == self.__SOURCE_END_POINT_ID
        assert cmf.destination_end_point_id == self.__DESTINATION_END_POINT_ID
        assert cmf.date_time_stamp is None
        assert cmf.command_type == self.__COMMAND_TYPE
        assert cmf.payload is None
        expect_json = test_json
        expect_json['DateTimeStamp'] = date_time
        assert cmf.json == expect_json

    def test_make_payload_01(self):
        """
        If PayloadObject does not exist,
        dictionary with only AccessToken will be generated.
        """
        # test
        cmf = self.createCMFRequest(json=self.__JSON)
        payload = cmf.make_payload(self.__ACCESS_TOKEN, None)

        # check
        expect_dict = {
            'AccessToken': self.__ACCESS_TOKEN
        }
        assert payload == expect_dict

    def test_make_payload_02(self):
        """
        If PayloadObject is present,
        AccessToken and PayloadObject dictionary will be generated.
        """
        # test
        cmf = self.createCMFRequest(json=self.__JSON)
        payload_obj = {
            'Body': {
                'DeviceID': '00000009-60fe-5e15-8002-000000001954'
            }
        }
        payload = cmf.make_payload(self.__ACCESS_TOKEN, payload_obj)

        # check
        expect_dict = {
            'AccessToken': self.__ACCESS_TOKEN,
            'PayloadObject': {
                'Body': {
                    'DeviceID': '00000009-60fe-5e15-8002-000000001954'
                }
            }
        }
        assert payload == expect_dict

    def test_make_request_01(self):
        """
        dictionary without headers will be generated.
        """
        # test
        cmf = self.createCMFRequest(date_time_stamp=self.__DATE_TIME_STAMP,
                                    payload=self.__PAYLOAD, command_id=self.__COMMAND_ID, json=self.__JSON)
        request = cmf.make_request(certificate=self.__CERTIFICATE)

        # check
        assert request == self.__JSON

    def test_wrap_jws_01(self):
        """
        dictionary with Key is 'SignedCMF' is generated.
        """
        # test
        cmf = self.createCMFRequest(date_time_stamp=self.__DATE_TIME_STAMP,
                                    payload=self.__PAYLOAD, command_id=self.__COMMAND_ID, json=self.__JSON)
        jws = cmf.wrap_jws(self.__JWS)

        # check
        expect_dict = {
            'SignedCMF': self.__JWS
        }
        assert jws == expect_dict

    def test_unwrap_jws_01(self):
        """
        JWS can get.
        """
        # test
        cmf = self.createCMFRequest(date_time_stamp=self.__DATE_TIME_STAMP,
                                    payload=self.__PAYLOAD, command_id=self.__COMMAND_ID, json=self.__JSON)
        wrap_jws = cmf.wrap_jws(self.__JWS)
        jws = cmf.unwrap_jws(wrap_jws)

        # check
        assert jws == self.__JWS

