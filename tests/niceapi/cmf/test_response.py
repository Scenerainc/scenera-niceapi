"""Test for CMFResponse."""
from src.niceapi.cmf._response import _CMFResponse


class TestCMFResponse:
    """CMFResponse test class."""
   
    __VERSION = '1.0'

    __MESSAGE_TYPE = 'response'
    
    __PAYLOAD = 'payload'

    __SOURCE_END_POINT_ID = 'source_end_point_id'

    __DESTINATION_END_POINT_ID = 'destination_end_point_id'

    __DATE_TIME_STAMP = '2022-02-21T03:25:57.771Z'

    __REPLY_STATUS_MESSAGE = 'success'

    __REPLY_STATUS_CODE = 200

    __JSON = {
        'Version': __VERSION,
        'MessageType': __MESSAGE_TYPE,
        'SourceEndPointID': __SOURCE_END_POINT_ID,
        'DestinationEndPointID': __DESTINATION_END_POINT_ID,
        'ReplyStatusCode': __REPLY_STATUS_CODE,
        'DateTimeStamp': __DATE_TIME_STAMP,
        'ReplyStatusMessage': __REPLY_STATUS_MESSAGE,
        'Payload': __PAYLOAD,
    }

    __JWS = 'jws'

    def createCMFResponse(self, date_time_stamp=None, reply_status_message=None,
                          payload=None, json=__JSON):
        cmf = _CMFResponse()
        cmf.source_end_point_id = self.__SOURCE_END_POINT_ID
        cmf.destination_end_point_id = self.__DESTINATION_END_POINT_ID
        cmf.date_time_stamp = date_time_stamp
        cmf.reply_status_code = self.__REPLY_STATUS_CODE
        cmf.reply_status_message = reply_status_message
        cmf.payload = payload
        cmf.json = json
        return cmf

    def test_property_01(self):
        """
        property is set correctly.
        """
        # test
        cmf = self.createCMFResponse(date_time_stamp=self.__DATE_TIME_STAMP,
                                     reply_status_message=self.__REPLY_STATUS_MESSAGE,
                                     payload=self.__PAYLOAD)

        # check
        assert cmf.version == self.__VERSION
        assert cmf.message_type == self.__MESSAGE_TYPE
        assert cmf.source_end_point_id == self.__SOURCE_END_POINT_ID
        assert cmf.destination_end_point_id == self.__DESTINATION_END_POINT_ID
        assert cmf.date_time_stamp == self.__DATE_TIME_STAMP
        assert cmf.reply_status_code == self.__REPLY_STATUS_CODE
        assert cmf.reply_status_message == self.__REPLY_STATUS_MESSAGE
        assert cmf.payload == self.__PAYLOAD
        assert cmf.json == self.__JSON

    def test_property_02(self, mocker):
        """
        property is set correctly.
        """
        # mock set
        date_time = '2022-02-22T05:00:00.771Z'
        mocker.patch('src.niceapi.cmf._response._datetime_utcnow', return_value=date_time)

        # test
        test_json = self.__JSON
        del test_json["Payload"], test_json["ReplyStatusMessage"]
        cmf = self.createCMFResponse(json=self.__JSON)
        cmf.date_time_stamp = None

        # check
        assert cmf.version == self.__VERSION
        assert cmf.message_type == self.__MESSAGE_TYPE
        assert cmf.source_end_point_id == self.__SOURCE_END_POINT_ID
        assert cmf.destination_end_point_id == self.__DESTINATION_END_POINT_ID
        assert cmf.date_time_stamp is None
        assert cmf.reply_status_code == self.__REPLY_STATUS_CODE
        assert cmf.reply_status_message is None
        assert cmf.payload is None
        expect_dict = test_json
        expect_dict['DateTimeStamp'] = date_time
        assert cmf.json == expect_dict

    def test_wrap_jws_01(self):
        """
        dictionary with Key is 'SignedCMF' is generated.
        """
        # test
        cmf = self.createCMFResponse(date_time_stamp=self.__DATE_TIME_STAMP,
                                     reply_status_message=self.__REPLY_STATUS_MESSAGE,
                                     payload=self.__PAYLOAD)
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
        cmf = self.createCMFResponse(date_time_stamp=self.__DATE_TIME_STAMP,
                                     reply_status_message=self.__REPLY_STATUS_MESSAGE,
                                     payload=self.__PAYLOAD)
        wrap_jws = cmf.wrap_jws(self.__JWS)
        jws = cmf.unwrap_jws(wrap_jws)

        # check
        assert jws == self.__JWS

    def test_has_valid_end_points_01(self):
        """
        Valid endpoint IDs
        """
        # test
        cmf = self.createCMFResponse()
        result = cmf.has_valid_end_points('destination_end_point_id', 'source_end_point_id')

        # check
        assert result == True

    def test_has_valid_end_points_02(self):
        """
        Invalid endpoint IDs
        """
        # test
        cmf = self.createCMFResponse()
        result = cmf.has_valid_end_points('destination_end_point_id', 'destination_end_point_id')

        # check
        assert result == False
