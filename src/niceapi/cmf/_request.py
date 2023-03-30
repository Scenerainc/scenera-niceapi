from logging import INFO, Logger, getLogger
from typing import Any, Dict, Optional

from ..util._tools import _datetime_utcnow, _logger_setup

DICT_T = Dict[str, Any]


logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)

JWS_KEY: str = "SignedCMF"
JWE_KEY: str = "Payload"
VER_KEY: str = "Version"
MSG_KEY: str = "MessageType"
SRC_KEY: str = "SourceEndPointID"
DST_KEY: str = "DestinationEndPointID"
DTS_KEY: str = "DateTimeStamp"
CMD_KEY: str = "CommandType"
PLD_KEY: str = "Payload"
TKN_KEY: str = "AccessToken"
OBJ_KEY: str = "PayloadObject"


class _CMFRequest:
    _VERSION: str = "1.0"
    _MESSAGE_TYPE: str = "request"

    def __init__(self) -> None:
        self._version: Optional[str] = self._VERSION
        self._message_type: Optional[str] = self._MESSAGE_TYPE
        self._source_end_point_id: Optional[str] = None
        self._destination_end_point_id: Optional[str] = None
        self._date_time_stamp: Optional[str] = None
        self._command_type: Optional[str] = None
        self._payload: Optional[str] = None

    @property
    def version(self) -> Optional[str]:
        return self._version

    @property
    def message_type(self) -> Optional[str]:
        return self._message_type

    @property
    def source_end_point_id(self) -> Optional[str]:
        return self._source_end_point_id

    @source_end_point_id.setter
    def source_end_point_id(self, obj: Optional[str]) -> None:
        self._source_end_point_id = obj

    @property
    def destination_end_point_id(self) -> Optional[str]:
        return self._destination_end_point_id

    @destination_end_point_id.setter
    def destination_end_point_id(self, obj: Optional[str]) -> None:
        self._destination_end_point_id = obj

    @property
    def date_time_stamp(self) -> Optional[str]:
        return self._date_time_stamp

    @date_time_stamp.setter
    def date_time_stamp(self, obj: Optional[str]) -> None:
        self._date_time_stamp = obj

    @property
    def command_type(self) -> Optional[str]:
        return self._command_type

    @command_type.setter
    def command_type(self, obj: Optional[str]) -> None:
        self._command_type = obj

    @property
    def payload(self) -> Optional[str]:
        return self._payload

    @payload.setter
    def payload(self, payload: Optional[str]) -> None:
        self._payload = payload

    @property
    def json(self) -> DICT_T:
        json_obj: DICT_T = {
            VER_KEY: self._VERSION,
            MSG_KEY: self._MESSAGE_TYPE,
            SRC_KEY: self._source_end_point_id,
            DST_KEY: self._destination_end_point_id,
            CMD_KEY: self._command_type,
        }
        if self._date_time_stamp is not None:
            json_obj[DTS_KEY] = self._date_time_stamp
        else:
            json_obj[DTS_KEY] = _datetime_utcnow()

        # option
        if self._payload is not None:
            json_obj[PLD_KEY] = self._payload

        return json_obj

    @json.setter
    def json(self, obj: DICT_T) -> None:
        self._version = obj.get(VER_KEY)
        self._message_type = obj.get(MSG_KEY)
        self._source_end_point_id = obj.get(SRC_KEY)
        self._destination_end_point_id = obj.get(DST_KEY)
        self._date_time_stamp = obj.get(DTS_KEY)
        self._command_type = obj.get(CMD_KEY)
        self._payload = obj.get(JWE_KEY)

    def make_payload(
        self,
        access_token: Optional[str],
        payload_object: Optional[DICT_T] = None,
    ) -> DICT_T:
        payload: DICT_T = {TKN_KEY: access_token}
        if payload_object:
            payload[OBJ_KEY] = payload_object
        return payload

    def make_request(self, certificate: Optional[str] = None) -> DICT_T:
        request = self.json
        return request

    def wrap_jws(self, jws: str) -> DICT_T:
        key = JWS_KEY
        return {key: jws}

    def unwrap_jws(self, container: DICT_T) -> Optional[Any]:
        jws = container.get(JWS_KEY)
        return jws
