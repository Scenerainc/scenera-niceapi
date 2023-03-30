from logging import INFO, Logger, getLogger
from typing import Any, Dict, Optional

from ..util._tools import _datetime_utcnow, _has_required_keys, _logger_setup

DICT_T = Dict[str, Any]

logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)

JWS_KEY: str = "SignedCMF"
VER_KEY: str = "Version"
MSG_KEY: str = "MessageType"
SRC_KEY: str = "SourceEndPointID"
DST_KEY: str = "DestinationEndPointID"
DTS_KEY: str = "DateTimeStamp"
PLD_KEY: str = "Payload"
RSC_KEY: str = "ReplyStatusCode"
RSM_KEY: str = "ReplyStatusMessage"


class _CMFResponse:
    _VERSION = "1.0"
    _MESSAGE_TYPE = "response"
    _REQUIRED_KEYS = [VER_KEY, MSG_KEY, SRC_KEY, DST_KEY, DTS_KEY, RSC_KEY]

    def __init__(self) -> None:
        self._initialize()

    def _initialize(self) -> None:
        self._json: Optional[DICT_T] = None
        self._version: Optional[str] = self._VERSION
        self._message_type: Optional[str] = self._MESSAGE_TYPE
        self._source_end_point_id: Optional[str] = None
        self._destination_end_point_id: Optional[str] = None
        self._date_time_stamp: Optional[str] = None
        self._reply_status_code: Optional[int] = None
        self._reply_status_message: Optional[str] = None
        self._payload: Any = None

    @property
    def is_available(self) -> bool:
        return self._json is not None

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
    def destination_end_point_id(self, obj: str) -> None:
        self._destination_end_point_id = obj

    @property
    def date_time_stamp(self) -> Optional[str]:
        return self._date_time_stamp

    @date_time_stamp.setter
    def date_time_stamp(self, obj: str) -> None:
        self._date_time_stamp = obj

    @property
    def reply_status_code(self) -> Optional[int]:
        return self._reply_status_code

    @reply_status_code.setter
    def reply_status_code(self, obj: int) -> None:
        self._reply_status_code = obj

    @property
    def reply_status_message(self) -> Optional[str]:
        return self._reply_status_message

    @reply_status_message.setter
    def reply_status_message(self, obj: str) -> None:
        self._reply_status_message = obj

    @property
    def payload(self) -> Any:
        return self._payload

    @payload.setter
    def payload(self, payload: Any) -> None:
        self._payload = payload

    @property
    def json(self) -> DICT_T:
        json_obj = {
            VER_KEY: self._version,
            MSG_KEY: self._message_type,
            SRC_KEY: self._source_end_point_id,
            DST_KEY: self._destination_end_point_id,
            RSC_KEY: self._reply_status_code,
        }
        if self._date_time_stamp is not None:
            json_obj[DTS_KEY] = self._date_time_stamp
        else:
            json_obj[DTS_KEY] = _datetime_utcnow()

        # option
        if self._reply_status_message is not None:
            json_obj["ReplyStatusMessage"] = self._reply_status_message
        if self._payload is not None:
            json_obj["Payload"] = self._payload

        return json_obj

    @json.setter
    def json(self, obj: DICT_T) -> None:
        self._initialize()
        try:
            if not _has_required_keys(obj, self._REQUIRED_KEYS):
                raise ValueError("Invalid CMFResponse")
            self._version = obj[VER_KEY]
            self._message_type = obj[MSG_KEY]
            self._source_end_point_id = obj[SRC_KEY]
            self._destination_end_point_id = obj[DST_KEY]
            self._date_time_stamp = obj[DTS_KEY]
            self._reply_status_code = obj[RSC_KEY]
            self._reply_status_message = obj.get(RSM_KEY)
            self._payload = obj.get(PLD_KEY)
            self._json = obj
        except Exception as e:
            logger.error(e)
            self._initialize()

    def wrap_jws(self, obj: Any) -> DICT_T:
        key = JWS_KEY
        return {key: obj}

    def unwrap_jws(self, container: DICT_T) -> Any:
        jws = container.get(JWS_KEY)
        return jws

    def has_valid_end_points(
        self, request_src: Optional[str], request_dst: Optional[str]
    ) -> bool:
        if request_src != self._destination_end_point_id:
            return False
        if request_dst != self._source_end_point_id:
            return False
        return True
