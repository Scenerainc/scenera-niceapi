import json
from logging import INFO, Logger, getLogger
from typing import Any, Dict, Optional, Tuple, Union

from ..cmf._request import _CMFRequest
from ..cmf._response import _CMFResponse
from ..crypto.base import JWEDecrypt, JWEEncrypt, JWSSign, JWSVerify
from ..util._tools import _logger_setup

RESUTL_T = Tuple[bool, ...]
DICT_T = Dict[str, Any]

logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)


class ApiRequestHandler:
    """API Request Handler class.

    This class is typically used on the server side to handle APIs requests.
    """

    @classmethod
    def parse_cmf_container_object(
        cls, verify: JWSVerify, cmf_container_object: DICT_T
    ) -> Tuple[bool, Optional[str], Optional[str], Optional[Any]]:
        """Parse CMFContainer Object.

        Parameters
        ----------
        verify : :obj:`JWSVerify` subclass
            instance of :obj:`JWSVerify` subclass

        cmf_container_object : dict
            CMFContainer Object

        Returns
        -------
        bool
            True if successful

        str
            SourceEndPointID or None

        str
            DestinationEndPointID or None

        dict
            verified CMFRequest or None
        """
        try:
            cmf_request = _CMFRequest()
            jws = cmf_request.unwrap_jws(cmf_container_object)
            success, jws_payload = verify(jws)
            if not success:
                logger.error("failed to verify")
                return False, None, None, None
            request = json.loads(jws_payload)
            cmf_request.json = request
            src = cmf_request.source_end_point_id
            dst = cmf_request.destination_end_point_id
            return True, src, dst, request
        except Exception as e:
            logger.error(e)
        return False, None, None, None

    @classmethod
    def parse_cmf_request_object(
        cls, decrypt: JWEDecrypt, cmf_request_object: DICT_T
    ) -> Tuple[bool, Optional[str], Optional[DICT_T]]:
        """Parse CMFRequest Object.

        Parameters
        ----------
        decrypt : :obj:`JWEDecrypt` subclass
            instance of :obj:`JWEDecrypt` subclass

        cmf_request_object : dict
            CMFRequest Object

        Returns
        -------
        bool
            True if successful

        str
            AccessToken or None

        dict
            Payload Object or None
        """
        try:
            cmf_request = _CMFRequest()
            cmf_request.json = cmf_request_object
            if cmf_request.payload:
                success, payload = decrypt(cmf_request.payload)
                if not success:
                    logger.error("failed to decrypt")
                    return False, None, None
                payload = json.loads(payload)
                token = payload.get("AccessToken")
                object_ = payload.get("PayloadObject")
                return True, token, object_
            else:
                return True, None, None
        except Exception as e:
            logger.error(e)
        return False, None, None

    @classmethod
    def make_cmf_container_object(
        cls,
        sign: JWSSign,
        encrypt: JWEEncrypt,
        request: DICT_T,
        date: str,
        code: int,
        msg: str,
        obj: DICT_T,
    ) -> Union[Tuple[bool, None, None], Tuple[bool, Any, Any]]:
        """Make CMFContainer Object.

        Parameters
        ----------
        sign : :obj:`JWSSign` subclass
            instance of :obj:`JWSSign` subclass

        encrypt : :obj:`JWEEncrypt` subclass
            instance of :obj:`JWEEncrypt` subclass

        request : dict
            CMFRequest Object

        date : str
            DateTimeStamp

        code : int
            ReplyStatusCode

        msg : str
            ReplyStatusMessage

        obj : dict
            JSON Object for response

        Returns
        -------
        bool
            True if successful

        dict
            CMFContainer Object or None

        dict
            CMFResponse Object or None
        """
        try:
            cmf_request = _CMFRequest()
            cmf_request.json = request
            src = cmf_request.destination_end_point_id
            dst = cmf_request.source_end_point_id
            encrypted_payload = {"PayloadObject": obj}
            success, jwe = encrypt(json.dumps(encrypted_payload).encode())
            if not success:
                logger.error("failed to encrypt")
                return False, None, None
            cmf_response = _CMFResponse()
            cmf_response.source_end_point_id = src
            cmf_response.destination_end_point_id = dst
            cmf_response.date_time_stamp = date
            cmf_response.reply_status_code = code
            cmf_response.reply_status_message = msg
            cmf_response.payload = jwe
            cmf_response_json = cmf_response.json
            payload = json.dumps(cmf_response_json).encode()
            success, jws = sign(payload)
            if not success:
                logger.error("failed to sign")
                return False, None, None
            cmf_container = cmf_response.wrap_jws(jws)
            return True, cmf_container, cmf_response_json
        except Exception as e:
            logger.error(e)
        return False, None, None
