from logging import INFO, Logger, getLogger
from typing import Any, Dict

from ..util._tools import _logger_setup

DICT_T = Dict[str, Any]

logger: Logger = getLogger(__name__)
_logger_setup(logger, INFO)


class DataSection:
    """DataSection class

    use ApiRequest.new_scene_data() for instantiation
    """

    def __init__(
        self,
        version: str,
        data_id: str,
        section: int,
        last_section: int,
        section_base64: str,
        media_format: str,
    ) -> None:
        """Constructor

        Parameters
        ----------
        version : str
            value of DataSection["Version"]

        data_id : str
            value of DataSection["DataID"]

        section : int
            value of DataSection["Section"]

        last_section : int
            value of DataSection["LastSection"]

        section_base64 : str
            value of DataSection["SectionBase64"]

        media_format : str
            value of DataSection["MediaFormat"]
        """
        self._json = {
            "Version": version,
            "DataID": data_id,
            "Section": section,
            "LastSection": last_section,
            "SectionBase64": section_base64,
            "MediaFormat": media_format,
        }

    @property
    def json(self) -> DICT_T:
        """dict: get JSON Object of DataSection"""
        return self._json

    def set_file_type(self, file_type: str) -> None:
        """Set DataSection["FileType"]

        Parameters
        ----------
        file_type : str
            value of FileType

        Returns
        -------
        None
        """
        self._json["FileType"] = file_type

    def set_file_name(self, file_name: str) -> None:
        """Set DataSection["FileName"]

        Parameters
        ----------
        file_name : str
            value of FileName

        Returns
        -------
        None
        """
        self._json["FileName"] = file_name

    def set_path_uri(self, path_uri: str) -> None:
        """Set DataSection["PathURI"]

        Parameters
        ----------
        path_uri : str
            value of PathURI

        Returns
        -------
        None
        """
        self._json["PathURI"] = path_uri

    def set_hash_method(self, hash_method: str) -> None:
        """Set DataSection["HashMethod"]

        Parameters
        ----------
        hash_method : str
            "MD5", "SHA1", or "SHA256"

        Returns
        -------
        None
        """
        self._json["HashMethod"] = hash_method

    def set_original_file_hash(self, original_file_hash: str) -> None:
        """Set DataSection["OriginalFileHash"]

        Parameters
        ----------
        original_file_hash : str
            value of OriginalFileHash

        Returns
        -------
        None
        """
        self._json["OriginalFileHash"] = original_file_hash

    def set_encryption_on(self, encryption_on: bool) -> None:
        """Set DataSection["EncryptionOn"]

        Parameters
        ----------
        encryption_on : bool
            value of EncryptionOn

        Returns
        -------
        None
        """
        self._json["EncryptionOn"] = encryption_on
