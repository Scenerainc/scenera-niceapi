import json
import pytest
from src.niceapi.api.data import DataSection

@pytest.fixture
def data_object():
    data = DataSection(
        version="1.0",
        data_id="001",
        section=1,
        last_section=1,
        section_base64="XXX",
        media_format="JPEG"
    )
    return data

class TestDataSection:
    """DataSection test class."""

    def test_property_json(self, data_object):
        """
        test the getter of json
        """
        assert data_object.json == {
            "Version": "1.0",
            "DataID": "001",
            "Section": 1,
            "LastSection": 1,
            "SectionBase64": "XXX",
            "MediaFormat": "JPEG"
        }

    def test_set_file_type(self, data_object):
        """
        test the setter of FileType
        """
        data_object.set_file_type("Image")
        assert data_object.json["FileType"] == "Image"

    def test_set_file_name(self, data_object):
        """
        test the setter of FileName
        """
        data_object.set_file_name("ABCD.jpg")
        assert data_object.json["FileName"] == "ABCD.jpg"

    def test_set_path_uri(self, data_object):
        """
        test the setter of PathURI
        """
        data_object.set_path_uri("ABCD")
        assert data_object.json["PathURI"] == "ABCD"

    def test_set_hash_method(self, data_object):
        """
        test the setter of HashMethod
        """
        data_object.set_hash_method("SHA256")
        assert data_object.json["HashMethod"] == "SHA256"

    def test_set_original_file_hash(self, data_object):
        """
        test the setter of OriginalFileHash
        """
        data_object.set_original_file_hash("ABCDEF")
        assert data_object.json["OriginalFileHash"] == "ABCDEF"

    def test_set_encryption_on(self, data_object):
        """
        test the setter of EncryptionOn
        """
        data_object.set_encryption_on(True)
        assert data_object.json["EncryptionOn"] == True
