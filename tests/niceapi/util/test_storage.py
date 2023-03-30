"""Test for Storage."""
from src.niceapi.util._storage import _Storage
import pytest
import json
import os
from pathlib import Path
from unittest.mock import patch, mock_open

class TestStorage:
    """Storage test class."""

    __STORAGE_SIZE = 3*1024*1024
    __STORE_PATH = 'storage/sample.json'
    __STORE_TEXT = '{"Version": "1.0"}'
    __SCENE_MARK = {'Version': '1.0', 'SceneMarkID': 'aaa'}
    __SCENE_DATA = {'Version': '1.0', 'DataID': 'aaa', 'Section': 1, 'LastSection': 1, 'FileType': 'Image'}
    __SCENE_DATA_VIDEO = {'Version': '1.0', 'DataID': 'aaa', 'Section': 1, 'LastSection': 1, 'FileType': 'Video'}

    @pytest.fixture()
    def setup_init(self):
        _Storage._sequence_number = 0
        _Storage._ready = False
        _Storage._size = 0
        _Storage._amount = 0
        _Storage._list.clear()

    def test_set_size_01(self, setup_init):
        """
        Storage size setting.
        """
        # test
        _Storage.set_size(self.__STORAGE_SIZE)

        # check
        assert _Storage._size == self.__STORAGE_SIZE

    def test_set_size_02(self, mocker, setup_init):
        """
        Storage size setting if the directory exists.
        """
        # mock set
        exists_mock = mocker.patch('pathlib.Path.exists', return_value=True)
        rmtree_mock = mocker.patch('shutil.rmtree')

        # test
        _Storage.set_size(self.__STORAGE_SIZE)

        # check
        assert _Storage._size == self.__STORAGE_SIZE
        exists_mock.assert_called_once()
        rmtree_mock.assert_called_once_with(Path('storage'))

    def test___get_sequence_number_01(self, setup_init):
        """
        Get sequence number.
        """
        # test
        _Storage._get_sequence_number()

        # check
        assert _Storage._sequence_number == 1

    def test___store_text_01(self, mocker, setup_init):
        """
        Store the text.
        """
        # mock set
        mkdir_mock = mocker.patch('pathlib.Path.mkdir')
        unlink_mock = mocker.patch('pathlib.Path.unlink')
        open_mock = mock_open()

        # test
        with patch('builtins.open', open_mock):
            _Storage.set_size(self.__STORAGE_SIZE)
            _Storage._store_text(self.__STORE_PATH, self.__STORE_TEXT)

        # check
        mkdir_mock.assert_called_once_with(exist_ok=True)
        unlink_mock.assert_not_called()
        open_mock().write.assert_called_once_with(self.__STORE_TEXT)

    def test___store_text_02(self, mocker, setup_init):
        """
        Store the text.
        storage size is 0.
        """
        # mock set
        mkdir_mock = mocker.patch('pathlib.Path.mkdir')
        unlink_mock = mocker.patch('pathlib.Path.unlink')
        open_mock = mock_open()

        # test
        with patch('builtins.open', open_mock):
            _Storage._list.clear()
            new = ('storage/SceneMark_SMK_00000009-60fe-5e15-8002-000000001954_0001_e84c0d07_seq_1.json', 2520)
            _Storage._list.append(new)
            _Storage._store_text(self.__STORE_PATH, self.__STORE_TEXT)

        # check
        mkdir_mock.assert_called_once_with(exist_ok=True)
        unlink_mock.assert_called_once()
        open_mock().write.assert_called_once_with(self.__STORE_TEXT)

    def test___store_text_03(self, mocker, setup_init):
        """
        Store the text.
        Storage __ready is True.
        """
        # mock set
        mkdir_mock = mocker.patch('pathlib.Path.mkdir')
        unlink_mock = mocker.patch('pathlib.Path.unlink')
        open_mock = mock_open()

        # test
        with patch('builtins.open', open_mock):
            _Storage.set_size(self.__STORAGE_SIZE)
            _Storage._ready = True
            _Storage._store_text(self.__STORE_PATH, self.__STORE_TEXT)

        # check
        mkdir_mock.assert_not_called()
        unlink_mock.assert_not_called()
        open_mock().write.assert_called_once_with(self.__STORE_TEXT)

    def test_store_scene_mark_01(self, mocker, setup_init):
        """
        If an Exception occurs in store_text,
        do not Store.
        """
        # mock set
        mocker.patch('src.niceapi.util._storage._Storage._store_text', side_effect=Exception)

        # test
        _Storage.store_scene_mark(self.__SCENE_MARK)

        # check
        assert len(_Storage._list) == 0

    def test_store_scene_mark_02(self, mocker, setup_init):
        """
        Store the scene mark.
        """
        # mock set
        store_text_mock = mocker.patch('src.niceapi.util._storage._Storage._store_text')

        # test
        _Storage.store_scene_mark(self.__SCENE_MARK)

        # check
        filename = 'SceneMark_aaa_seq_1.json'
        path = os.path.join("storage", filename)
        store_text_mock.assert_called_once_with(path, json.dumps(self.__SCENE_MARK))

    def test_store_scene_data_01(self, mocker, setup_init):
        """
        If an Exception occurs in store_text,
        do not Store.
        """
        # mock set
        mocker.patch('src.niceapi.util._storage._Storage._store_text', side_effect=Exception)

        # test
        _Storage.store_scene_data(self.__SCENE_DATA)

        # check
        assert len(_Storage._list) == 0

    def test_store_scene_data_02(self, mocker, setup_init):
        """
        Store the scene data.
        file type is image.
        """
        # mock set
        store_text_mock = mocker.patch('src.niceapi.util._storage._Storage._store_text')

        # test
        _Storage.store_scene_data(self.__SCENE_DATA)

        # check
        filename = 'Image_aaa_seq_1.json'
        path = os.path.join("storage", filename)
        store_text_mock.assert_called_once_with(path, json.dumps(self.__SCENE_DATA))

    def test_store_scene_data_03(self, mocker, setup_init):
        """
        Store the scene data.
        file type is video.
        """
        # mock set
        store_text_mock = mocker.patch('src.niceapi.util._storage._Storage._store_text')

        # test
        _Storage.store_scene_data(self.__SCENE_DATA_VIDEO)

        # check
        filename = 'Video_aaa_seq_1_Chunk_1_NumberOfChunk_1.json'
        path = os.path.join("storage", filename)
        store_text_mock.assert_called_once_with(path, json.dumps(self.__SCENE_DATA_VIDEO))
