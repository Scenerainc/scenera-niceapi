"""Test for tools."""
from distutils.log import ERROR
from src.niceapi.util._tools import _logger_setup, _datetime_utcnow, _datetime_decode, _base64url_decode, _file_update, _json_load, _is_list
from logging import getLogger, DEBUG, INFO, ERROR
import json
import os
import pytest
from unittest import mock
from datetime import datetime


class TestTools:
    """tools test class."""

    __LOG_FILE_NAME = 'test.log'

    @pytest.fixture()
    def setup_teardown(self):
        f = open(self.__LOG_FILE_NAME, 'w')
        f.close()
        yield
        os.remove(self.__LOG_FILE_NAME)

    def test_logger_01(self, caplog):
        """
        Log output to console.
        """
        logger = getLogger(__name__)
        _logger_setup(logger, DEBUG)

        # test
        logger.debug('debug')
        logger.info('info')
        logger.error('error')
        log_str = caplog.record_tuples

        # check
        assert ('tests.niceapi.util.test_tools', DEBUG, 'debug') in log_str
        assert ('tests.niceapi.util.test_tools', INFO, 'info') in log_str
        assert ('tests.niceapi.util.test_tools', ERROR, 'error') in log_str

    def test_logger_02(self, caplog, setup_teardown):
        """
        Log output to file.
        """
        # setup logger
        logger = getLogger(__name__)
        _logger_setup(logger, DEBUG, output=self.__LOG_FILE_NAME)

        # test
        logger.debug('debug')
        logger.info('info')
        logger.error('error')
        log_str = caplog.record_tuples

        # check
        assert ('tests.niceapi.util.test_tools', DEBUG, 'debug') in log_str
        assert ('tests.niceapi.util.test_tools', INFO, 'info') in log_str
        assert ('tests.niceapi.util.test_tools', ERROR, 'error') in log_str

    @mock.patch('src.niceapi.util._tools.datetime')
    def test_datetime_utcnow_01(self, m):
        """
        Get current UTC datetime.
        """
        # mock set
        m.utcnow.return_value = datetime(2022, 2, 22, 7, 00, 00, 423315)

        # test
        date_time = _datetime_utcnow()
        
        # check
        assert date_time == '2022-02-22T07:00:00.423Z'

    def test_datetime_decode_01(self):
        """
        Decode datetime.
        """
        # test
        date_time = _datetime_decode('2022-02-22T07:00:00.423Z')

        # expect
        expect_date_time = datetime(2022, 2, 22, 7, 00, 00, 423000)
        
        # check
        assert date_time == expect_date_time

    def test_base64url_decode_01(self):
        """
        Decode base64url.
        """
        # test
        decode_url = _base64url_decode('aHR0cHM6Ly9naXRodWIuY29t')
        
        # check
        assert decode_url == b'https://github.com'

    def test_file_update_01(self):
        """
        Not file
        """
        # test
        ret = _file_update("/tmp/", "abc")

        # check
        assert ret == False

    def test_file_update_02(self):
        """
        Not string
        """
        # test
        ret = _file_update(1, "abc")

        # check
        assert ret == False

    def test_json_load_01(self):
        """
        Load JSON
        """
        TEST_JSON = {"ABC": "DEF"}

        # mock set
        open_mock = mock.mock_open(read_data=json.dumps(TEST_JSON))

        # test
        with mock.patch('builtins.open', open_mock):
            obj = _json_load("test")

        # check
        assert obj == TEST_JSON

    def test_json_load_02(self):
        """
        Load non-existent file
        """
        # test
        obj = _json_load("test")

        # check
        assert obj == None

    def test_is_list_01(self):
        """
        Check no-key
        """
        # test
        test = {"a": "b"}
        result = _is_list(test, "test")

        # check
        assert result == False

    def test_is_list_02(self):
        """
        Check non-list
        """
        # test
        test = {"test": 1}
        result = _is_list(test, "test")

        # check
        assert result == False
