"""Test for _WebAPI."""
from unittest.mock import patch, mock_open, MagicMock
import requests
from src.niceapi.io._webapi import _WebAPI, _get_webapi_default
import base64
import json
import os
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# dummy data
DUMMY_SERVER = 'SimpleHTTP/0.6 Python/3.10.2'
DUMMY_DATE = 'Mon, 31 Jan 2022 08:15:17 GMT'
DUMMY_LOCATION = 'https://dummy.com'
DUMMY_CERTS = [
    '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'
]

class TestWebAPI:
    """_WebAPI test class."""

    __URL = 'http://github.com'
    __BODY = {'EncryptedPayload':'eyJraWQiOiIwMDAwMDAwOS02M'}
    __HEADERS = {'Content-type': 'application/json'}
    __TIMEOUT = 60

    # fixture
    def create_tls_root_certs(self, certs=DUMMY_CERTS):
        root_certs = []
        for val in certs:
            crt = x509.load_der_x509_certificate(base64.b64decode(val), default_backend())
            root_certs.append(crt.public_bytes(encoding=serialization.Encoding.PEM))
        return root_certs

    def create_response(self, code=200, server=DUMMY_SERVER, date=DUMMY_DATE,
                        location=False, url=DUMMY_LOCATION):
        response = requests.Response()
        response.headers = {}
        response.headers['Server'] = server
        response.headers['Date'] = date
        if location:
            response.headers['Location'] = url
        response.status_code = code
        return response

    def create_response_dict(self, code=200, server=DUMMY_SERVER, date=DUMMY_DATE):
        dict = {
            'status_code':code,
            'headers': {
                'Server':server, 
                'Date':date,
            }
        }
        return dict

    @pytest.fixture()
    def tls_root_certs(self):
        return self.create_tls_root_certs()

    @pytest.fixture()
    def write_data(self):
        root_certs = self.create_tls_root_certs()
        data = b''
        for cert in root_certs:
            data = data + cert
        return data

    @pytest.fixture()
    def resp_ok(self):
        return self.create_response()

    @pytest.fixture()
    def dict_resp_ok(self):
        return self.create_response_dict()

    def test_get_webapi_default(self, mocker):
        """
        ImportError occured
        """
        from src.niceapi.io._webapi_default import _WebAPIDefault
        mocker.patch.object(_WebAPIDefault, '__init__').side_effect = ImportError()
        webapi = _get_webapi_default()
        assert webapi.post(self.__URL, self.__HEADERS, self.__BODY) == None
        assert webapi.update_root_cert() == None

    def test_set_webapi(self):
        """
        set dummy webapi
        """
        from src.niceapi.io.webapi_base import WebAPIBase
        from src.niceapi.io._webapi_default import _WebAPIDefault
        RESP = {"Response": "OK"}
        class Dummy(WebAPIBase):
            def post(self, url, headers, body, timeout=1, token=None, verify=True):
                return RESP
            def update_root_cert(self, tls_root_certs=None):
                pass
        _WebAPI.set_webapi(Dummy())
        assert _WebAPI.post_json(self.__URL, self.__BODY) == RESP
        # recover WebAPI
        _WebAPI.set_webapi(_WebAPIDefault())

    def test_set_max_connection(self):
        """
        set maximum number of connection to unlimited
        """
        LIMIT = 0
        from src.niceapi.io._webapi import _WebAPI
        _WebAPI.set_max_connection(LIMIT)
        assert _WebAPI._semaphore == None

    def test_post_json_01(self, mocker, resp_ok, dict_resp_ok):
        """
        call wrapper_method post_json
        """
        # mock set
        mocker.patch.object(requests.Session, 'request').return_value = resp_ok
        mocker.patch.object(requests.Response, 'json').return_value = dict_resp_ok

        # test
        res_json = _WebAPI.post_json(self.__URL, self.__BODY, verify=False)

        # check
        assert res_json

    def test_post_text_01(self, mocker, resp_ok, dict_resp_ok):
        """
        call wrapper_method post_text
        """
        # mock set
        mocker.patch.object(requests.Session, 'request').return_value = resp_ok
        mocker.patch.object(requests.Response, 'json').return_value = dict_resp_ok

        # test
        res_json = _WebAPI.post_text(self.__URL, json.dumps(self.__BODY), verify=False)

        # check
        assert res_json

    def test_post_text_02(self, mocker, resp_ok, dict_resp_ok):
        """
        call wrapper_method post_text
        """
        # mock set
        mocker.patch.object(requests.Session, 'request').return_value = resp_ok
        mocker.patch.object(requests.Response, 'json').return_value = dict_resp_ok

        _WebAPI.set_max_connection(5)

        # test
        res_json = _WebAPI.post_text(self.__URL, json.dumps(self.__BODY), token="BEARER", verify=False)

        _WebAPI.set_max_connection(0)

        # check
        assert res_json

    def test_update_root_cert_01(self):
        """
        Parameter is None.
        Do not create a certificate.
        """
        # mock set
        temp_mock = mock_open(MagicMock())

        # test
        with patch('tempfile.NamedTemporaryFile', temp_mock):
            _WebAPI.update_root_cert(None)

        # check
        temp_mock().write.assert_not_called()

    def test_update_root_cert_02(self, mocker, tls_root_certs, write_data):
        """
        Normal test.
        Create a certificate.
        """
        # mock set
        temp_mock = mock_open(MagicMock())
        chmod_mock = mocker.patch('os.chmod')
        replace_mock = mocker.patch('os.replace')

        # test
        with patch('tempfile.NamedTemporaryFile', temp_mock):
            f = temp_mock.return_value
            f.name = "tmp"
            _WebAPI.update_root_cert(tls_root_certs)

        # check
        temp_mock().write.assert_called_once_with(write_data)
        chmod_mock.assert_called_once_with(os.path.join('.', 'tmp'), 0o644)
        replace_mock.assert_called_once_with(os.path.join('.', 'tmp'), 'tls-root-cert.pem')

    def test_update_root_cert_03(self):
        """
        Parameter is a list of empty certificate.
        Do not create a certificate.
        """
        # mock set
        open_mock = mock_open()

        # test
        with patch('builtins.open', open_mock):
            _WebAPI.update_root_cert([b""])

        # check
        open_mock().write.assert_not_called()
