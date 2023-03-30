"""Test for _WebAPIDefault."""
from unittest.mock import patch, mock_open, MagicMock
import requests
from src.niceapi.io._webapi_default import _WebAPIDefault
import base64
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

class TestWebAPIDefault:
    """_WebAPIDefault test class."""

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
    def webapi(self):
        return _WebAPIDefault()

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
    def resp_redirect(self):
        return self.create_response(code=308, location=True)

    @pytest.fixture()
    def resp_rd_no_location(self):
        return self.create_response(code=301)

    @pytest.fixture()
    def resp_rd_no_url(self):
        return self.create_response(code=307, location=True, url='')

    @pytest.fixture()
    def resp_not_found(self):
        return self.create_response(code=404)

    @pytest.fixture()
    def dict_resp_ok(self):
        return self.create_response_dict()


    def test_update_root_cert_01(self, webapi):
        """
        Parameter is None.
        Do not create a certificate.
        """
        # mock set
        temp_mock = mock_open(MagicMock())

        # test
        with patch('tempfile.NamedTemporaryFile', temp_mock):
            webapi.update_root_cert(None)

        # check
        temp_mock().write.assert_not_called()

    def test_update_root_cert_02(self, mocker, webapi, tls_root_certs, write_data):
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
            webapi.update_root_cert(tls_root_certs)

        # check
        temp_mock().write.assert_called_once_with(write_data)
        chmod_mock.assert_called_once_with(os.path.join('.', 'tmp'), 0o644)
        replace_mock.assert_called_once_with(os.path.join('.', 'tmp'), 'tls-root-cert.pem')

    def test_update_root_cert_03(self, webapi):
        """
        Parameter is a list of empty certificate.
        Do not create a certificate.
        """
        # mock set
        open_mock = mock_open()

        # test
        with patch('builtins.open', open_mock):
            webapi.update_root_cert([b""])

        # check
        open_mock().write.assert_not_called()

    def test_post_redirect_01(self, mocker, webapi, resp_ok, resp_rd_no_location):
        """
        Do not redirect if Location does not exist.
        """
        # mock set
        request_mock = mocker.patch.object(requests.Session, 'request')
        request_mock.return_value=resp_ok

        # test
        webapi._post_redirect(requests.Session(), self.__URL, False, self.__BODY, self.__HEADERS, self.__TIMEOUT, resp_rd_no_location)

        # check
        request_mock.assert_not_called()

    def test_post_redirect_02(self, mocker, webapi, resp_ok, resp_rd_no_url):
        """
        Do not redirect if the URL is not set.
        """
        # mock set
        request_mock = mocker.patch.object(requests.Session, 'request')
        request_mock.return_value=resp_ok

        # test
        webapi._post_redirect(requests.Session(), self.__URL, False, self.__BODY, self.__HEADERS, self.__TIMEOUT, resp_rd_no_url)

        # check
        request_mock.assert_not_called()

    def test_post_redirect_03(self, mocker, webapi, resp_ok, resp_redirect):
        """
        If the redirect response is other than 301/307/308,
        redirect only once.
        """
        # mock set
        request_mock = mocker.patch.object(requests.Session, 'request')
        request_mock.return_value=resp_ok
 
        # test
        webapi._post_redirect(requests.Session(), self.__URL, False, self.__BODY, self.__HEADERS, self.__TIMEOUT, resp_redirect)

        # check
        assert request_mock.call_count == 1

    def test_post_redirect_04(self, mocker, webapi, resp_redirect):
        """
        If the redirect response is 301/307/308,
        redirect 5 times.
        """
        # mock set
        request_mock = mocker.patch.object(requests.Session, 'request')
        request_mock.return_value=resp_redirect

        # test
        webapi._post_redirect(requests.Session(), self.__URL, False, self.__BODY, self.__HEADERS, self.__TIMEOUT, resp_redirect)
        
        # check
        assert request_mock.call_count == 5

    def test_post_json_01(self, mocker, webapi):
        """
        If an exception occurs in POST,
        empty data returned.
        """
        # mock set
        mocker.patch.object(requests.Session, 'request').side_effect=Exception
        
        # test
        res_json = webapi.post(self.__URL, self.__HEADERS, self.__BODY, verify=False)
        
        # check
        assert not res_json

    def test_post_json_02(self, mocker, webapi, resp_not_found):
        """
        If the POST response is an error,
        empty data returned. 
        """
        # mock set
        mocker.patch.object(requests.Session, 'request').return_value=resp_not_found
        
        # test
        res_json = webapi.post(self.__URL, self.__HEADERS, self.__BODY, verify=False)
        
        # check
        assert not res_json

    def test_post_json_03(self, mocker, webapi, resp_redirect, resp_not_found):
        """
        If the redirect response is an error,
        empty data returned.
        """
        # mock set
        mocker.patch.object(requests.Session, 'request').return_value=resp_redirect
        mocker.patch.object(_WebAPIDefault, '_post_redirect').return_value = resp_not_found
        
        # test
        res_json = webapi.post(self.__URL, self.__HEADERS, self.__BODY, verify=False)
        
        # check
        assert not res_json

    def test_post_json_04(self, mocker, webapi, resp_redirect, resp_ok):
        """
        If ValueError occurs after redirect,
        empty data returned.
        """
        # mock set
        mocker.patch.object(requests.Session, 'request').return_value = resp_redirect
        mocker.patch.object(_WebAPIDefault, '_post_redirect').return_value = resp_ok
        mocker.patch.object(requests.Response, 'json').side_effect = ValueError
        
        # test
        res_json = webapi.post(self.__URL, self.__HEADERS, self.__BODY, verify=False)
        
        # check
        assert not res_json

    def test_post_json_05(self, mocker, webapi, resp_redirect, resp_ok, dict_resp_ok):
        """
        If the redirect is successful,
        json returned.
        """
        # mock set
        mocker.patch.object(requests.Session, 'request').return_value = resp_redirect
        mocker.patch.object(_WebAPIDefault, '_post_redirect').return_value = resp_ok
        mocker.patch.object(requests.Response, 'json').return_value = dict_resp_ok
      
        # test
        res_json = webapi.post(self.__URL, self.__HEADERS, self.__BODY, verify=False)
        
        # check
        assert res_json

    def test_post_json_06(self, mocker, webapi, resp_ok):
        """
        If ValueError occurs after successful POST,
        empty data returned.
        """
        # mock set
        mocker.patch.object(requests.Session, 'request').return_value = resp_ok
        mocker.patch.object(requests.Response, 'json').side_effect = ValueError
        
        # test
        res_json = webapi.post(self.__URL, self.__HEADERS, self.__HEADERS, self.__BODY, verify=False)
        
        # check
        assert not res_json

    def test_post_json_07(self, mocker, webapi, resp_ok, dict_resp_ok):
        """
        If the POST response is successful,
        json returned.
        """
        # mock set
        mocker.patch.object(requests.Session, 'request').return_value = resp_ok
        mocker.patch.object(requests.Response, 'json').return_value = dict_resp_ok
        
        # test
        res_json = webapi.post(self.__URL, self.__HEADERS, self.__BODY, verify=False)
        
        # check
        assert res_json

    def test_post_json_08(self, mocker, webapi, resp_ok, dict_resp_ok):
        """
        If the POST response is successful (verify=True, token=<string>),
        json returned.
        """
        # mock set
        mocker.patch.object(requests.Session, 'request').return_value = resp_ok
        mocker.patch.object(requests.Response, 'json').return_value = dict_resp_ok
        
        # test
        res_json = webapi.post(self.__URL, self.__HEADERS, self.__BODY, token='eyJ0eXAiOiJKV1QiLCJhbGciOiJ', verify=True)
        
        # check
        assert res_json

    def test_post_json_09(self, mocker, webapi):
        """
        If an exception occurs in POST,
        empty data returned.
        """
        # mock set
        mocker.patch.object(requests.Session, 'request').side_effect=requests.exceptions.RequestException

        # test
        res_json = webapi.post(self.__URL, self.__HEADERS, self.__BODY, verify=False)

        # check
        assert not res_json
