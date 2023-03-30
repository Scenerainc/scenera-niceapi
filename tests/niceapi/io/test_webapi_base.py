from src.niceapi.io.webapi_base import WebAPIBase
import pytest

class TestWebAPIBase:
    """_WebAPIBase test class."""

    RESP = {"Response": "OK"}

    @pytest.fixture()
    def webapi(self):
        class WebAPITest(WebAPIBase):
            def post(self, url, headers, body, timeout=5, token=None, verify=True):
                super().post(url, headers, body)
                return TestWebAPIBase.RESP

            def update_root_cert(self, tls_root_certs=None):
                super().update_root_cert()
                return None

        return WebAPITest()

    def test_post_json(self, webapi):
        """
        call post_json
        """
        assert webapi.post(url="localhost", headers="", body="{}") == TestWebAPIBase.RESP

    def test_update_root_cert(self, webapi):
        """
        call update_root_cert
        """
        assert webapi.update_root_cert() == None
