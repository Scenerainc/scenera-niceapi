"""Test for Jose."""

import base64
from datetime import datetime, timedelta
import json
from typing import Any, List, Tuple, Union

from authlib.jose import JsonWebSignature, RSAKey
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import NameOID

from src.niceapi.crypto.jose import Decrypt, Encrypt, JoseOps, Sign, Verify, _jwe_encrypt, _jwe_decrypt,_verifying

import pytest
from pytest_mock.plugin import MockerFixture


PRIVATE_KEY_TYPES_T = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]

def gen_private_key(is_ec: bool=False) -> PRIVATE_KEY_TYPES_T:
    f,a = (ec.generate_private_key, [ec.SECP256R1()]) if is_ec else [rsa.generate_private_key,[65537, 3072]]
    return f(*a, default_backend()) # type: ignore


def set_x509name_attr() -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"JP"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tokyo"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"EXAMPLE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"My CA"),
    ])

def rep(certificate: bytes) ->bytes:
    BGN = (b'-----BEGIN CERTIFICATE-----', b'')
    END = (b'-----END CERTIFICATE-----', b'')
    return certificate.replace(*BGN).replace(*END).replace(b'\n', b'')

CHAINING_CERTS_T = List[Tuple[PRIVATE_KEY_TYPES_T, x509.Certificate]]
def gen_chaining_certs(is_ec: bool, is_invalid_date: bool) -> CHAINING_CERTS_T:
    private_key = gen_private_key(is_ec)
    subject = issuer = set_x509name_attr()
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                private_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                private_key.public_key()
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    def _gen_cert(is_ec: bool, is_invalid: bool, k: PRIVATE_KEY_TYPES_T, c: x509.Certificate, d: int):
        before_delta = timedelta(days=1 if is_invalid else 0)
        new_key = gen_private_key(is_ec)
        new_cert = (
            x509.CertificateBuilder()
            .subject_name(set_x509name_attr())
            .issuer_name(c.issuer)
            .public_key(new_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() + before_delta)
            .not_valid_after(datetime.utcnow() + timedelta(days=d))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("somedomain1.com")]),
                critical=False,
            )
            .sign(k, hashes.SHA256(), default_backend())
        )
        return (new_key, new_cert)

    inter = _gen_cert(is_ec, is_invalid_date, private_key, root_cert, 365)
    cert = _gen_cert(is_ec, False, *inter, 30)

    return [(private_key, root_cert), inter, cert]

GEN_TEST_CERTS_T = List[Tuple[PRIVATE_KEY_TYPES_T, bytes]]
def generate_test_certs(is_ec: bool=False, is_invalid_date: bool=False) -> GEN_TEST_CERTS_T:
    return [(k, c.public_bytes(encoding=serialization.Encoding.PEM)) for k, c in gen_chaining_certs(is_ec, is_invalid_date)]

###

class TestVerify:
    """Verify test class."""

    __DUMMY_VERIFY_JWS = 'eyJhbGciOiJSUzUxMiIsImtpZCI6IjAwMDAwMDAwLTBhYWEtMDAwYS0wMDAwLTAwMDAwMDAwMDAwMCIsIng1YyI6WyJNSUlEbHpDQ0FuOENGQ0w2SjJuTUhFazhiZ3ljVFlBaTdKQndvaHA5TUEwR0NTcUdTSWIzRFFFQkN3VUFNSUdITVFzd0NRWURWUVFHRXdKS1VERU9NQXdHQTFVRUNBd0ZUM05oYTJFeERqQU1CZ05WQkFjTUJVOXpZV3RoTVF3d0NnWURWUVFLREFOemMzTXhEREFLQmdOVkJBc01BM056Y3pFWU1CWUdBMVVFQXd3UGQzZDNMbVY0WVcxd2JHVXVZMjl0TVNJd0lBWUpLb1pJaHZjTkFRa0JGaE56YjIxbGIyNWxRR1Y0WVcxd2JHVXVZMjl0TUI0WERUSXlNRE15TWpBeE16WXdOVm9YRFRNeU1ETXhPVEF4TXpZd05Wb3dnWWN4Q3pBSkJnTlZCQVlUQWtwUU1RNHdEQVlEVlFRSURBVlBjMkZyWVRFT01Bd0dBMVVFQnd3RlQzTmhhMkV4RERBS0JnTlZCQW9NQTNOemN6RU1NQW9HQTFVRUN3d0RjM056TVJnd0ZnWURWUVFEREE5M2QzY3VaWGhoYlhCc1pTNWpiMjB4SWpBZ0Jna3Foa2lHOXcwQkNRRVdFM052YldWdmJtVkFaWGhoYlhCc1pTNWpiMjB3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRE1ic2Q2N1FqVGFhbmFCNzR3Y2ZPbHZhZmNzRFQ3K2FCVHlSSTM2bHVLaEJZVWYwek53SlhSZWVSR3JtNHVKVkw4THA4K2lhM2xhMHJXZ3pkdWsvdk81anpPa2NqRjd1ck9wZXpWd3dLRW5wdXhLUXIxekhGV3poK1c3WE44Wmw2WTRQUTFFcktqZU5nK3NXRUtlcGVka05zb0RSTHBidTNrWG9iUklNNWJ2eEdzTXdQbEJZRjFnbEtQWGZTM0tXVUJTVWNYMzJTMFdZbFNZKzgxbjRydTJNY1ZWSjFXOHRhMktCUjJIeEZ6R252MWphbUY5N0djRzJYUzEzcTNmNUJUM2lRUWkyVVV3ZDdzaTFkYjNuaDg5eGtVTnN5aXVwUTFmNFRKT0Q5c0lpL3IxVWZzWWRramNaVGlGWjJ0dURzeERWMkNWZ2JLZk96ZEFVR1NBc1I5QWdNQkFBRXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBSWp5UHF6V2syT285UklwV2NqSmJTZzRVSHNKR282ak45L2JYdE00V3UvbmdBMGNpQTBTeFZSZEFmVWpwL0lxbW1PZFFyVEpiMy84Q09od1lFUWg2N0VIRnlWcHhydVhqYnVaN09KVkxxN3AwVmsyQkVVT1FKZndsejZGSmM3WUNuSW04SWpxdmdPdHV3ZjFQNnpKN1E4OUZwbFpnOTg1R3VBdEpwRUdTM0xtY1FyZUhzL0s1aDFGQUw0SlZHODh0ZmEvYmQwNnRnbGRibngrZUVTc0ltc2o1V2g4ZWVuZjBZMHRmNTBFMllyNHF1S2VnNklxL1hkZVdjTkRyd2ZwM09IR0Nmc0U3NEM1Q1ZWSjBjSTEyM2UwVllON2Ruc3N4WFhKNUcrTU5KaWE5ekhleDMvUTFPem8vRXJ3Z2dXWmxqVzJmYjQ0aXpIb3h0dWk1VW9CV1hRPSJdfQ==.eyJWZXJzaW9uIjoiMS4wIiwiTWVzc2FnZVR5cGUiOiJyZXNwb25zZSIsIlNvdXJjZUVuZFBvaW50SUQiOiIwMDAwMDAwMC0wMGFhLTBhMDAtMDAwMC0wMDAwMDAwMDAwMDAiLCJEZXN0aW5hdGlvbkVuZFBvaW50SUQiOiIwMDAwMDAwMC0wYWFhLTAwMGEtMDAwMC0wMDAwMDAwMDAwMDAiLCJEYXRlVGltZVN0YW1wIjoiMjAyMi0wMi0xNVQwOToxNzo0MC41MThaIiwiUmVwbHlJRCI6MCwiUGF5bG9hZCI6ImFHVnNiRzhzSUhkdmNteGtJUSIsIlJlcGx5U3RhdHVzTWVzc2FnZSI6Ik9LIiwiUmVwbHlTdGF0dXNDb2RlIjoyMDB9.aaaaa'

    __DUMMY_VERIFY_RESP = b'{"Version":"1.0","MessageType":"response","SourceEndPointID":"00000000-00aa-0a00-0000-000000000000","DestinationEndPointID":"00000000-0aaa-000a-0000-000000000000","DateTimeStamp":"2022-02-15T09:17:40.518Z","ReplyID":0,"Payload":"aaa","ReplyStatusMessage":"OK","ReplyStatusCode":200}'

    __DUMMY_JWS_TOKEN = {"payload": __DUMMY_VERIFY_RESP}


    __jws_verify = Verify(False, None)

    def test_verify_01(self, mocker: MockerFixture):
        """
        If an ValueError occurs in rsplit,
        empty response returned.
        """
        # mock set
        deserialize_compact_mock = mocker.patch('authlib.jose.JsonWebSignature.deserialize_compact', side_effect=Exception)

        # test
        success, response = self.__jws_verify('10')

        # check
        assert success is False
        assert response is None
        deserialize_compact_mock.assert_not_called()
        
    def test_verify_02(self, mocker: MockerFixture):
        """
        If an Exception occurs in verify,
        empty response returned.
        """
        # mock set
        deserialize_compact_mock = mocker.patch('authlib.jose.JsonWebSignature.deserialize_compact', side_effect=Exception)

        # test
        success, response = self.__jws_verify(None)

        # check
        assert success is False
        assert response is None
        deserialize_compact_mock.assert_not_called()

    def test_verify_03(self, mocker: MockerFixture):
        """
        If an Exception occurs in deserialize_compact,
        empty response returned.
        """
        # mock set
        deserialize_compact_mock = mocker.patch('authlib.jose.JsonWebSignature.deserialize_compact', side_effect=Exception)
        
        # test
        success, response = self.__jws_verify(self.__DUMMY_VERIFY_JWS)

        # check
        assert success is False
        assert response is None
        deserialize_compact_mock.assert_called_once()

    def test_verify_04(self, mocker: MockerFixture):
        """
        Normal test.
        """
        # mock set
        mocker.patch('authlib.jose.JsonWebSignature.deserialize_compact', return_value=self.__DUMMY_JWS_TOKEN)

        # test
        success, response = self.__jws_verify(self.__DUMMY_VERIFY_JWS)

        # check
        assert success is True
        assert response == self.__DUMMY_VERIFY_RESP

    def test_verify_05(self, mocker: MockerFixture):
        """
        within verify test.
        """
        __DUMMY_CRT = 'MIIDvDCCAiSgAwIBAgIGAXKCg+HeMA0GCSqGSIb3DQEBDQUAMCAxHjAcBgNVBAMMFU1hc3RlcktleS5zY2VuZXJhLmNvbTAgFw0yMDA2MDUwMzI2MjBaGA8yMTIwMTIzMTA4MDAwMFowHDEaMBgGA1UEAxMRTEFSb290LnNjZW5lcy5jb20wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCuOSjirBX+pKkdiCHO2zsdTHOW4nTewQdgYfG+npRJ2/79ooiS8PkXFEY98eCUD9YyQuhxKIbGBbD2+YZGPv1TCdShRu0J+LuwVq3e/0r64c67HdUt7LMSjtSCVPF82RW083C8rUDXSBWondXiAHYjriOsl12X5FOK17aYNlvHh9Hzx6XCT5lUNpEu+fcAH9G1+j1XI/gLcsGML3iJ2N0wsPR1ryaSVM5JvsXE57aa77Qk6uN7P3RbJmg0hevZp9sboLkJgBim8CEvJsqkE1hhuDbNaAzGa49tmAoFo2j7JysRbJtC5XhEmBE13yl6zcXynpV569W+13VVMKmxS/1EsdrwSIAZN9AwMRvSqXPCn1ZPD3XPrbhvBk62nxMkIfe0bh5G/S4uQUejqqCoFTpcXSVIlxubEmO3Ph0ocpp172Ky7kI3Y93v/XjrcdLRQYQ3tXA1O/+x9F6GAj4cgN4BrljrIazRWScd6beFv412Gu3CsKVFClmy90ARiCyj3TUCAwEAATANBgkqhkiG9w0BAQ0FAAOCAYEAdoJAyuaLb+wOIhP/FQjuEPkPi9qYvLC0d0LBYTT9gPRpKIYONP6iGNvrYYzrZCjNWEztLmnbkDykK9HZsoUt3OZu3P+0k5wUK0IMXK6WGPmYKkEmOXDAGvW6T4wOxjLEWybZS+0CcEm3WDPX3al3+r3qV1FkYczD6s8PItLcIkl7PKzGMd+GUt3nbGSQoGnCanC+otKbR1dM/LtcGr9+pIxH9aIxScLIdKQrk3LvmHiKpAHlw1uaGQjWzQE2qtwZfRIOx6nAkTUC7Jw8RDFjSiQBfyZDH4YvF0VJxHBXvDoxXZIUz1eKZfaNzGsnAd7J2BcnrzgDnNgvxyGjf4VlYxGpzE+ycvRJcg5lNkjpxflbeIoTOa+WcwYLsh2BZLLTVw7HB3wHAaIu60JMSSXr2pp9PaK/Qw8T+tEnBatxl2u37V4gWUHfgtG38Ee5Dzo/cs9fdIDyzXbrzRGPHmwLaOYztYUKQ0+0+PWAGFE4P6XqezWWP95sigB17+LAEk8w'
        jws_verify = Verify(True, [__DUMMY_CRT])

        # mock set
        def create_dummy_dsa_cert(_1: Any, _2: Any) -> Any:
            one_day = timedelta(1, 0, 0)
            private_key = dsa.generate_private_key(
                key_size=2048
            )
            public_key = private_key.public_key()
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
            ]))
            builder = builder.issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
            ]))
            builder = builder.not_valid_before(datetime.today() - one_day)
            builder = builder.not_valid_after(datetime.today() + (one_day * 30))
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.public_key(public_key)
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(u'cryptography.io')]
                ),
                critical=False
            )
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            )
            certificate = builder.sign(
                private_key=private_key, algorithm=hashes.SHA256(),
            )
            return certificate

        mocker.patch('cryptography.x509.load_der_x509_certificate', side_effect=create_dummy_dsa_cert)
        mocker.patch('authlib.jose.JsonWebSignature.deserialize_compact', return_value=self.__DUMMY_JWS_TOKEN)

        # test
        success, response = jws_verify(self.__DUMMY_VERIFY_JWS)

        # check
        assert success is True
        assert response == self.__DUMMY_VERIFY_RESP

    def test_verify_06(self, mocker: MockerFixture):
        """
        within verify test.
        """
        __DUMMY_CRT = 'MIIDvDCCAiSgAwIBAgIGAXKCg+HeMA0GCSqGSIb3DQEBDQUAMCAxHjAcBgNVBAMMFU1hc3RlcktleS5zY2VuZXJhLmNvbTAgFw0yMDA2MDUwMzI2MjBaGA8yMTIwMTIzMTA4MDAwMFowHDEaMBgGA1UEAxMRTEFSb290LnNjZW5lcy5jb20wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCuOSjirBX+pKkdiCHO2zsdTHOW4nTewQdgYfG+npRJ2/79ooiS8PkXFEY98eCUD9YyQuhxKIbGBbD2+YZGPv1TCdShRu0J+LuwVq3e/0r64c67HdUt7LMSjtSCVPF82RW083C8rUDXSBWondXiAHYjriOsl12X5FOK17aYNlvHh9Hzx6XCT5lUNpEu+fcAH9G1+j1XI/gLcsGML3iJ2N0wsPR1ryaSVM5JvsXE57aa77Qk6uN7P3RbJmg0hevZp9sboLkJgBim8CEvJsqkE1hhuDbNaAzGa49tmAoFo2j7JysRbJtC5XhEmBE13yl6zcXynpV569W+13VVMKmxS/1EsdrwSIAZN9AwMRvSqXPCn1ZPD3XPrbhvBk62nxMkIfe0bh5G/S4uQUejqqCoFTpcXSVIlxubEmO3Ph0ocpp172Ky7kI3Y93v/XjrcdLRQYQ3tXA1O/+x9F6GAj4cgN4BrljrIazRWScd6beFv412Gu3CsKVFClmy90ARiCyj3TUCAwEAATANBgkqhkiG9w0BAQ0FAAOCAYEAdoJAyuaLb+wOIhP/FQjuEPkPi9qYvLC0d0LBYTT9gPRpKIYONP6iGNvrYYzrZCjNWEztLmnbkDykK9HZsoUt3OZu3P+0k5wUK0IMXK6WGPmYKkEmOXDAGvW6T4wOxjLEWybZS+0CcEm3WDPX3al3+r3qV1FkYczD6s8PItLcIkl7PKzGMd+GUt3nbGSQoGnCanC+otKbR1dM/LtcGr9+pIxH9aIxScLIdKQrk3LvmHiKpAHlw1uaGQjWzQE2qtwZfRIOx6nAkTUC7Jw8RDFjSiQBfyZDH4YvF0VJxHBXvDoxXZIUz1eKZfaNzGsnAd7J2BcnrzgDnNgvxyGjf4VlYxGpzE+ycvRJcg5lNkjpxflbeIoTOa+WcwYLsh2BZLLTVw7HB3wHAaIu60JMSSXr2pp9PaK/Qw8T+tEnBatxl2u37V4gWUHfgtG38Ee5Dzo/cs9fdIDyzXbrzRGPHmwLaOYztYUKQ0+0+PWAGFE4P6XqezWWP95sigB17+LAEk8w'
        __DUMMY_CRT = [__DUMMY_CRT]
        jws_verify = Verify(False, __DUMMY_CRT)

        # mock set
        def create_dummy_dsa_cert(_1: Any, _2: Any) -> Any:
            one_day = timedelta(1, 0, 0)
            private_key = dsa.generate_private_key(
                key_size=2048
            )
            public_key = private_key.public_key()
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
            ]))
            builder = builder.issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
            ]))
            builder = builder.not_valid_before(datetime.today() - one_day)
            builder = builder.not_valid_after(datetime.today() + (one_day * 30))
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.public_key(public_key)
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(u'cryptography.io')]
                ),
                critical=False
            )
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            )
            certificate = builder.sign(
                private_key=private_key, algorithm=hashes.SHA256(),
            )
            return certificate

        mocker.patch('cryptography.x509.load_der_x509_certificate', side_effect=create_dummy_dsa_cert)
        mocker.patch('authlib.jose.JsonWebSignature.deserialize_compact', return_value=self.__DUMMY_JWS_TOKEN)

        # test
        success, response = jws_verify(self.__DUMMY_VERIFY_JWS)

        # check
        assert success is True
        assert response == self.__DUMMY_VERIFY_RESP

    def test_verify_07(self, mocker: MockerFixture):
        """
        x5c verify test.
        """

        date_from = datetime(2022, 1, 1, 1, 1, 1)
        date_to = datetime(2037, 12, 31, 23, 59, 59)
        token = {
            "Version": "1.0",
            "iss": "SERVER_ID",
            "sub": "SERVER_ID",
            "aud": "DEVICE_ID",
            "jti": 'SERVER_ID_DEVICE_ID',
            "exp": int(date_to.timestamp()),
            "nbf": int(date_from.timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
            "Permissions": ["Management", "Control", "Data"]
        }

        root, mid, server = generate_test_certs()
        root_cert = rep(root[1]).decode()
        certs_str = [rep(c).decode() for _, c in (server, mid)]
        protected = {"alg" : "PS256", "kid": "SERVER_ID", "x5c": certs_str}
        jws = JsonWebSignature()
        expected = json.dumps(token).encode('utf-8')
        jws_token = jws.serialize_compact(protected, expected, server[0]).decode()
        jws_verify = Verify(True, [root_cert])

        # test
        success, response = jws_verify(jws_token)

        # check
        assert success is True
        assert response == expected

    def test_verify_08(self, mocker: MockerFixture):
        """
        x5c(EllipticCurvePrivateKey) verify test.
        """

        mocker.resetall()

        date_from = datetime(2022, 1, 1, 1, 1, 1)
        date_to = datetime(2037, 12, 31, 23, 59, 59)
        token = {
            "Version": "1.0",
            "iss": "SERVER_ID",
            "sub": "SERVER_ID",
            "aud": "DEVICE_ID",
            "jti": 'SERVER_ID_DEVICE_ID',
            "exp": int(date_to.timestamp()),
            "nbf": int(date_from.timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
            "Permissions": ["Management", "Control", "Data"]
        }

        root, mid, server = generate_test_certs(True)
        root_cert = rep(root[1]).decode()
        certs_str = [rep(c).decode() for _, c in (server, mid)]
        protected = {"alg" : "ES256", "kid": "SERVER_ID", "x5c": certs_str}
        jws = JsonWebSignature()
        expected = json.dumps(token).encode('utf-8')
        jws_token = jws.serialize_compact(protected, expected, server[0]).decode()
        jws_verify = Verify(True, [root_cert])

        # test
        success, response = jws_verify(jws_token)

        # check
        assert success is True
        assert response == expected

    def test_verify_09(self, mocker: MockerFixture):
        """
        x5c(Othre PrivateKey) verify test.
        """

        mocker.resetall()

        private_key = dsa.generate_private_key(1024, default_backend())
        issuer = set_x509name_attr()
        cert = (
            x509.CertificateBuilder()
            .subject_name(issuer)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=10))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("somedomain1.com")]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )
        
        # test
        with pytest.raises(TypeError) as e:
            _verifying(private_key.public_key(), cert)

        # check
        assert str(e.value) == "verify() missing 1 required positional argument: 'algorithm'"

    def test_verify_10(self, mocker: MockerFixture):
        """
        x5c(invalid date) verify test.
        """

        mocker.resetall()

        date_from = datetime(2022, 1, 1, 1, 1, 1)
        date_to = datetime(2037, 12, 31, 23, 59, 59)
        token = {
            "Version": "1.0",
            "iss": "SERVER_ID",
            "sub": "SERVER_ID",
            "aud": "DEVICE_ID",
            "jti": 'SERVER_ID_DEVICE_ID',
            "exp": int(date_to.timestamp()),
            "nbf": int(date_from.timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
            "Permissions": ["Management", "Control", "Data"]
        }

        root, mid, server = generate_test_certs(False, True)
        root_cert = rep(root[1]).decode()
        certs_str = [rep(c).decode() for _, c in (server, mid)]
        protected = {"alg" : "PS256", "kid": "SERVER_ID", "x5c": certs_str}
        jws = JsonWebSignature()
        expected = json.dumps(token).encode('utf-8')
        jws_token = jws.serialize_compact(protected, expected, server[0]).decode()
        jws_verify = Verify(True, [root_cert])

        # test
        success, _ = jws_verify(jws_token)

        # check
        assert success is False

    def test_verify_11(self, mocker: MockerFixture):
        """
        x5c(invalid date) verify test.
        """

        mocker.resetall()

        date_from = datetime(2022, 1, 1, 1, 1, 1)
        date_to = datetime(2037, 12, 31, 23, 59, 59)
        token = {
            "Version": "1.0",
            "iss": "SERVER_ID",
            "sub": "SERVER_ID",
            "aud": "DEVICE_ID",
            "jti": 'SERVER_ID_DEVICE_ID',
            "exp": int(date_to.timestamp()),
            "nbf": int(date_from.timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
            "Permissions": ["Management", "Control", "Data"]
        }

        root, mid, server = generate_test_certs(False, True)
        root_cert = rep(root[1]).decode()
        certs_str = [rep(c).decode() for _, c in (server, mid)]
        protected = {"alg" : "PS256", "kid": "SERVER_ID", "x5c": certs_str}
        jws = JsonWebSignature()
        expected = json.dumps(token).encode('utf-8')
        jws_token = jws.serialize_compact(protected, expected, server[0]).decode()
        jws_verify = Verify(False, root_cert)

        # test
        success, response = jws_verify(jws_token)

        # check
        assert success is True
        assert response == expected

class TestSign:
    """Sign test class."""

    __DUMMY_SIGN_KID = '00000009-60fe-5e15-8002-000000001954'

    __DUMMY_SIGN_KEY = {'crv': 'P-256', 'd': 'q9oqUvmn60v0xJU8FSCu__JpBrHcXLDxt2vgVUXMzzs', 'kty': 'EC', 'x': 'S1tYZTnQKtM5KNDNNmBfL3NRLyB_QV3jwMBZR-u0TBo', 'y': 'IsxOTEPzHeXSOQSHDEiStaw6Er-B5vrVvUntKRxZVLc'}

    __DUMMY_SIGN_CRT = 'MIICeDCB4aADAgECAgYBeuGfkIkwDQYJKoZIhvcNAQENBQAwFTETMBEGA1UEAwwKS2V5U2VydmljZTAgFw0yMTA3MjYwNzAyNDhaGA8yMTIxMDcwMjA3MDI0OFowLzEtMCsGA1UEAwwkMDAwMDAwMDktNjAxMy1mMGVhLTgwMDItMDAwMDAwMDAwMDAwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAES1tYZTnQKtM5KNDNNmBfL3NRLyB/QV3jwMBZR+u0TBoizE5MQ/Md5dI5BIcMSJK1rDoSv4Hm+tW9Se0pHFlUtzANBgkqhkiG9w0BAQ0FAAOCAYEAEX/grJqq6P+S9Fssb4pC0YB28KFUxsy+jqak1XwRoeoB94Syy2EUxy0Tk/EQYNARSjrwalbvkBeBNSqxsXZy+yV0Se/CxtwebfKkqLcoWIgwQwpQBKj12bOAII+uml2GXCR45BcflGX/Yc6k2HtgjBZ3EUMddyE9MZm6nQW5sI0UifTMcMCmIECuBVQxXHW6pKzxL0poCmolhYjb3tIvcTEl7/9LNqMyfojWGYhVIK7LFV/I8+HdLDMVQY2DsY3qG2qpFJP/mU0BJUc6jFL2gb7HKt8iNz7/MF5NkeeZBON4ILi70Zdr9srR06syIqktiub41Q95RwoDweiKoRWZ9Or+js81rW/zRycizDDKapns0HmejKtRYLn0iEFZtolR96UwbxTfrh1ZzS9DTWLBVTkO9As0YDByyqimJsg62JXx5RK0lBaFR2kdSOKPOvV/U3F/QdQGGXHUfWz2Uj3xj5M67PAMkKe7oE31mUKDp1LN/Q9MPasHxYwr8zRAiaBt'

    __DUMMY_SIGN_PAYLOAD=b'{"EndPointX509Certificate": "MIIDvDCCAiSgAwIBAgIGAXKCg+HeMA0GCSqGSIb3DQEBDQUAMCAxHjAcBgNVBAMMFU1hc3RlcktleS5zY2VuZXJhLmNvbTAgFw0yMDA2MDUwMzI2MjBaGA8yMTIwMTIzMTA4MDAwMFowHDEaMBgGA1UEAxMRTEFSb290LnNjZW5lcy5jb20wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCuOSjirBX+pKkdiCHO2zsdTHOW4nTewQdgYfG+npRJ2/79ooiS8PkXFEY98eCUD9YyQuhxKIbGBbD2+YZGPv1TCdShRu0J+LuwVq3e/0r64c67HdUt7LMSjtSCVPF82RW083C8rUDXSBWondXiAHYjriOsl12X5FOK17aYNlvHh9Hzx6XCT5lUNpEu+fcAH9G1+j1XI/gLcsGML3iJ2N0wsPR1ryaSVM5JvsXE57aa77Qk6uN7P3RbJmg0hevZp9sboLkJgBim8CEvJsqkE1hhuDbNaAzGa49tmAoFo2j7JysRbJtC5XhEmBE13yl6zcXynpV569W+13VVMKmxS/1EsdrwSIAZN9AwMRvSqXPCn1ZPD3XPrbhvBk62nxMkIfe0bh5G/S4uQUejqqCoFTpcXSVIlxubEmO3Ph0ocpp172Ky7kI3Y93v/XjrcdLRQYQ3tXA1O/+x9F6GAj4cgN4BrljrIazRWScd6beFv412Gu3CsKVFClmy90ARiCyj3TUCAwEAATANBgkqhkiG9w0BAQ0FAAOCAYEAdoJAyuaLb+wOIhP/FQjuEPkPi9qYvLC0d0LBYTT9gPRpKIYONP6iGNvrYYzrZCjNWEztLmnbkDykK9HZsoUt3OZu3P+0k5wUK0IMXK6WGPmYKkEmOXDAGvW6T4wOxjLEWybZS+0CcEm3WDPX3al3+r3qV1FkYczD6s8PItLcIkl7PKzGMd+GUt3nbGSQoGnCanC+otKbR1dM/LtcGr9+pIxH9aIxScLIdKQrk3LvmHiKpAHlw1uaGQjWzQE2qtwZfRIOx6nAkTUC7Jw8RDFjSiQBfyZDH4YvF0VJxHBXvDoxXZIUz1eKZfaNzGsnAd7J2BcnrzgDnNgvxyGjf4VlYxGpzE+ycvRJcg5lNkjpxflbeIoTOa+WcwYLsh2BZLLTVw7HB3wHAaIu60JMSSXr2pp9PaK/Qw8T+tEnBatxl2u37V4gWUHfgtG38Ee5Dzo/cs9fdIDyzXbrzRGPHmwLaOYztYUKQ0+0+PWAGFE4P6XqezWWP95sigB17+LAEk8w", "CMFHeader": "{\\"Version\\": \\"1.0\\", \\"MessageType\\": \\"request\\", \\"SourceEndPointID\\": \\"00000009-60fe-5e15-8002-000000001954\\", \\"DestinationEndPointID\\": \\"00000001-5cdd-280b-8002-000000000000\\", \\"CommandType\\": \\"/1.0/00000001-5cdd-280b-8002-000000000000/management/GetManagementEndPoint\\", \\"DateTimeStamp\\": \\"2022-02-16T07:51:40.385Z\\", \\"CommandID\\": 0}", "AccessToken&Payload": "eyJlbmMiOiJBMjU2R0NNIiwia2lkIjoiMDAwMDAwMDEtNWNkZC0yODBiLTgwMDItMDAwMDAwMDAwMDAwIiwiYWxnIjoiUlNBMV81In0.nk0n7Dh1Uqqj79dbgk8qq_U9M3k5X_Vr0YLYKH-rkEqP5jaPn1AByOw9GWABVkkrhnDL10Unms1YmHNRtaKYGQtNrSEMozfQCQo7U55orhLcWO9zJigPmSBzNvS46TxRkRee_sTN6gUARW1QZ37NknTCBGHe5YchBTkvOdi6_-RfpospZ1o-lzfzKyxSVGXfV_zsohcp3536TQMlkZqJ5GwhG2TpV66gHcN87J55AKKIZe3j5O3FhJk-aDd11n86rHdEaD8ykx9s6wp8cbSlX4JOmcbX0UumLEc4hiiy7Nq7GeuAOzxcVUpMFVG5aoFhqaOb_n4Cq4fBYfQqCbbkIZVKmr4WH79ivE_-Xr32k9xP691aWbGysSB0p4b0gQw5vvqEdTFI2xsPRjmTy0KSX1kBNewYrirNu-0XEMahuAtpoLTiz0xHI9yXoTl3c7vpmcwVj9PXYFFQN8VgnhRDdfEp65bP-h5JWM-InW1xs0conB4YbPlEGkU4x7ASLp-o.Lbw1af1zLOWQ35l8.qMWavaBbi0GYjcizgZTrCQpzqF5IMy4_gUPtMgluramLja0TbXYAdHM5T76funDBe-QzGwtEmjqGtOVFh3hMXkTvtkRYxBQcPVcFprV9zaHk_WkW5vrQvByw-eRlJ5GcMx8jdo9r3cuGhM2akiih93vx9BDeQI3EXTZAGIAEZ79i3d1yVqzxOAvWUgywD_RE4k9QpeaswwJZiPPb4MViMTY0ns17mieDn2K2acZt-Uc5JR0YQyeuJb6bXbHjkuXHPsPgsucp2f-YrGLPhI_IdWrw3Nvh8mp5nwFkL_ewa6UsybZRYMa6rIbPSojImEtGB4OCN_H1SmUKAYlJwBgG7ZUZ1SSktGpaxJ1jTk8OCq3WndDvXczpGywtyKUmi1zizqkcrM07DhOscWpPnB5Ed1XAOUwuStctIDG3Zdzc0MLIMUF08TlUYsWzxsBJaHa-Hb_AlW-DzB58uRu1LS_npt5WJfEIMOpoleQjEhDb2_teyVOvLCDm5LdIVlBQ0wlZGjRgMv7PjDE61FXouwKL-zX6GqTQPVlsaM0P4xHpPuuWekhpkwDZUeiUTpRi17waArOPO2EiAF1WXwkHqzFSeh73IaSn9uTAnFiCvu8Hn0GY9yGF_rD7WA0RvpXm2Ru2DEHHxzCv95TYMdqxANPt0fQsK4Np7JaxwcUCJHYR9Ec2V8465byctl0Ac78f9fdQEllQHUUGD2Ud3hdi4-YpRhuGTIhLU-ophd1ZP8rX4NJqwt6zVd7ERWeTx-jWD3xt1JdicDMh8RYiinpz56Cuwg9tyCm-zsLSipKDcCfmqz82lH5VNBjYYxu3e2TqAuHVZsZJ4C40BKQ4aZDRNyj-NUs-6zIB_uY9B_29Z_yEDNZmaKMoRpejfv7omRmIOl8deBZ4Kcr41_FmAyLB69Q3QrpnrrILovbE2L0wQwCIy0unPyh4kOFH7CQNUEAsFTtu3Zx3RKY74-9Ihr-KrCRQ8_6gNW81TKEy364FT9e6uBVvC4eTieOui1CM7FTt2rLWb2Iwg2w7D4qTgPGPd8d-rRLiDrMm699aBnGyn-G4AnkyK11eUpHhuonaMUtzvXjDHDUd6_EW1hs1H5sWr4RLPttiydnUJiiV8At0Ea5Q0bEbjEpRQXRys2PMg0xwwNdlGkAoHldcgdpXuX-9mROf-nrRKQ3d0e9zceKdnn8dTJCCgltPBudXF5_fwhqztEQPI2avwLIvzAF61fXyME8HhUWqm3P7l8pdjGExDAohxVyjYB9ubST93Kvxi7VjezsfZVVRuzwNE6p5Y6ew7UxkCXTVZUgOZq5lgLa3P7StaficYv2kArYSzzn0_IzQ_4iCGElYjrytPni3No7w2NPPUiKGntxT_WixumaMx_Cgw45YuKZZWrLnKHSvFJB7aDKrl3O9em8qRfqv2OCASpRkqIo-qrU7SnutUmTpKfHj3FMs04_n38WgQrF1FOkxZhcec9LZkLrCc9BDSWSElie8IKdSwmV3ltcZ1_JdjmkN29yCDKlICRZLUBISmtzLAknbaodfHO89MVXw7CzvXYgEjffFsBfxkAuJGGx6n_b1OobrnRYKQNdbiGLCmJAhgAdKXZ2V6K1haL0S5VRn3dwFS6zfL9C4Fp6DdY34tUHinR4rPTYEH0guNS1yMjhTtUry0qvQuWS0ZFDjDS0hlweFtHhpX-A4NUOQm3fwvCNToDR5tQKUmGxtThHqNkAw7upncYEREUHJ_AILhaHCr8n5lRCmi5_BnEQpcxd_5qDVrE-WRoA4uEPPYd4CZ60y3xOe7ls56-NGSQxWyL9qJoe9UOOe2XZmaftkbLHfSXhACD4zTdv5gDXNJyp8kbdso01t5NwcZe5dDxHAx_HF2b6Y0S-aOvK6yY9T70eQQfJdxa14JDQ4f1TFHytz9Na65yXe1_RSNa9BLbW2v1zsYERAoaAh4VmtH4mq_QGVgDbU-zcDJreeeTNwk5uE1aVqgHBY-9haNYbMBgBjMUrK7czKXsrucepnAfLtaIcF5UDOVY9iYxvihJ0T6sJoJjiHuwQzGIE4vRdsEf5Q7ebGpWlQt_RvDfWqOXOu0BvY8kQGPhl7I5vb5hdurLOdxAmYuiCWdCNvZbwcRFt-56R3icR_Uf9Wv82Ocoy39flJqS2A_A_VH5apLbqa9sp-wJl49IsyR8UePIpVjCh1FbAjI0rL31CUpmBAv7T5ZXZqSIUHfiPhZgMPPMMWiX4Xnh6zML6h31AU8Q_7jegfiOrqffwGjEKJrK6IVEQY8YCmCocepXPppth2MWd1T_yY2v6Au-ftBA_SPlB-Yly4M5Sy9FQ6rDdD5KMfzD35qy-uEoBzyHklVWof249xoZrBztdNXUVgsZzVwb5VgSm0y-RK2qqu0mr0TlBVlFGgaXHA5mw6TWH6dipYO15zrPaFnnLYbSRvucrYc7Tn50g01uIL95lXtAtx0j-tAi5XkXeiP5EQ0pPyWEkNlxr7Kcz3hSpKwEwXtWWCydMYCtWVwBEsr54ii6A4dO66nsnq5324Et_Kmo0FqKZ5-wRdJZgJzYZB2saB-WDJHlvG81J8tzVaKgeAJ3mnKyPyc2WBuJW18JhtrWtnstdCfzAeXDzTyRv8VkcchlQrvdN2L2NMvwnAb4JCZjRAdmkA2sDvrQhRFeDwICfAHKCjhf_8YsMYyWR53DcQxipnwJkA5RUHHtXHRcasLj_KZBOPgzFUpHd2Ys7stuZqJiNfniv0NGs-5VPX2tDYsm9b4_DTO-iWJHSOcFhbyjiDGLUxzg99QuipTJCD5hkwPo8L1CMcPwCf6rFFFctfL1cvSt3D_M13xu7dVvV9RuKHKIwzcDLuNhVTNZ7ugb0gn1fi3SkwodFxwbTCY_kQ-ootFOhi4_sPDE2X7mAgICYB3kc_xS-k_pqbmSHf3bLOCJraHc24-BJO0sw3S5NNbfTBZJ3K_dLW8jOBLnElBRU3MWnkAFYyY-HpxTU29spLjlcZXmGEEYlIwRqeDfJGeLcv5IGCQ-Av5HesUzNL53Wlw-O5Zi3EJMQ3Fn92W1XWxeV1SM2WKWev3SvX6pnv2nby3eg-9anXLEdVJKFyQHsC5Ny71ftookcXqchxvCKKOR8y5qFE4PECSKtHk-Bf8M4gaaDa7R4dkV463SGLf0nkajFOtimkIpcxoocOY7P02nYPoa3Q9JDWDLzdWNmIv0eIz55-y4CkPum9fadicLho_TjZFKh9Egl_dwFtIJcqyYzR6wzDKnU_eT7ztKNPWRfmsGEB4TBzza1DS6yKWCUVKYbMVYi6K9iAudzOMFuc1n8I0b2l9Tnobsmwk2F1jAk5o2eryzsTcVbtTrweMKhAkTzWKVg2APhw6CbABCRvWNLRevQsnodfRYonn_xxRUEDGt8IszMdYSkC4MsCkxQ_Sb65TL_vkVdrUiTpbehZvhEkno6MnTyaoG6ArLFpFAP0qEsoqdz1lJFlVbT7VxUTKZCfffzSPdLogaw9VrHUqjtXVFyMnMtVHWyIsHBEx2nCQ2twdQbAo-j-EC2NflOr4S0_Us-VyoRXfGjotbo_zyAs_GPT8pqGhTakQSscV93xpWW4yL1YPARAHkyrTe4JUmJnfZdnMX0j9lfjcGX0qoJTOFY6keZqBnbc_d13gRLc7LUg9o-kPeF6__aXcu6HM3Fs0ptMraXjGKaNydV0rJcBg4A93FQ5PW4dCZa0Xte7G5vPR9u61pOfSFBPNJzmWrJj5ohi_LlZGNYklQo3NknOBHAXDE1W_NKIQsDe_v7TugqNXMH4wVhckLcrrUidAILVmbWTdI1ScDrDi_fhLff03KttXvhkwPo6k6h9qA7BJlKq9iKynxo5WseMnJtMUdIpeIJxkqck6KcekUH_MSZXZ9ao5bYVORj28MTxPjU7lFRQeE-fOP3TPB-W_gockVmzvRMAAWX1rurnM5wNmOngpAchORMaNbjcGMTgB5OrL2K8qxK_jQzjD9j-rDu2uRV6n6sMOy09KUUA6LzQrV44QUJF0sQSsjKpwll_5PYl1z7L1selIEEPVOa7L-DyMD3PCng9c_JsRGOSVN4zYktG1o30dm_7rdbwCqMTy3MlDvfmPaNr2k7ylPBOh0ACafFvi1-Qm48CWimYUqoV1myumi1UwJDEOO0yNpt9kaD6KtQppkmosc5pfF8v80AZ_Punz4X-mQ5BPRoBMooouGMMf3UgI4EVRXlccwLUhAIseoWK6unx-12w8FEy6LxUQZOrivP8Z3Xirc8sDMaDcnT8rLYxmPUR_s_WLM0zIs0jmtq2sQob3nnKWRlcKYmZe0h9dbB75aaBwiDJ5D325gDZYEhLUJNuMLbKmbb7xlvtzce1lpUh0ecNoMFaI4AeiQwwCIE8MC4tCu9ty7NI0FmulETnRVzO-B8SIu65hBmBS0m09unb0UQvN3Kf9EXqVV9swXdrbSUu9Lr2i2veAeDW6Zrsma8naBSGMUB0EHvzjptmyNCH0U-ALRIoOTDix9-JKngraEjY2g9rVJ_jp-wRITntPj1vUdK7vq3tgcUV5XBb0YaXsPYL7N1veCwIoobmO3C1VIoDtR8RLXSTx8ujxYRh-qfNW8m7NSUpo6y5nMWys9VaSfFBarfOUmIlWUbUgRdm96Cov6y1V_zWUZZ2PcjI54agg_qJobXSxMQ_hycNbs0cAyoA4U43rLuWeXH4_B9hhrjQD-y-shAemp6fLJf8DA59UdJj9PgsXk6oejhr53nxnZrpH6ZihELDkKcd5mggMcuCCOS4YymZx7xN5pRBSjfRv0gpDZlhDcAHGG0aP5zDQpBDztckskvBydg_7-Zg4pHORF00-DnwyPM41o-xR-G44JdR-TKSpZsQgFuS_irgAo6lO4h1y38-V38cbcQhb-iZgRv9HYrEBz6DixF_cuxtW1OBdHii4rCPPeyzk9Oexc5hTx037hsSt8FUECBeL5OXe3L_tV8sUkK44zdG1j2cXb8YP2_u2py1Ib6XN-iSb2VtP4ppVwssi_EE9r-hi1--huoxRt2qUZu1nB-rvFzkYWL73UsdzQZox35Q13KHSldhfMEtR-7EY8oixM2QdX_9O5SP6ZORwa-Sotb47DPmnVuIkBGSgtG9ypmUUffMCMkgPXYFRcm66pddcg57-XYRHYCnn2vrKRlqJHbhhPEAIdJD2ln3y4SbMj3J4XSdSsKDsu1ihiWSVHdXjTnljMxy1ubA5grbL-nbdW5S8ifD_F_8ny5EKY5G18vXvI7f2cvyrjvkKxtFrbrPKirHRPj8od0Fmuc5QpW8J8ogdkTEZdcBXrgJdQg68fWkZzsU3PNMXSNFT12rxKQqAkC6KhV8QC0KnNy0350fGiWzVRC35iX3l2o-YGARr8NTsWWxEJelrF-m7A5VvQE7mecxmhbwH4uh-3y3YcKw8yx2y1X43z2K0_5-ifoyVj8XEJQmk3eS8omeTM76v4BHXkZ8Se59KCi0Og7yZG1b7RYo87VB3dvefpYJvFmlXyMwMF2D6O_kkHYahw68n3e2-jw9yP9gUFR1RdokEAxAnpE6ryc7yhJyEg10WlmZCLH1Vhp1XEScFFOgdaC-JO7PSO8sZoRNzk_-gBTKpzN7YJCzhxEyQnHzUepFT091aC8-_0wWlghkkoHKsNyF0m7A31oDDgp_zoegpGdLp6SRGB0RFaFk6WPo6egUbgLNi3FeK17LS2CwcbYR2raEIKrAxwsONQLxuzH9mq3FiffJbNNxJOOZqdDd6Lrdoei59aU5AGd2Vcgc93FjlDqhFyYXAQ92W3RV510HToc5715Gl87gFmgVMOPOSfKxIyJfL_jRUKNU5n57jQVJ9_eam6V_LHR5TiiKCa0nqZYIArlJd9oMRaA6Pur8lasMhAW7X8QjJgk75tx1ANHl8avpwpSGe7ofje1tIVluTZPDwGUt9dka58msUlUcgg4784DAz-uROoLnzBMe56QDxdt_H3yZ7TH8i6iP3H6Be-2MHItpI3yi6xT9uRtc4pnz1E_e42i7OR2N_AC7YdfGZZ9Bcg5hEK5UpEFKaDZDWaV-nqcQdtM6j_iD45EPM_bwFJ4RJTXaWomZWnMubkGi_fHK0XClqpA2tHWqUrP1ykBLOyMdsILkQiVYYbPtlPPNmdbwcUB4x59dNAmNdLz0ICunAtoF1SfoT2txVLmzAY_M8gp2UWzwcdf9OeLNz8AxRSsagJdArilbWRigwANekdB42RxxA9VLWOLzpZUKSYJqi46EYdu-pqUx_vWwepyQqBiatpzEWhoctoHyV-51M7AP64nO0xVLa5Rwcki2S3nHq_WUgRL5Di9tnbnQrv3qVtUjLd-8UJgGhtxJw588aN2GE3mNKUNYvahZczEGI6U_C86Sr_ZvB2TfOIffxEnMXGS8ejKD_ChMl3MzwQrXA4R-q6cpAoJHMNemJcfeA_ZKygqLSHPUjMGup7lkcIHRP5n_1AcUGrBOuak7mmKZmb1ZXUatVOKkVGa3Wv4KXMfa0ow-Sc1Dmzf2C2ChYr5pIQT_sWiAEJhVWcEpyNnrQpDXxwo1X-dBeqTVGkGBEWfnUgS9SC4AZISqu-eiTWjK3YRxHacis7tdvwmfeQeQP559iaf2W2plSuRC_dn743StID8P-epSZ8B5_74kUFnq8Hb_85qYxelZD7sgwnVEm1eLIGq7l3ZwdvKhkidWFj8xEPDnxZcvMU4EA9RjgT0BLUvBEcVAcTlBZ3z-GBrdoZ4ojhGb6F6cN3twZ_AqJaqk7dKg29RsFRJ2wT9V6YRHEPJ6ZE2pz5_4Z2TZepxGVF9FkIdA9DQWlpymW3DwnDdBlj7OZmfE2DUUwsnYWZopQybbpgdfEru_lpCPAPSeJE9RwgpFGFqVQ53M_z0SH1c8Cc_SLFX5LfHwVXlahC8walzorGrFVKEdzJ3j3M0PjhPSX0iPTJZ1PtuKcPtqvcGed1k4uNqTrB3E9_9pFE9ycc_OVXab1zBjuAFFgCwvMlLLrJR1CBjtRIiQWArbDPALHIO_-DawPsG3dGpV6HsOJ3wToSEiQqFmtlNHJU_GWoc3SH8lqdnsEXf07HP43f2G2e9SryDtiK_z4O9jD7u1OOYCZpcnxy3WvTAgjquGJQ-HpUry-5XBWBZxCj1czlpC93DWcJthLzhZgpqxoQw-BztFsF3QlBbjrAmsEMqMLnaV8Gl3VqGCADGIlfbQqGwRWAI5opAUlwfvCQS97ar8SMM_qMpFDowtYhxphmqyjxfuBW4ETc0aS92k-TR6ov89pB9o9zX-fdpGl6zuZaiNsuxpjCNSNp-w4ATrOEk1YDvoErcbfsDQpcsXZn9FZYTcAJ6FH8eFXzP-_xdL_yqPZyT3eleDSn-CthZrVh4DFxSL_dYRgSSuCMHW21puhI4uWUvsTUM9Qn1IxdehVgwTzYogemPxWh7h1ZqnkiN4QohqFpEOseo2Co8MPC8iMewPSKE7K16WbfArHLVb9bJxSO8xRuYvUV6keHG2mBQWcgItNQsEnAeIktpYqfVrGBzIoT5iLEp0gCczTnhU64SwpvjaAwP1C49WatXIDwiVhl-FK7L8pmuIR1DPXeY2V8jXYvpgTkadM-PbyJ6IdLvzIsMrdU175ta_YbYELPgcxjYRvV2FhyZhrd3IANeWOhzThC530SXBYngp2ZvrhCto2DVVeo7mAVGi3ScBnfQKxkDtToUdoEqMs1mLAjlVzvx-hM3T95GQ8rJngOK81vtvjjiu-zqwo_LspzdenTAaL4A6rYM1HlFCXA_xPctA-O471R6c7fBdh8RVh1FuaymQgsGq18IuwFWcGwhXZH4ZYhtTuCDVsunALq7fs_99UaFnTmivTew8c_NIaqL4JzYQENA4YIAYs_TpMk3E11RNOEndTDEBxuUjcuQuFwInQAgcIV7vOilBbBW4Ey8KECxUqIljRhUq6UWOcCtHdUlskxFKqzE1ICI0vFvzCfe2ZB1xDXQuzYKAE1Xa__nEb6H3FUorwva-440-lnltjgkKOGBZsZldwJzyBui4_hYE-s0TYIr6Ys9tAxnSKwVgIywzAgpKPvhXEF11GdR5CR1gtO0Zp7n8f4Tr_lR6glkGeE3sh4YiPIHjd6bL5awiPqINP2v_CqsDvjvfxpgaJ-zvr1n7t4L48bYwCIxtBcffiRsJkwfQ6W99FZmnnWXIHmPmWTcny9qC9vX58-Etmbf3OoSNFlJS3CwVOVBfAe_AaNJ0OVmHCokSDM_CLCh1nreCse4v6JUPfjnO_pcwUDvnW43c8Fn6JWk4cQhSXm0X7TCaFIdBjsnM-nPf43ykuNIvBgkOaUjLbeeKtWZiGPr32ZpX9nTGrkXnSh_0wp2F4VcMvIxGeMb2FVkT75I5sFORm9Neu-uMMkivsNltjQLoq498FVpXBQx9XWN2gHWNCxAjsZKQJWAewna6gsjCMHDpwuTOMFgXjz7S9lThhmpqykW37Vf1cecoxOGR3fcIFNpOvD_VDgT41u_nbpY9025L8YWYJK8t2BFE0hTGfHOrxamabtqsXxHgL1j4xkA_JZzfR2HBItaZCNwuoTJaYGDJegEooduLwF_stHB3t4l2sON1HCtJ35GBHuiyR68vHr-WKhhvDlPOZjB4zdz4x6rNflLfK2qDYRcgXKWTi7DuN-vxzDblH6jHuyjIilntbLGoz9TnGHki0ZHC9wOvIpgfapQO8wx9EGkngVV7CToi82xf2mpJENE-OZlgv7eGwHgpzpsjX4EUnwiPVecolRu0RXXNtfPkcdKN1ykn9nfqQBPXcTRgRRY5uBPSj-OM8O-PDSAMre18-Kdid0kpLOiPWdP1k7CJHUDj9x9sXV5N50RJIhHjWRjRiAUKfyb9B9fwbxiyjUqFdNGYLyTtUffXDo2S5EiT_iGSy21D24PoSEhnCp254CyvNYDrwgefDjk68hu3jeqhU14kLHZvZRCik9SljHAMtjI0uC1gvGC9U2hLEDUw3QBZhOcmRz8KW8Z9spj0NcjQ_f5Om7Yi6x2scu3jWcSTSDTCI5CCoBBl53xge39Kq_Fy4lG2lEJNtt5LeIJ8wAxaxwjW2Ro_3JFcvRWd3IgfeSp6iCKFcDKFrqxfoyoVBhPG2UryNDDkM8REp9pbUG-E6oAP1rD3KYRlbr7xpgm1oFb4j0iOTkkelQ4faYY-_L-tJ2KHweQE48phdJkcJsOJNod8rRtLC7cvb1gNokmEXRhQrGDQNBTHC8hEvygEhgv20sEFcgh0_lj-OYXq9NAm0ZYHG_VNsWn5IgJLK1ZdmSgshOu9Oj3XCpgwPT5bCxRnCRmC-U0EQROR1oVX688V9u3GoWhDLQ6KLh_OfJLkL7FxEqJtUU3V64VF-RN5Uvw9lOCw6RwOk8eM5vqdpjlxrhfsObf0Ugr7T02oJXE4JkeI9r95iiOvY3Mi1CrHjYmr1tj0oGnyT98DfIg3YGK80xp-PHBUTHrb_tQvs9lFbkh0An25XQCUJFkSveD2Gf7W35dVSejW-7AJSGMF5TVClOpy7G6BnI510q8PanLh_8rsm8iKz3cXgM74TEmYfcGHHHxNLT_yjgToNTIRkYCdv_ullBH1eJk-Q8aCfbX3IE59uVmldXIRaHeMF1vEMdo7r5zon9JR0h4LDqw9tRbbJzhXO_fIpV0k-7bsImPo5NQ1bKcQubkIJAGTUnHnPhRS22aaThBPrCNEo-JrjDeXczmq1e6ezfdx5JTBMd-cG9QVoVlEYjDxgjEmUFIrJh0LQr9xitrL2loFAdbw-hQZTZ4NFWCOcEfnx6ZBipcGro0bKsmw98fk50bt62c20EE92QCyfgHdblW2zw9V04JaKadMpzUXPUL3e1Ux2ii9pN6sdxDpHhm2mj40hG0qczhIyvRG7y7yelLEPeoXie3OVfwJizfG2ne01ScTlh9JHuYd2iNQ300t71ISSeB3ySXodiUeWpRMjYMpCyOR3RyOVTtgPaKAUKU4itjUmH7naDmAuMWhYTlDjTweE2GuDJuesnsHb5sQUUZRlAFmRApu2AfomvJEg0I1_SNdWKXpCxkJV3iGVxqEH-Z-XQHZ3G1j6UPFrbKrzEIiGBFn_S4W7Ef6w1DutfU8ZlcsA1KLpI26bkMfN7BRBAFiUFIsgKVOJuk-bTB4cr8XFWn0yQFJG92z9yXZNHcX4KCXs-T81i9wlrqWC0gslyVVjBrRBBv-lvKcFHaf1E99PBUenvuTNzq4bsaDiYUdHnpnG80TgQsF9oUSbesbGsmWY5YzIuUYdtt7BdtWcMqUYkj-G820bvDQa1-jTO4ke7ShB573AzNyXFp08xLKAr5GSwFHy3Ru4DlpPgRtgqKcNOVaTm1_CNY3x_nI5KI3Sfxs0m9f-dtSPb_2LZHhaMu8VlbbLOBhSUXDZu9M2kAkcEjQfZRX-XnJ2Xa1EWUWTcQk0FkbWyMuQzy8JaOQi5HSSRuoCyNe8GiYjGDX_0sUb88olLTXAQ981wNQBUJX5MS9vVKFWbhfVaujpjQQMN2wkwUnr88brx2fOdGUROm8rg_iLXvci5HQLB98copfVUeaZ3CsBRhBMiCRzgW7UO7Nszo1zzAr9DsoNNGFNy8TwX-Peapixb8j-SqT31n1iPahDptiHekmQLnDThrHNNoLnTai-MCmPPq78AJBlBikZQtfkVe-5iHgP0FqJw9YDKRBQaL4qKHPD1u0WKnvTUX8LRSjyIjk8clovK8fLeO-t5cBcgEnpXmZhxY5kapr4t-T82FAl-4U1IfOioP8Eanq74jNZAaOg8aSAZElkjjnw2bz0b2cc7sa00De3NlBYc_tGAE8uCDkloR3uAqbqvRrm6XAv_Ngu1DSkHf8Ej6szJB317II70HdArGH2Rz1lSQziwoAsIFO0_ZKo7H_dNSUbrr_OjQbg9MYdt6TLNyhb9MS10sgpueLM-aGUpCb9A61Rv907KcWccGCIRgVrRiwN7sX5Z1yP-tUdaXBAMQ7H2MyZBHFOWWF9nB_p8M1rxnya9mHSSwvSCR-RihNOeeNyS2a-GzJA1PijCXr0aD8e2a0M7KbOMx9FhERwAeURc8RN_0bCIfTvrAkRUzjS5dub1hOHCz7PzMWF39fkBtY-eqNrEBT4DxAfq-MkDAQi_M4OVz1wEOhxv2pekFpiIkRaLrKzR3GZcZjJ9sarejJivn_ImrawpdvRS75aS37E7Dlax9wa_QBgWFu6evOsX0Sb9v3A0FdiSl4XExxtHF-fN6OA4_4Wn16CH3vis1LJxZQPDsp0s_CNYqcCMJ2eG2EKneBv37Jv4ZV6XA5BXqyQUmfhCQoUaJCYaIGO2UJmuYYYh9VrpDTaPLmIaSNpITTDCUXKRPbMJMCTUe0opxLZM0Jh5XATcKHg7PG0axcRcG36Ki4alDz_0fT9oewLgBpWpVnTFlCsI2vQ7xed8ykm8u8CYjWt9_YHfs1Lj0S0UsHBP8AOa4Vd0SiMbBmNeLOhZHyC_POnGUFVGkCH9W-GSNrfDpykZVM_etJRtIGBasKN2MNd71TZalGpxS437Lyxg7Mkmdc1OAzUHYysdBpENEdpK_vYU654JdQyLsULLiz_sCmf8kZK-X6J2D-s_vNeEg5DEyqse9KMV1MjJj_p8_qXwMQLRQJQJsGQHrNx_FxDgCs7FKZCqBTitaxGgsNHnGsHFK0x5RdjhWJtQL8lzpzZ6GhK0RtrEygu51NwUJ0iyid74o8WELX6rDrSUNpkvJfzuy9NC0qGDtKzymTTwc-uaz-T7xl7rAGuOlrFOqy--9Bt0KM04ZZ_ttzLMgHuAazrfdSf7-bFlnZzt4AYREmyaFteziDNOAH62Y4yxNYjnnNfekPWBc6MzLAHMoEDSOf0RZeJAS2nEvOXi_fJ1V07RwdBuSAzxlDQz5nJHOeo7MeVZP9BMGOzpS60NUJ-PuCpxPCuVr_diZV2zU0aMJT8Ezs99WWfg2ygWIi-QdBSVhSI8waXjjNaT3w-bymhsOAQVfpP5hYuu9hBIfGjNwqSNEtpiyUDQvfc0ra9tnPYG0lc9vjQ990Sp2qBIv_YRdjevL3BlbfXIWsPjM1hOTe32vYrOksr2TpafLpTufdEj9yFTwaOEkwen59tjIbdp_rB1Kg6mxRlXzr8OTizPUV6-og_CZCGTk46dA0I2U35i9ZnJ0U1-RUcFf1abEUsKBaJszY2aW_5C9IXPV7vC8T99_8h8EuCQp8JCiml-Pbr-v0GfR_kdOwB-7k61VI028cAlp9VcBh7fHauKfCpLSHipO0WU9o4FaDHzlyuvHWBWOXPSxCLkrr8-4FOfWxAL7oMGZW8YdDRUbWjbUZda9aCdg2ctVJ42u3ssyhpbbFKCy3IYSM1VRTRr_6Ma3gbvGbbAd1rhNe7iUQOBTfuO42bGRnTcxPiMNn59x0KqtSiOEVsCqHU2EWlmt5Li3c2W9C_6_mS-Q5EYxJOvL3xvo0kYlb0QiveTirZzsr7lnQCU0Lo0Rbf2aJkiEmCWnesER_pWKWPXO3RMaF_bNLlEVV6A5jvDrELi1Tpe51aJ0t9BflyaJu1NQ1HTMyDK1VxMglnJ9TaJi4CyBfzdifkwOHce4g3m6F8x84qySd079Sdq1H7BgQJvS1HHsJd8spghckTe6apTN-jznNL6kLx14PTEgweQK_ljYTgZSSu8xCwyaVnutPoxr-n4a0ACsH9LrwQA09YmMW3QCZAjn3_sL5PgpXWlMeAm0mC2xVIIeRiPwBIKbMZ7Y9_Q-8QV03ZonK5cg1tNkwpsqJSI73zwtU4Ph8O4UgPH8iHm93h5aRfpJy3EfGVLyI-lly0-1sWcHT8S2AEBRN7JH-x1i30s-hCctVVp46h_ABp0FWoKPoMbKqHTLEER7z66Tu3gtPYduArvXhBx5f7tV9Rd2O0VZCCw2wso0qFOCEVjXNs0gx1lPhYR5drOLXnY_1o8pOo4sh5ruJ7jax8vz7ibkAtas_SAtDTN09_ruEzHQsdOOABTzdSz-ab_Y75cFQfWP1y7ibnJfbqhMP6Bg6Z1jYChJ8hLpSSbX6GDdzH6w_aS1GnoEDtdXmDyQax4bv1sz8GFlNfb05Et7Pc6VbWugmlCEhWoMMG17v-wIMQbZCFBiYknl7svJpEbG4yWagl-tf6Ar7Zluhx-JP0p6lKQrxTOrHer6FIt_jZCFRugI6oyU2fQaUR1WKDXul8UBb5sK_wVf1-6EkaoEQIhoIHYFggysa7vWxyZ15Qy3nhC7V2JJ1HFxbbxg_vRnzlwbLDPL0vjwiXeydx1V6u66jNays0xrAf39Gk4AbtSr0ZC5y4TVt-egKGt6e2rH9octcBpAyaecd5CmIXuzQwSRTGryBRC6f7ur01v03nLU8Rw05RdjPU68MdwAqcFpDg8YzmcFYpszMPgclcgMepF2wnt_xCoQjvnUkbaCCjH4f-T6WPXCACXhxNqFB7nANpVQwsoDVv2pTcJ0gs_2wdlMZ3v6rF6KNvQYoA7Ymjj9YuDksProc-w2QOZtblG0c1Ody4Dx53xPPiU-sLr369vLqTqp-qBhKkljzwHC8gjXL67WIX1WhRtMdVXDGaHSrbql8eqXuOl3Wass8A0LeCzuIBeaFMPev51JBgyzzUuhnokUBT3tclysKcbJBo1Ebnwp0wUl2NQn6DnrlagwVZIjqQfQvcGyR0lhbHi1zWT3ZN-nHPJwu30oBcsFDc0KCIq4zvctVtvl9qbgIAfeIktEelLlmmE4O9Axb-LOKk4wrmEaacXRT0fa2soClSYWbm_Dho9E_Gh3m2ReZ_xU4QV9-5KgDhFlOINZnz0MQZVDImEi2_Uo0A29W5427yTcgTxTHvLJzAB4TAzu6iCpYPUPwJgU1wqQz51Y6C2ycoJJcYQ2EmNW9KxC_8-YK6KRikFmsa_-jSYOfcL19coBJrQ9XaKGt_fzhqgAFc1ZPcmXBskDqZZIEoM8lHa3jvKBQprLJuTM-_-hxkCkjGV6y1-mA1ebYgkqhy-YXPuu3pCEnbCIElxgb9D5il340FXySAlbaNzLkrGORwcXeH2VuF1qU4PnESD6mgn8TDdaMfZviov83S1oxUjEPOzbeNHsuz6gRkzQNJ-nbXTBozCBhgGO7Ze8x3q_plw3BmP7t-ltLhdA0WK3QH1vsFQ8t2pGZT8b6WTDteDfw6Y5TzAplHH5ynih6Ufcfe3xWR8FMP6a966NJiDBEmnLaDgac36lsLBl4MYpYc-apixMyzt58IcMZTmyV2FYXaxfg9D5lH4M.zJXfQj8fL02qr-pWpO6msw"}'

    __DUMMY_SIGN_JWS_HEADER = 'eyJraWQiOiIwMDAwMDAwOS02MGZlLTVlMTUtODAwMi0wMDAwMDAwMDE5NTQiLCJ4NWMiOlsiTUlJQ2VEQ0I0YUFEQWdFQ0FnWUJldUdma0lrd0RRWUpLb1pJaHZjTkFRRU5CUUF3RlRFVE1CRUdBMVVFQXd3S1MyVjVVMlZ5ZG1salpUQWdGdzB5TVRBM01qWXdOekF5TkRoYUdBOHlNVEl4TURjd01qQTNNREkwT0Zvd0x6RXRNQ3NHQTFVRUF3d2tNREF3TURBd01Ea3ROakF4TXkxbU1HVmhMVGd3TURJdE1EQXdNREF3TURBd01EQXdNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVTMXRZWlRuUUt0TTVLTkROTm1CZkwzTlJMeUIvUVYzandNQlpSK3UwVEJvaXpFNU1RL01kNWRJNUJJY01TSksxckRvU3Y0SG0rdFc5U2UwcEhGbFV0ekFOQmdrcWhraUc5dzBCQVEwRkFBT0NBWUVBRVgvZ3JKcXE2UCtTOUZzc2I0cEMwWUIyOEtGVXhzeStqcWFrMVh3Um9lb0I5NFN5eTJFVXh5MFRrL0VRWU5BUlNqcndhbGJ2a0JlQk5TcXhzWFp5K3lWMFNlL0N4dHdlYmZLa3FMY29XSWd3UXdwUUJLajEyYk9BSUkrdW1sMkdYQ1I0NUJjZmxHWC9ZYzZrMkh0Z2pCWjNFVU1kZHlFOU1abTZuUVc1c0kwVWlmVE1jTUNtSUVDdUJWUXhYSFc2cEt6eEwwcG9DbW9saFlqYjN0SXZjVEVsNy85TE5xTXlmb2pXR1loVklLN0xGVi9JOCtIZExETVZRWTJEc1kzcUcycXBGSlAvbVUwQkpVYzZqRkwyZ2I3SEt0OGlOejcvTUY1TmtlZVpCT040SUxpNzBaZHI5c3JSMDZzeUlxa3RpdWI0MVE5NVJ3b0R3ZWlLb1JXWjlPcitqczgxclcvelJ5Y2l6RERLYXBuczBIbWVqS3RSWUxuMGlFRlp0b2xSOTZVd2J4VGZyaDFaelM5RFRXTEJWVGtPOUFzMFlEQnl5cWltSnNnNjJKWHg1UkswbEJhRlIya2RTT0tQT3ZWL1UzRi9RZFFHR1hIVWZXejJVajN4ajVNNjdQQU1rS2U3b0UzMW1VS0RwMUxOL1E5TVBhc0h4WXdyOHpSQWlhQnQiXSwiYWxnIjoiRVMyNTYifQ'

    __DUMMY_SIGN_JWS_PAYLOAD = 'eyJFbmRQb2ludFg1MDlDZXJ0aWZpY2F0ZSI6ICJNSUlEdkRDQ0FpU2dBd0lCQWdJR0FYS0NnK0hlTUEwR0NTcUdTSWIzRFFFQkRRVUFNQ0F4SGpBY0JnTlZCQU1NRlUxaGMzUmxja3RsZVM1elkyVnVaWEpoTG1OdmJUQWdGdzB5TURBMk1EVXdNekkyTWpCYUdBOHlNVEl3TVRJek1UQTRNREF3TUZvd0hERWFNQmdHQTFVRUF4TVJURUZTYjI5MExuTmpaVzVsY3k1amIyMHdnZ0dpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCandBd2dnR0tBb0lCZ1FDdU9TamlyQlgrcEtrZGlDSE8yenNkVEhPVzRuVGV3UWRnWWZHK25wUkoyLzc5b29pUzhQa1hGRVk5OGVDVUQ5WXlRdWh4S0liR0JiRDIrWVpHUHYxVENkU2hSdTBKK0x1d1ZxM2UvMHI2NGM2N0hkVXQ3TE1TanRTQ1ZQRjgyUlcwODNDOHJVRFhTQldvbmRYaUFIWWpyaU9zbDEyWDVGT0sxN2FZTmx2SGg5SHp4NlhDVDVsVU5wRXUrZmNBSDlHMStqMVhJL2dMY3NHTUwzaUoyTjB3c1BSMXJ5YVNWTTVKdnNYRTU3YWE3N1FrNnVON1AzUmJKbWcwaGV2WnA5c2JvTGtKZ0JpbThDRXZKc3FrRTFoaHVEYk5hQXpHYTQ5dG1Bb0ZvMmo3SnlzUmJKdEM1WGhFbUJFMTN5bDZ6Y1h5bnBWNTY5VysxM1ZWTUtteFMvMUVzZHJ3U0lBWk45QXdNUnZTcVhQQ24xWlBEM1hQcmJodkJrNjJueE1rSWZlMGJoNUcvUzR1UVVlanFxQ29GVHBjWFNWSWx4dWJFbU8zUGgwb2NwcDE3Mkt5N2tJM1k5M3YvWGpyY2RMUlFZUTN0WEExTy8reDlGNkdBajRjZ040QnJsanJJYXpSV1NjZDZiZUZ2NDEyR3UzQ3NLVkZDbG15OTBBUmlDeWozVFVDQXdFQUFUQU5CZ2txaGtpRzl3MEJBUTBGQUFPQ0FZRUFkb0pBeXVhTGIrd09JaFAvRlFqdUVQa1BpOXFZdkxDMGQwTEJZVFQ5Z1BScEtJWU9OUDZpR052cllZenJaQ2pOV0V6dExtbmJrRHlrSzlIWnNvVXQzT1p1M1ArMGs1d1VLMElNWEs2V0dQbVlLa0VtT1hEQUd2VzZUNHdPeGpMRVd5YlpTKzBDY0VtM1dEUFgzYWwzK3IzcVYxRmtZY3pENnM4UEl0TGNJa2w3UEt6R01kK0dVdDNuYkdTUW9HbkNhbkMrb3RLYlIxZE0vTHRjR3I5K3BJeEg5YUl4U2NMSWRLUXJrM0x2bUhpS3BBSGx3MXVhR1FqV3pRRTJxdHdaZlJJT3g2bkFrVFVDN0p3OFJERmpTaVFCZnlaREg0WXZGMFZKeEhCWHZEb3hYWklVejFlS1pmYU56R3NuQWQ3SjJCY25yemdEbk5ndnh5R2pmNFZsWXhHcHpFK3ljdlJKY2c1bE5ranB4ZmxiZUlvVE9hK1djd1lMc2gyQlpMTFRWdzdIQjN3SEFhSXU2MEpNU1NYcjJwcDlQYUsvUXc4VCt0RW5CYXR4bDJ1MzdWNGdXVUhmZ3RHMzhFZTVEem8vY3M5ZmRJRHl6WGJyelJHUEhtd0xhT1l6dFlVS1EwKzArUFdBR0ZFNFA2WHFleldXUDk1c2lnQjE3K0xBRWs4dyIsICJDTUZIZWFkZXIiOiAie1wiVmVyc2lvblwiOiBcIjEuMFwiLCBcIk1lc3NhZ2VUeXBlXCI6IFwicmVxdWVzdFwiLCBcIlNvdXJjZUVuZFBvaW50SURcIjogXCIwMDAwMDAwOS02MGZlLTVlMTUtODAwMi0wMDAwMDAwMDE5NTRcIiwgXCJEZXN0aW5hdGlvbkVuZFBvaW50SURcIjogXCIwMDAwMDAwMS01Y2RkLTI4MGItODAwMi0wMDAwMDAwMDAwMDBcIiwgXCJDb21tYW5kVHlwZVwiOiBcIi8xLjAvMDAwMDAwMDEtNWNkZC0yODBiLTgwMDItMDAwMDAwMDAwMDAwL21hbmFnZW1lbnQvR2V0TWFuYWdlbWVudEVuZFBvaW50XCIsIFwiRGF0ZVRpbWVTdGFtcFwiOiBcIjIwMjItMDItMTZUMDc6NTE6NDAuMzg1WlwiLCBcIkNvbW1hbmRJRFwiOiAwfSIsICJBY2Nlc3NUb2tlbiZQYXlsb2FkIjogImV5SmxibU1pT2lKQk1qVTJSME5OSWl3aWEybGtJam9pTURBd01EQXdNREV0TldOa1pDMHlPREJpTFRnd01ESXRNREF3TURBd01EQXdNREF3SWl3aVlXeG5Jam9pVWxOQk1WODFJbjAubmswbjdEaDFVcXFqNzlkYmdrOHFxX1U5TTNrNVhfVnIwWUxZS0gtcmtFcVA1amFQbjFBQnlPdzlHV0FCVmtrcmhuREwxMFVubXMxWW1ITlJ0YUtZR1F0TnJTRU1vemZRQ1FvN1U1NW9yaExjV085ekppZ1BtU0J6TnZTNDZUeFJrUmVlX3NUTjZnVUFSVzFRWjM3TmtuVENCR0hlNVljaEJUa3ZPZGk2Xy1SZnBvc3BaMW8tbHpmekt5eFNWR1hmVl96c29oY3AzNTM2VFFNbGtacUo1R3doRzJUcFY2NmdIY044N0o1NUFLS0laZTNqNU8zRmhKay1hRGQxMW44NnJIZEVhRDh5a3g5czZ3cDhjYlNsWDRKT21jYlgwVXVtTEVjNGhpaXk3TnE3R2V1QU96eGNWVXBNRlZHNWFvRmhxYU9iX240Q3E0ZkJZZlFxQ2Jia0laVkttcjRXSDc5aXZFXy1YcjMyazl4UDY5MWFXYkd5c1NCMHA0YjBnUXc1dnZxRWRURkkyeHNQUmptVHkwS1NYMWtCTmV3WXJpck51LTBYRU1haHVBdHBvTFRpejB4SEk5eVhvVGwzYzd2cG1jd1ZqOVBYWUZGUU44VmduaFJEZGZFcDY1YlAtaDVKV00tSW5XMXhzMGNvbkI0WWJQbEVHa1U0eDdBU0xwLW8uTGJ3MWFmMXpMT1dRMzVsOC5xTVdhdmFCYmkwR1lqY2l6Z1pUckNRcHpxRjVJTXk0X2dVUHRNZ2x1cmFtTGphMFRiWFlBZEhNNVQ3NmZ1bkRCZS1Rekd3dEVtanFHdE9WRmgzaE1Ya1R2dGtSWXhCUWNQVmNGcHJWOXphSGtfV2tXNXZyUXZCeXctZVJsSjVHY014OGpkbzlyM2N1R2hNMmFraWloOTN2eDlCRGVRSTNFWFRaQUdJQUVaNzlpM2QxeVZxenhPQXZXVWd5d0RfUkU0azlRcGVhc3d3SlppUFBiNE1WaU1UWTBuczE3bWllRG4ySzJhY1p0LVVjNUpSMFlReWV1SmI2YlhiSGprdVhIUHNQZ3N1Y3AyZi1ZckdMUGhJX0lkV3J3M052aDhtcDVud0ZrTF9ld2E2VXN5YlpSWU1hNnJJYlBTb2pJbUV0R0I0T0NOX0gxU21VS0FZbEp3QmdHN1pVWjFTU2t0R3BheEoxalRrOE9DcTNXbmREdlhjenBHeXd0eUtVbWkxeml6cWtjck0wN0RoT3NjV3BQbkI1RWQxWEFPVXd1U3RjdElERzNaZHpjME1MSU1VRjA4VGxVWXNXenhzQkphSGEtSGJfQWxXLUR6QjU4dVJ1MUxTX25wdDVXSmZFSU1PcG9sZVFqRWhEYjJfdGV5Vk92TENEbTVMZElWbEJRMHdsWkdqUmdNdjdQakRFNjFGWG91d0tMLXpYNkdxVFFQVmxzYU0wUDR4SHBQdXVXZWtocGt3RFpVZWlVVHBSaTE3d2FBck9QTzJFaUFGMVdYd2tIcXpGU2VoNzNJYVNuOXVUQW5GaUN2dThIbjBHWTl5R0ZfckQ3V0EwUnZwWG0yUnUyREVISHh6Q3Y5NVRZTWRxeEFOUHQwZlFzSzROcDdKYXh3Y1VDSkhZUjlFYzJWODQ2NWJ5Y3RsMEFjNzhmOWZkUUVsbFFIVVVHRDJVZDNoZGk0LVlwUmh1R1RJaExVLW9waGQxWlA4clg0Tkpxd3Q2elZkN0VSV2VUeC1qV0QzeHQxSmRpY0RNaDhSWWlpbnB6NTZDdXdnOXR5Q20tenNMU2lwS0RjQ2ZtcXo4MmxINVZOQmpZWXh1M2UyVHFBdUhWWnNaSjRDNDBCS1E0YVpEUk55ai1OVXMtNnpJQl91WTlCXzI5Wl95RUROWm1hS01vUnBlamZ2N29tUm1JT2w4ZGVCWjRLY3I0MV9GbUF5TEI2OVEzUXJwbnJySUxvdmJFMkwwd1F3Q0l5MHVuUHloNGtPRkg3Q1FOVUVBc0ZUdHUzWngzUktZNzQtOUloci1LckNSUThfNmdOVzgxVEtFeTM2NEZUOWU2dUJWdkM0ZVRpZU91aTFDTTdGVHQyckxXYjJJd2cydzdENHFUZ1BHUGQ4ZC1yUkxpRHJNbTY5OWFCbkd5bi1HNEFua3lLMTFlVXBIaHVvbmFNVXR6dlhqREhEVWQ2X0VXMWhzMUg1c1dyNFJMUHR0aXlkblVKaWlWOEF0MEVhNVEwYkViakVwUlFYUnlzMlBNZzB4d3dOZGxHa0FvSGxkY2dkcFh1WC05bVJPZi1uclJLUTNkMGU5emNlS2RubjhkVEpDQ2dsdFBCdWRYRjVfZndocXp0RVFQSTJhdndMSXZ6QUY2MWZYeU1FOEhoVVdxbTNQN2w4cGRqR0V4REFvaHhWeWpZQjl1YlNUOTNLdnhpN1ZqZXpzZlpWVlJ1endORTZwNVk2ZXc3VXhrQ1hUVlpVZ09acTVsZ0xhM1A3U3RhZmljWXYya0FyWVN6em4wX0l6UV80aUNHRWxZanJ5dFBuaTNObzd3Mk5QUFVpS0dudHhUX1dpeHVtYU14X0NndzQ1WXVLWlpXckxuS0hTdkZKQjdhREtybDNPOWVtOHFSZnF2Mk9DQVNwUmtxSW8tcXJVN1NudXRVbVRwS2ZIajNGTXMwNF9uMzhXZ1FyRjFGT2t4WmhjZWM5TFprTHJDYzlCRFNXU0VsaWU4SUtkU3dtVjNsdGNaMV9KZGpta04yOXlDREtsSUNSWkxVQklTbXR6TEFrbmJhb2RmSE84OU1WWHc3Q3p2WFlnRWpmZkZzQmZ4a0F1SkdHeDZuX2IxT29icm5SWUtRTmRiaUdMQ21KQWhnQWRLWFoyVjZLMWhhTDBTNVZSbjNkd0ZTNnpmTDlDNEZwNkRkWTM0dFVIaW5SNHJQVFlFSDBndU5TMXlNamhUdFVyeTBxdlF1V1MwWkZEakRTMGhsd2VGdEhocFgtQTROVU9RbTNmd3ZDTlRvRFI1dFFLVW1HeHRUaEhxTmtBdzd1cG5jWUVSRVVISl9BSUxoYUhDcjhuNWxSQ21pNV9CbkVRcGN4ZF81cURWckUtV1JvQTR1RVBQWWQ0Q1o2MHkzeE9lN2xzNTYtTkdTUXhXeUw5cUpvZTlVT09lMlhabWFmdGtiTEhmU1hoQUNENHpUZHY1Z0RYTkp5cDhrYmRzbzAxdDVOd2NaZTVkRHhIQXhfSEYyYjZZMFMtYU92SzZ5WTlUNzBlUVFmSmR4YTE0SkRRNGYxVEZIeXR6OU5hNjV5WGUxX1JTTmE5QkxiVzJ2MXpzWUVSQW9hQWg0Vm10SDRtcV9RR1ZnRGJVLXpjREpyZWVlVE53azV1RTFhVnFnSEJZLTloYU5ZYk1CZ0JqTVVySzdjektYc3J1Y2VwbkFmTHRhSWNGNVVET1ZZOWlZeHZpaEowVDZzSm9KamlIdXdRekdJRTR2UmRzRWY1UTdlYkdwV2xRdF9SdkRmV3FPWE91MEJ2WThrUUdQaGw3STV2YjVoZHVyTE9keEFtWXVpQ1dkQ052WmJ3Y1JGdC01NlIzaWNSX1VmOVd2ODJPY295MzlmbEpxUzJBX0FfVkg1YXBMYnFhOXNwLXdKbDQ5SXN5UjhVZVBJcFZqQ2gxRmJBakkwckwzMUNVcG1CQXY3VDVaWFpxU0lVSGZpUGhaZ01QUE1NV2lYNFhuaDZ6TUw2aDMxQVU4UV83amVnZmlPcnFmZndHakVLSnJLNklWRVFZOFlDbUNvY2VwWFBwcHRoMk1XZDFUX3lZMnY2QXUtZnRCQV9TUGxCLVlseTRNNVN5OUZRNnJEZEQ1S01mekQzNXF5LXVFb0J6eUhrbFZXb2YyNDl4b1pyQnp0ZE5YVVZnc1p6VndiNVZnU20weS1SSzJxcXUwbXIwVGxCVmxGR2dhWEhBNW13NlRXSDZkaXBZTzE1enJQYUZubkxZYlNSdnVjclljN1RuNTBnMDF1SUw5NWxYdEF0eDBqLXRBaTVYa1hlaVA1RVEwcFB5V0VrTmx4cjdLY3ozaFNwS3dFd1h0V1dDeWRNWUN0V1Z3QkVzcjU0aWk2QTRkTzY2bnNucTUzMjRFdF9LbW8wRnFLWjUtd1JkSlpnSnpZWkIyc2FCLVdESkhsdkc4MUo4dHpWYUtnZUFKM21uS3lQeWMyV0J1SlcxOEpodHJXdG5zdGRDZnpBZVhEelR5UnY4VmtjY2hsUXJ2ZE4yTDJOTXZ3bkFiNEpDWmpSQWRta0Eyc0R2clFoUkZlRHdJQ2ZBSEtDamhmXzhZc01ZeVdSNTNEY1F4aXBud0prQTVSVUhIdFhIUmNhc0xqX0taQk9QZ3pGVXBIZDJZczdzdHVacUppTmZuaXYwTkdzLTVWUFgydERZc205YjRfRFRPLWlXSkhTT2NGaGJ5amlER0xVeHpnOTlRdWlwVEpDRDVoa3dQbzhMMUNNY1B3Q2Y2ckZGRmN0ZkwxY3ZTdDNEX00xM3h1N2RWdlY5UnVLSEtJd3pjREx1TmhWVE5aN3VnYjBnbjFmaTNTa3dvZEZ4d2JUQ1lfa1Etb290Rk9oaTRfc1BERTJYN21BZ0lDWUIza2NfeFMta19wcWJtU0hmM2JMT0NKcmFIYzI0LUJKTzBzdzNTNU5OYmZUQlpKM0tfZExXOGpPQkxuRWxCUlUzTVdua0FGWXlZLUhweFRVMjlzcExqbGNaWG1HRUVZbEl3UnFlRGZKR2VMY3Y1SUdDUS1BdjVIZXNVek5MNTNXbHctTzVaaTNFSk1RM0ZuOTJXMVhXeGVWMVNNMldLV2V2M1N2WDZwbnYybmJ5M2VnLTlhblhMRWRWSktGeVFIc0M1Tnk3MWZ0b29rY1hxY2h4dkNLS09SOHk1cUZFNFBFQ1NLdEhrLUJmOE00Z2FhRGE3UjRka1Y0NjNTR0xmMG5rYWpGT3RpbWtJcGN4b29jT1k3UDAybllQb2EzUTlKRFdETHpkV05tSXYwZUl6NTUteTRDa1B1bTlmYWRpY0xob19UalpGS2g5RWdsX2R3RnRJSmNxeVl6UjZ3ekRLblVfZVQ3enRLTlBXUmZtc0dFQjRUQnp6YTFEUzZ5S1dDVVZLWWJNVllpNks5aUF1ZHpPTUZ1YzFuOEkwYjJsOVRub2JzbXdrMkYxakFrNW8yZXJ5enNUY1ZidFRyd2VNS2hBa1R6V0tWZzJBUGh3NkNiQUJDUnZXTkxSZXZRc25vZGZSWW9ubl94eFJVRURHdDhJc3pNZFlTa0M0TXNDa3hRX1NiNjVUTF92a1ZkclVpVHBiZWhadmhFa25vNk1uVHlhb0c2QXJMRnBGQVAwcUVzb3FkejFsSkZsVmJUN1Z4VVRLWkNmZmZ6U1BkTG9nYXc5VnJIVXFqdFhWRnlNbk10VkhXeUlzSEJFeDJuQ1EydHdkUWJBby1qLUVDMk5mbE9yNFMwX1VzLVZ5b1JYZkdqb3Rib196eUFzX0dQVDhwcUdoVGFrUVNzY1Y5M3hwV1c0eUwxWVBBUkFIa3lyVGU0SlVtSm5mWmRuTVgwajlsZmpjR1gwcW9KVE9GWTZrZVpxQm5iY19kMTNnUkxjN0xVZzlvLWtQZUY2X19hWGN1NkhNM0ZzMHB0TXJhWGpHS2FOeWRWMHJKY0JnNEE5M0ZRNVBXNGRDWmEwWHRlN0c1dlBSOXU2MXBPZlNGQlBOSnptV3JKajVvaGlfTGxaR05Za2xRbzNOa25PQkhBWERFMVdfTktJUXNEZV92N1R1Z3FOWE1INHdWaGNrTGNyclVpZEFJTFZtYldUZEkxU2NEckRpX2ZoTGZmMDNLdHRYdmhrd1BvNms2aDlxQTdCSmxLcTlpS3lueG81V3NlTW5KdE1VZElwZUlKeGtxY2s2S2Nla1VIX01TWlhaOWFvNWJZVk9SajI4TVR4UGpVN2xGUlFlRS1mT1AzVFBCLVdfZ29ja1ZtenZSTUFBV1gxcnVybk01d05tT25ncEFjaE9STWFOYmpjR01UZ0I1T3JMMks4cXhLX2pRempEOWotckR1MnVSVjZuNnNNT3kwOUtVVUE2THpRclY0NFFVSkYwc1FTc2pLcHdsbF81UFlsMXo3TDFzZWxJRUVQVk9hN0wtRHlNRDNQQ25nOWNfSnNSR09TVk40ellrdEcxbzMwZG1fN3JkYndDcU1UeTNNbER2Zm1QYU5yMms3eWxQQk9oMEFDYWZGdmkxLVFtNDhDV2ltWVVxb1YxbXl1bWkxVXdKREVPTzB5TnB0OWthRDZLdFFwcGttb3NjNXBmRjh2ODBBWl9QdW56NFgtbVE1QlBSb0JNb29vdUdNTWYzVWdJNEVWUlhsY2N3TFVoQUlzZW9XSzZ1bngtMTJ3OEZFeTZMeFVRWk9yaXZQOFozWGlyYzhzRE1hRGNuVDhyTFl4bVBVUl9zX1dMTTB6SXMwam10cTJzUW9iM25uS1dSbGNLWW1aZTBoOWRiQjc1YWFCd2lESjVEMzI1Z0RaWUVoTFVKTnVNTGJLbWJiN3hsdnR6Y2UxbHBVaDBlY05vTUZhSTRBZWlRd3dDSUU4TUM0dEN1OXR5N05JMEZtdWxFVG5SVnpPLUI4U0l1NjVoQm1CUzBtMDl1bmIwVVF2TjNLZjlFWHFWVjlzd1hkcmJTVXU5THIyaTJ2ZUFlRFc2WnJzbWE4bmFCU0dNVUIwRUh2empwdG15TkNIMFUtQUxSSW9PVERpeDktSktuZ3JhRWpZMmc5clZKX2pwLXdSSVRudFBqMXZVZEs3dnEzdGdjVVY1WEJiMFlhWHNQWUw3TjF2ZUN3SW9vYm1PM0MxVklvRHRSOFJMWFNUeDh1anhZUmgtcWZOVzhtN05TVXBvNnk1bk1XeXM5VmFTZkZCYXJmT1VtSWxXVWJVZ1JkbTk2Q292NnkxVl96V1VaWjJQY2pJNTRhZ2dfcUpvYlhTeE1RX2h5Y05iczBjQXlvQTRVNDNyTHVXZVhINF9COWhocmpRRC15LXNoQWVtcDZmTEpmOERBNTlVZEpqOVBnc1hrNm9lamhyNTNueG5acnBINlppaEVMRGtLY2Q1bWdnTWN1Q0NPUzRZeW1aeDd4TjVwUkJTamZSdjBncERabGhEY0FIR0cwYVA1ekRRcEJEenRja3NrdkJ5ZGdfNy1aZzRwSE9SRjAwLURud3lQTTQxby14Ui1HNDRKZFItVEtTcFpzUWdGdVNfaXJnQW82bE80aDF5MzgtVjM4Y2JjUWhiLWlaZ1J2OUhZckVCejZEaXhGX2N1eHRXMU9CZEhpaTRyQ1BQZXl6azlPZXhjNWhUeDAzN2hzU3Q4RlVFQ0JlTDVPWGUzTF90VjhzVWtLNDR6ZEcxajJjWGI4WVAyX3UycHkxSWI2WE4taVNiMlZ0UDRwcFZ3c3NpX0VFOXItaGkxLS1odW94UnQycVVadTFuQi1ydkZ6a1lXTDczVXNkelFab3gzNVExM0tIU2xkaGZNRXRSLTdFWThvaXhNMlFkWF85TzVTUDZaT1J3YS1Tb3RiNDdEUG1uVnVJa0JHU2d0Rzl5cG1VVWZmTUNNa2dQWFlGUmNtNjZwZGRjZzU3LVhZUkhZQ25uMnZyS1JscUpIYmhoUEVBSWRKRDJsbjN5NFNiTWozSjRYU2RTc0tEc3UxaWhpV1NWSGRYalRubGpNeHkxdWJBNWdyYkwtbmJkVzVTOGlmRF9GXzhueTVFS1k1RzE4dlh2STdmMmN2eXJqdmtLeHRGcmJyUEtpckhSUGo4b2QwRm11YzVRcFc4SjhvZ2RrVEVaZGNCWHJnSmRRZzY4ZldrWnpzVTNQTk1YU05GVDEycnhLUXFBa0M2S2hWOFFDMEtuTnkwMzUwZkdpV3pWUkMzNWlYM2wyby1ZR0FScjhOVHNXV3hFSmVsckYtbTdBNVZ2UUU3bWVjeG1oYndINHVoLTN5M1ljS3c4eXgyeTFYNDN6MkswXzUtaWZveVZqOFhFSlFtazNlUzhvbWVUTTc2djRCSFhrWjhTZTU5S0NpME9nN3laRzFiN1JZbzg3VkIzZHZlZnBZSnZGbWxYeU13TUYyRDZPX2trSFlhaHc2OG4zZTItanc5eVA5Z1VGUjFSZG9rRUF4QW5wRTZyeWM3eWhKeUVnMTBXbG1aQ0xIMVZocDFYRVNjRkZPZ2RhQy1KTzdQU084c1pvUk56a18tZ0JUS3B6TjdZSkN6aHhFeVFuSHpVZXBGVDA5MWFDOC1fMHdXbGdoa2tvSEtzTnlGMG03QTMxb0REZ3Bfem9lZ3BHZExwNlNSR0IwUkZhRms2V1BvNmVnVWJnTE5pM0ZlSzE3TFMyQ3djYllSMnJhRUlLckF4d3NPTlFMeHV6SDltcTNGaWZmSmJOTnhKT09acWREZDZMcmRvZWk1OWFVNUFHZDJWY2djOTNGamxEcWhGeVlYQVE5MlczUlY1MTBIVG9jNTcxNUdsODdnRm1nVk1PUE9TZkt4SXlKZkxfalJVS05VNW41N2pRVko5X2VhbTZWX0xIUjVUaWlLQ2EwbnFaWUlBcmxKZDlvTVJhQTZQdXI4bGFzTWhBVzdYOFFqSmdrNzV0eDFBTkhsOGF2cHdwU0dlN29mamUxdElWbHVUWlBEd0dVdDlka2E1OG1zVWxVY2dnNDc4NERBei11Uk9vTG56Qk1lNTZRRHhkdF9IM3laN1RIOGk2aVAzSDZCZS0yTUhJdHBJM3lpNnhUOXVSdGM0cG56MUVfZTQyaTdPUjJOX0FDN1lkZkdaWjlCY2c1aEVLNVVwRUZLYURaRFdhVi1ucWNRZHRNNmpfaUQ0NUVQTV9id0ZKNFJKVFhhV29tWlduTXVia0dpX2ZISzBYQ2xxcEEydEhXcVVyUDF5a0JMT3lNZHNJTGtRaVZZWWJQdGxQUE5tZGJ3Y1VCNHg1OWROQW1OZEx6MElDdW5BdG9GMVNmb1QydHhWTG16QVlfTThncDJVV3p3Y2RmOU9lTE56OEF4UlNzYWdKZEFyaWxiV1JpZ3dBTmVrZEI0MlJ4eEE5VkxXT0x6cFpVS1NZSnFpNDZFWWR1LXBxVXhfdld3ZXB5UXFCaWF0cHpFV2hvY3RvSHlWLTUxTTdBUDY0bk8weFZMYTVSd2NraTJTM25IcV9XVWdSTDVEaTl0bmJuUXJ2M3FWdFVqTGQtOFVKZ0dodHhKdzU4OGFOMkdFM21OS1VOWXZhaFpjekVHSTZVX0M4NlNyX1p2QjJUZk9JZmZ4RW5NWEdTOGVqS0RfQ2hNbDNNendRclhBNFItcTZjcEFvSkhNTmVtSmNmZUFfWkt5Z3FMU0hQVWpNR3VwN2xrY0lIUlA1bl8xQWNVR3JCT3VhazdtbUtabWIxWlhVYXRWT0trVkdhM1d2NEtYTWZhMG93LVNjMURtemYyQzJDaFlyNXBJUVRfc1dpQUVKaFZXY0VweU5uclFwRFh4d28xWC1kQmVxVFZHa0dCRVdmblVnUzlTQzRBWklTcXUtZWlUV2pLM1lSeEhhY2lzN3RkdndtZmVRZVFQNTU5aWFmMlcycGxTdVJDX2RuNzQzU3RJRDhQLWVwU1o4QjVfNzRrVUZucThIYl84NXFZeGVsWkQ3c2d3blZFbTFlTElHcTdsM1p3ZHZLaGtpZFdGajh4RVBEbnhaY3ZNVTRFQTlSamdUMEJMVXZCRWNWQWNUbEJaM3otR0JyZG9aNG9qaEdiNkY2Y04zdHdaX0FxSmFxazdkS2cyOVJzRlJKMndUOVY2WVJIRVBKNlpFMnB6NV80WjJUWmVweEdWRjlGa0lkQTlEUVdscHltVzNEd25EZEJsajdPWm1mRTJEVVV3c25ZV1pvcFF5YmJwZ2RmRXJ1X2xwQ1BBUFNlSkU5UndncEZHRnFWUTUzTV96MFNIMWM4Q2NfU0xGWDVMZkh3VlhsYWhDOHdhbHpvckdyRlZLRWR6SjNqM00wUGpoUFNYMGlQVEpaMVB0dUtjUHRxdmNHZWQxazR1TnFUckIzRTlfOXBGRTl5Y2NfT1ZYYWIxekJqdUFGRmdDd3ZNbExMckpSMUNCanRSSWlRV0FyYkRQQUxISU9fLURhd1BzRzNkR3BWNkhzT0ozd1RvU0VpUXFGbXRsTkhKVV9HV29jM1NIOGxxZG5zRVhmMDdIUDQzZjJHMmU5U3J5RHRpS196NE85akQ3dTFPT1lDWnBjbnh5M1d2VEFnanF1R0pRLUhwVXJ5LTVYQldCWnhDajFjemxwQzkzRFdjSnRoTHpoWmdwcXhvUXctQnp0RnNGM1FsQmJqckFtc0VNcU1MbmFWOEdsM1ZxR0NBREdJbGZiUXFHd1JXQUk1b3BBVWx3ZnZDUVM5N2FyOFNNTV9xTXBGRG93dFloeHBobXF5anhmdUJXNEVUYzBhUzkyay1UUjZvdjg5cEI5bzl6WC1mZHBHbDZ6dVphaU5zdXhwakNOU05wLXc0QVRyT0VrMVlEdm9FcmNiZnNEUXBjc1habjlGWllUY0FKNkZIOGVGWHpQLV94ZExfeXFQWnlUM2VsZURTbi1DdGhaclZoNERGeFNMX2RZUmdTU3VDTUhXMjFwdWhJNHVXVXZzVFVNOVFuMUl4ZGVoVmd3VHpZb2dlbVB4V2g3aDFacW5raU40UW9ocUZwRU9zZW8yQ284TVBDOGlNZXdQU0tFN0sxNldiZkFySExWYjliSnhTTzh4UnVZdlVWNmtlSEcybUJRV2NnSXROUXNFbkFlSWt0cFlxZlZyR0J6SW9UNWlMRXAwZ0NjelRuaFU2NFN3cHZqYUF3UDFDNDlXYXRYSUR3aVZobC1GSzdMOHBtdUlSMURQWGVZMlY4alhZdnBnVGthZE0tUGJ5SjZJZEx2eklzTXJkVTE3NXRhX1liWUVMUGdjeGpZUnZWMkZoeVpocmQzSUFOZVdPaHpUaEM1MzBTWEJZbmdwMlp2cmhDdG8yRFZWZW83bUFWR2kzU2NCbmZRS3hrRHRUb1Vkb0VxTXMxbUxBamxWenZ4LWhNM1Q5NUdROHJKbmdPSzgxdnR2amppdS16cXdvX0xzcHpkZW5UQWFMNEE2cllNMUhsRkNYQV94UGN0QS1PNDcxUjZjN2ZCZGg4UlZoMUZ1YXltUWdzR3ExOEl1d0ZXY0d3aFhaSDRaWWh0VHVDRFZzdW5BTHE3ZnNfOTlVYUZuVG1pdlRldzhjX05JYXFMNEp6WVFFTkE0WUlBWXNfVHBNazNFMTFSTk9FbmRUREVCeHVVamN1UXVGd0luUUFnY0lWN3ZPaWxCYkJXNEV5OEtFQ3hVcUlsalJoVXE2VVdPY0N0SGRVbHNreEZLcXpFMUlDSTB2RnZ6Q2ZlMlpCMXhEWFF1ellLQUUxWGFfX25FYjZIM0ZVb3J3dmEtNDQwLWxubHRqZ2tLT0dCWnNabGR3Snp5QnVpNF9oWUUtczBUWUlyNllzOXRBeG5TS3dWZ0l5d3pBZ3BLUHZoWEVGMTFHZFI1Q1IxZ3RPMFpwN244ZjRUcl9sUjZnbGtHZUUzc2g0WWlQSUhqZDZiTDVhd2lQcUlOUDJ2X0Nxc0R2anZmeHBnYUotenZyMW43dDRMNDhiWXdDSXh0QmNmZmlSc0prd2ZRNlc5OUZabW5uV1hJSG1QbVdUY255OXFDOXZYNTgtRXRtYmYzT29TTkZsSlMzQ3dWT1ZCZkFlX0FhTkowT1ZtSENva1NETV9DTENoMW5yZUNzZTR2NkpVUGZqbk9fcGN3VUR2blc0M2M4Rm42SldrNGNRaFNYbTBYN1RDYUZJZEJqc25NLW5QZjQzeWt1Tkl2QmdrT2FVakxiZWVLdFdaaUdQcjMyWnBYOW5UR3JrWG5TaF8wd3AyRjRWY012SXhHZU1iMkZWa1Q3NUk1c0ZPUm05TmV1LXVNTWtpdnNObHRqUUxvcTQ5OEZWcFhCUXg5WFdOMmdIV05DeEFqc1pLUUpXQWV3bmE2Z3NqQ01IRHB3dVRPTUZnWGp6N1M5bFRoaG1wcXlrVzM3VmYxY2Vjb3hPR1IzZmNJRk5wT3ZEX1ZEZ1Q0MXVfbmJwWTkwMjVMOFlXWUpLOHQyQkZFMGhUR2ZIT3J4YW1hYnRxc1h4SGdMMWo0eGtBX0paemZSMkhCSXRhWkNOd3VvVEphWUdESmVnRW9vZHVMd0Zfc3RIQjN0NGwyc09OMUhDdEozNUdCSHVpeVI2OHZIci1XS2hodkRsUE9aakI0emR6NHg2ck5mbExmSzJxRFlSY2dYS1dUaTdEdU4tdnh6RGJsSDZqSHV5aklpbG50YkxHb3o5VG5HSGtpMFpIQzl3T3ZJcGdmYXBRTzh3eDlFR2tuZ1ZWN0NUb2k4MnhmMm1wSkVORS1PWmxndjdlR3dIZ3B6cHNqWDRFVW53aVBWZWNvbFJ1MFJYWE50ZlBrY2RLTjF5a245bmZxUUJQWGNUUmdSUlk1dUJQU2otT004Ty1QRFNBTXJlMTgtS2RpZDBrcExPaVBXZFAxazdDSkhVRGo5eDlzWFY1TjUwUkpJaEhqV1JqUmlBVUtmeWI5Qjlmd2J4aXlqVXFGZE5HWUx5VHRVZmZYRG8yUzVFaVRfaUdTeTIxRDI0UG9TRWhuQ3AyNTRDeXZOWURyd2dlZkRqazY4aHUzamVxaFUxNGtMSFp2WlJDaWs5U2xqSEFNdGpJMHVDMWd2R0M5VTJoTEVEVXczUUJaaE9jbVJ6OEtXOFo5c3BqME5jalFfZjVPbTdZaTZ4MnNjdTNqV2NTVFNEVENJNUNDb0JCbDUzeGdlMzlLcV9GeTRsRzJsRUpOdHQ1TGVJSjh3QXhheHdqVzJSb18zSkZjdlJXZDNJZ2ZlU3A2aUNLRmNES0ZycXhmb3lvVkJoUEcyVXJ5TkREa004UkVwOXBiVUctRTZvQVAxckQzS1lSbGJyN3hwZ20xb0ZiNGowaU9Ua2tlbFE0ZmFZWS1fTC10SjJLSHdlUUU0OHBoZEprY0pzT0pOb2Q4clJ0TEM3Y3ZiMWdOb2ttRVhSaFFyR0RRTkJUSEM4aEV2eWdFaGd2MjBzRUZjZ2gwX2xqLU9ZWHE5TkFtMFpZSEdfVk5zV241SWdKTEsxWmRtU2dzaE91OU9qM1hDcGd3UFQ1YkN4Um5DUm1DLVUwRVFST1Ixb1ZYNjg4Vjl1M0dvV2hETFE2S0xoX09mSkxrTDdGeEVxSnRVVTNWNjRWRi1STjVVdnc5bE9DdzZSd09rOGVNNXZxZHBqbHhyaGZzT2JmMFVncjdUMDJvSlhFNEprZUk5cjk1aWlPdlkzTWkxQ3JIalltcjF0ajBvR255VDk4RGZJZzNZR0s4MHhwLVBIQlVUSHJiX3RRdnM5bEZia2gwQW4yNVhRQ1VKRmtTdmVEMkdmN1czNWRWU2VqVy03QUpTR01GNVRWQ2xPcHk3RzZCbkk1MTBxOFBhbkxoXzhyc204aUt6M2NYZ003NFRFbVlmY0dISEh4TkxUX3lqZ1RvTlRJUmtZQ2R2X3VsbEJIMWVKay1ROGFDZmJYM0lFNTl1Vm1sZFhJUmFIZU1GMXZFTWRvN3I1em9uOUpSMGg0TERxdzl0UmJiSnpoWE9fZklwVjBrLTdic0ltUG81TlExYktjUXVia0lKQUdUVW5IblBoUlMyMmFhVGhCUHJDTkVvLUpyakRlWGN6bXExZTZlemZkeDVKVEJNZC1jRzlRVm9WbEVZakR4Z2pFbVVGSXJKaDBMUXI5eGl0ckwybG9GQWRidy1oUVpUWjRORldDT2NFZm54NlpCaXBjR3JvMGJLc213OThmazUwYnQ2MmMyMEVFOTJRQ3lmZ0hkYmxXMnp3OVYwNEphS2FkTXB6VVhQVUwzZTFVeDJpaTlwTjZzZHhEcEhobTJtajQwaEcwcWN6aEl5dlJHN3k3eWVsTEVQZW9YaWUzT1Zmd0ppemZHMm5lMDFTY1RsaDlKSHVZZDJpTlEzMDB0NzFJU1NlQjN5U1hvZGlVZVdwUk1qWU1wQ3lPUjNSeU9WVHRnUGFLQVVLVTRpdGpVbUg3bmFEbUF1TVdoWVRsRGpUd2VFMkd1REp1ZXNuc0hiNXNRVVVaUmxBRm1SQXB1MkFmb212SkVnMEkxX1NOZFdLWHBDeGtKVjNpR1Z4cUVILVotWFFIWjNHMWo2VVBGcmJLcnpFSWlHQkZuX1M0VzdFZjZ3MUR1dGZVOFpsY3NBMUtMcEkyNmJrTWZON0JSQkFGaVVGSXNnS1ZPSnVrLWJUQjRjcjhYRlduMHlRRkpHOTJ6OXlYWk5IY1g0S0NYcy1UODFpOXdscnFXQzBnc2x5VlZqQnJSQkJ2LWx2S2NGSGFmMUU5OVBCVWVudnVUTnpxNGJzYURpWVVkSG5wbkc4MFRnUXNGOW9VU2Jlc2JHc21XWTVZekl1VVlkdHQ3QmR0V2NNcVVZa2otRzgyMGJ2RFFhMS1qVE80a2U3U2hCNTczQXpOeVhGcDA4eExLQXI1R1N3Rkh5M1J1NERscFBnUnRncUtjTk9WYVRtMV9DTlkzeF9uSTVLSTNTZnhzMG05Zi1kdFNQYl8yTFpIaGFNdThWbGJiTE9CaFNVWERadTlNMmtBa2NFalFmWlJYLVhuSjJYYTFFV1VXVGNRazBGa2JXeU11UXp5OEphT1FpNUhTU1J1b0N5TmU4R2lZakdEWF8wc1ViODhvbExUWEFROTgxd05RQlVKWDVNUzl2VktGV2JoZlZhdWpwalFRTU4yd2t3VW5yODhicngyZk9kR1VST204cmdfaUxYdmNpNUhRTEI5OGNvcGZWVWVhWjNDc0JSaEJNaUNSemdXN1VPN05zem8xenpBcjlEc29OTkdGTnk4VHdYLVBlYXBpeGI4ai1TcVQzMW4xaVBhaERwdGlIZWttUUxuRFRockhOTm9MblRhaS1NQ21QUHE3OEFKQmxCaWtaUXRma1ZlLTVpSGdQMEZxSnc5WURLUkJRYUw0cUtIUEQxdTBXS252VFVYOExSU2p5SWprOGNsb3ZLOGZMZU8tdDVjQmNnRW5wWG1aaHhZNWthcHI0dC1UODJGQWwtNFUxSWZPaW9QOEVhbnE3NGpOWkFhT2c4YVNBWkVsa2pqbncyYnowYjJjYzdzYTAwRGUzTmxCWWNfdEdBRTh1Q0RrbG9SM3VBcWJxdlJybTZYQXZfTmd1MURTa0hmOEVqNnN6SkIzMTdJSTcwSGRBckdIMlJ6MWxTUXppd29Bc0lGTzBfWktvN0hfZE5TVWJycl9PalFiZzlNWWR0NlRMTnloYjlNUzEwc2dwdWVMTS1hR1VwQ2I5QTYxUnY5MDdLY1djY0dDSVJnVnJSaXdON3NYNVoxeVAtdFVkYVhCQU1RN0gyTXlaQkhGT1dXRjluQl9wOE0xcnhueWE5bUhTU3d2U0NSLVJpaE5PZWVOeVMyYS1HekpBMVBpakNYcjBhRDhlMmEwTTdLYk9NeDlGaEVSd0FlVVJjOFJOXzBiQ0lmVHZyQWtSVXpqUzVkdWIxaE9IQ3o3UHpNV0YzOWZrQnRZLWVxTnJFQlQ0RHhBZnEtTWtEQVFpX000T1Z6MXdFT2h4djJwZWtGcGlJa1JhTHJLelIzR1pjWmpKOXNhcmVqSml2bl9JbXJhd3BkdlJTNzVhUzM3RTdEbGF4OXdhX1FCZ1dGdTZldk9zWDBTYjl2M0EwRmRpU2w0WEV4eHRIRi1mTjZPQTRfNFduMTZDSDN2aXMxTEp4WlFQRHNwMHNfQ05ZcWNDTUoyZUcyRUtuZUJ2MzdKdjRaVjZYQTVCWHF5UVVtZmhDUW9VYUpDWWFJR08yVUptdVlZWWg5VnJwRFRhUExtSWFTTnBJVFREQ1VYS1JQYk1KTUNUVWUwb3B4TFpNMEpoNVhBVGNLSGc3UEcwYXhjUmNHMzZLaTRhbER6XzBmVDlvZXdMZ0JwV3BWblRGbENzSTJ2UTd4ZWQ4eWttOHU4Q1lqV3Q5X1lIZnMxTGowUzBVc0hCUDhBT2E0VmQwU2lNYkJtTmVMT2haSHlDX1BPbkdVRlZHa0NIOVctR1NOcmZEcHlrWlZNX2V0SlJ0SUdCYXNLTjJNTmQ3MVRaYWxHcHhTNDM3THl4ZzdNa21kYzFPQXpVSFl5c2RCcEVORWRwS192WVU2NTRKZFF5THNVTExpel9zQ21mOGtaSy1YNkoyRC1zX3ZOZUVnNURFeXFzZTlLTVYxTWpKal9wOF9xWHdNUUxSUUpRSnNHUUhyTnhfRnhEZ0NzN0ZLWkNxQlRpdGF4R2dzTkhuR3NIRksweDVSZGpoV0p0UUw4bHpwelo2R2hLMFJ0ckV5Z3U1MU53VUowaXlpZDc0bzhXRUxYNnJEclNVTnBrdkpmenV5OU5DMHFHRHRLenltVFR3Yy11YXotVDd4bDdyQUd1T2xyRk9xeS0tOUJ0MEtNMDRaWl90dHpMTWdIdUFhenJmZFNmNy1iRmxuWnp0NEFZUkVteWFGdGV6aUROT0FINjJZNHl4Tllqbm5OZmVrUFdCYzZNekxBSE1vRURTT2YwUlplSkFTMm5Fdk9YaV9mSjFWMDdSd2RCdVNBenhsRFF6NW5KSE9lbzdNZVZaUDlCTUdPenBTNjBOVUotUHVDcHhQQ3VWcl9kaVpWMnpVMGFNSlQ4RXpzOTlXV2ZnMnlnV0lpLVFkQlNWaFNJOHdhWGpqTmFUM3ctYnltaHNPQVFWZnBQNWhZdXU5aEJJZkdqTndxU05FdHBpeVVEUXZmYzByYTl0blBZRzBsYzl2alE5OTBTcDJxQkl2X1lSZGpldkwzQmxiZlhJV3NQak0xaE9UZTMydllyT2tzcjJUcGFmTHBUdWZkRWo5eUZUd2FPRWt3ZW41OXRqSWJkcF9yQjFLZzZteFJsWHpyOE9UaXpQVVY2LW9nX0NaQ0dUazQ2ZEEwSTJVMzVpOVpuSjBVMS1SVWNGZjFhYkVVc0tCYUpzelkyYVdfNUM5SVhQVjd2QzhUOTlfOGg4RXVDUXA4SkNpbWwtUGJyLXYwR2ZSX2tkT3dCLTdrNjFWSTAyOGNBbHA5VmNCaDdmSGF1S2ZDcExTSGlwTzBXVTlvNEZhREh6bHl1dkhXQldPWFBTeENMa3JyOC00Rk9mV3hBTDdvTUdaVzhZZERSVWJXamJVWmRhOWFDZGcyY3RWSjQydTNzc3locGJiRktDeTNJWVNNMVZSVFJyXzZNYTNnYnZHYmJBZDFyaE5lN2lVUU9CVGZ1TzQyYkdSblRjeFBpTU5uNTl4MEtxdFNpT0VWc0NxSFUyRVdsbXQ1TGkzYzJXOUNfNl9tUy1RNUVZeEpPdkwzeHZvMGtZbGIwUWl2ZVRpclp6c3I3bG5RQ1UwTG8wUmJmMmFKa2lFbUNXbmVzRVJfcFdLV1BYTzNSTWFGX2JOTGxFVlY2QTVqdkRyRUxpMVRwZTUxYUowdDlCZmx5YUp1MU5RMUhUTXlESzFWeE1nbG5KOVRhSmk0Q3lCZnpkaWZrd09IY2U0ZzNtNkY4eDg0cXlTZDA3OVNkcTFIN0JnUUp2UzFISHNKZDhzcGdoY2tUZTZhcFROLWp6bk5MNmtMeDE0UFRFZ3dlUUtfbGpZVGdaU1N1OHhDd3lhVm51dFBveHItbjRhMEFDc0g5THJ3UUEwOVltTVczUUNaQWpuM19zTDVQZ3BYV2xNZUFtMG1DMnhWSUllUmlQd0JJS2JNWjdZOV9RLThRVjAzWm9uSzVjZzF0Tmt3cHNxSlNJNzN6d3RVNFBoOE80VWdQSDhpSG05M2g1YVJmcEp5M0VmR1ZMeUktbGx5MC0xc1djSFQ4UzJBRUJSTjdKSC14MWkzMHMtaENjdFZWcDQ2aF9BQnAwRldvS1BvTWJLcUhUTEVFUjd6NjZUdTNndFBZZHVBcnZYaEJ4NWY3dFY5UmQyTzBWWkNDdzJ3c28wcUZPQ0VWalhOczBneDFsUGhZUjVkck9MWG5ZXzFvOHBPbzRzaDVydUo3amF4OHZ6N2lia0F0YXNfU0F0RFROMDlfcnVFekhRc2RPT0FCVHpkU3otYWJfWTc1Y0ZRZldQMXk3aWJuSmZicWhNUDZCZzZaMWpZQ2hKOGhMcFNTYlg2R0Rkekg2d19hUzFHbm9FRHRkWG1EeVFheDRidjFzejhHRmxOZmIwNUV0N1BjNlZiV3VnbWxDRWhXb01NRzE3di13SU1RYlpDRkJpWWtubDdzdkpwRWJHNHlXYWdsLXRmNkFyN1psdWh4LUpQMHA2bEtRcnhUT3JIZXI2Rkl0X2paQ0ZSdWdJNm95VTJmUWFVUjFXS0RYdWw4VUJiNXNLX3dWZjEtNkVrYW9FUUlob0lIWUZnZ3lzYTd2V3h5WjE1UXkzbmhDN1YySkoxSEZ4YmJ4Z192Um56bHdiTERQTDB2andpWGV5ZHgxVjZ1NjZqTmF5czB4ckFmMzlHazRBYnRTcjBaQzV5NFRWdC1lZ0tHdDZlMnJIOW9jdGNCcEF5YWVjZDVDbUlYdXpRd1NSVEdyeUJSQzZmN3VyMDF2MDNuTFU4UncwNVJkalBVNjhNZHdBcWNGcERnOFl6bWNGWXBzek1QZ2NsY2dNZXBGMndudF94Q29RanZuVWtiYUNDakg0Zi1UNldQWENBQ1hoeE5xRkI3bkFOcFZRd3NvRFZ2MnBUY0owZ3NfMndkbE1aM3Y2ckY2S052UVlvQTdZbWpqOVl1RGtzUHJvYy13MlFPWnRibEcwYzFPZHk0RHg1M3hQUGlVLXNMcjM2OXZMcVRxcC1xQmhLa2xqendIQzhnalhMNjdXSVgxV2hSdE1kVlhER2FIU3JicWw4ZXFYdU9sM1dhc3M4QTBMZUN6dUlCZWFGTVBldjUxSkJneXp6VXVobm9rVUJUM3RjbHlzS2NiSkJvMUVibndwMHdVbDJOUW42RG5ybGFnd1ZaSWpxUWZRdmNHeVIwbGhiSGkxeldUM1pOLW5IUEp3dTMwb0Jjc0ZEYzBLQ0lxNHp2Y3RWdHZsOXFiZ0lBZmVJa3RFZWxMbG1tRTRPOUF4Yi1MT0trNHdybUVhYWNYUlQwZmEyc29DbFNZV2JtX0RobzlFX0doM20yUmVaX3hVNFFWOS01S2dEaEZsT0lOWm56ME1RWlZESW1FaTJfVW8wQTI5VzU0Mjd5VGNnVHhUSHZMSnpBQjRUQXp1NmlDcFlQVVB3SmdVMXdxUXo1MVk2QzJ5Y29KSmNZUTJFbU5XOUt4Q184LVlLNktSaWtGbXNhXy1qU1lPZmNMMTljb0JKclE5WGFLR3RfZnpocWdBRmMxWlBjbVhCc2tEcVpaSUVvTThsSGEzanZLQlFwckxKdVRNLV8taHhrQ2tqR1Y2eTEtbUExZWJZZ2txaHktWVhQdXUzcENFbmJDSUVseGdiOUQ1aWwzNDBGWHlTQWxiYU56TGtyR09Sd2NYZUgyVnVGMXFVNFBuRVNENm1nbjhURGRhTWZadmlvdjgzUzFveFVqRVBPemJlTkhzdXo2Z1JrelFOSi1uYlhUQm96Q0JoZ0dPN1plOHgzcV9wbHczQm1QN3QtbHRMaGRBMFdLM1FIMXZzRlE4dDJwR1pUOGI2V1REdGVEZnc2WTVUekFwbEhINXluaWg2VWZjZmUzeFdSOEZNUDZhOTY2TkppREJFbW5MYURnYWMzNmxzTEJsNE1ZcFljLWFwaXhNeXp0NThJY01aVG15VjJGWVhheGZnOUQ1bEg0TS56SlhmUWo4ZkwwMnFyLXBXcE82bXN3In0'

    __jws_sign = Sign(__DUMMY_SIGN_KID, __DUMMY_SIGN_KEY, __DUMMY_SIGN_CRT)

    def test_update_certificate_01(self):
        """
        Do not update if parameter is None.
        """       
        # test
        self.__jws_sign.update_certificate(None)

        # check
        assert self.__jws_sign._certificate is not None

    def test_update_certificate_02(self):
        """
        Do update if parameter is not None.
        """
        # test
        sign = Sign(self.__DUMMY_SIGN_KID, self.__DUMMY_SIGN_KEY, None)
        sign.update_certificate('abc')

        # check
        assert sign._certificate == 'abc'

    def test_sign_01(self, mocker: MockerFixture):
        """
        If an Exeption occurs in sign,
        empty JWS returned.
        """
        # mock set
        mocker.patch('authlib.jose.JsonWebSignature.serialize_compact', side_effect=Exception)
        
        # test
        success, jws = self.__jws_sign(self.__DUMMY_SIGN_PAYLOAD)

        # check
        assert success is False
        assert jws is None

    def test_sign_02(self, mocker: MockerFixture):
        """
        If Key is None,
        empty JWS returned.
        """
        # mock set
        mocker.patch('authlib.jose.JsonWebKey.import_key', return_value=None)
        mocker.patch('authlib.jose.JsonWebSignature.serialize_compact', side_effect=Exception)

        # test
        sign = Sign(self.__DUMMY_SIGN_KID, self.__DUMMY_SIGN_KEY, self.__DUMMY_SIGN_CRT)
        success, jws = sign(self.__DUMMY_SIGN_PAYLOAD)

        # check
        assert success is False
        assert jws is None

    def test_sign_03(self, mocker: MockerFixture):
        """
        If Key is RSA,
        JWS returned.
        """
        # mock set
        mocker.patch('authlib.jose.JsonWebKey.import_key', return_value=RSAKey.generate_key())
        mocker.patch('authlib.jose.JsonWebSignature.serialize_compact', return_value=b'abc')

        # test
        sign = Sign(self.__DUMMY_SIGN_KID, self.__DUMMY_SIGN_KEY, self.__DUMMY_SIGN_CRT)
        success, jws = sign(self.__DUMMY_SIGN_PAYLOAD)

        # check
        assert success is True
        assert jws == 'abc'

    def test_sign_04(self):
        """
        If certificate is array,
        JWS returned.
        """
        # test
        sign = Sign(self.__DUMMY_SIGN_KID, self.__DUMMY_SIGN_KEY, [self.__DUMMY_SIGN_CRT])
        success, token = sign(self.__DUMMY_SIGN_PAYLOAD)
        token_list = token.split('.')

        # check
        assert success is True
        # Signature changes every time, so check the header and payload.
        assert token_list[0] == self.__DUMMY_SIGN_JWS_HEADER
        assert token_list[1] == self.__DUMMY_SIGN_JWS_PAYLOAD


class TestDecrypt:
    """Decrypt test class."""

    __DUMMY_DECRYPT_KEY = {'crv': 'P-256', 'd': 'q9oqUvmn60v0xJU8FSCu__JpBrHcXLDxt2vgVUXMzzs', 'kty': 'EC', 'x': 'S1tYZTnQKtM5KNDNNmBfL3NRLyB_QV3jwMBZR-u0TBo', 'y': 'IsxOTEPzHeXSOQSHDEiStaw6Er-B5vrVvUntKRxZVLc'}

    __DUMMY_DECRYPT_JWE = 'eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImtpZCI6IjAwMDAwMDAyLTVjZGQtMjgwYi04MDAyLTAwMDAwMDAwMDAwMCIsIng1YyI6WyJNSUlEdkRDQ0FpU2dBd0lCQWdJR0FYS0NnK0hlTUEwR0NTcUdTSWIzRFFFQkRRVUFNQ0F4SGpBY0JnTlZCQU1NRlUxaGMzUmxja3RsZVM1elkyVnVaWEpoTG1OdmJUQWdGdzB5TURBMk1EVXdNekkyTWpCYUdBOHlNVEl3TVRJek1UQTRNREF3TUZvd0hERWFNQmdHQTFVRUF4TVJURUZTYjI5MExuTmpaVzVsY3k1amIyMHdnZ0dpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCandBd2dnR0tBb0lCZ1FDdU9TamlyQlgrcEtrZGlDSE8yenNkVEhPVzRuVGV3UWRnWWZHK25wUkoyLzc5b29pUzhQa1hGRVk5OGVDVUQ5WXlRdWh4S0liR0JiRDIrWVpHUHYxVENkU2hSdTBKK0x1d1ZxM2UvMHI2NGM2N0hkVXQ3TE1TanRTQ1ZQRjgyUlcwODNDOHJVRFhTQldvbmRYaUFIWWpyaU9zbDEyWDVGT0sxN2FZTmx2SGg5SHp4NlhDVDVsVU5wRXUrZmNBSDlHMStqMVhJL2dMY3NHTUwzaUoyTjB3c1BSMXJ5YVNWTTVKdnNYRTU3YWE3N1FrNnVON1AzUmJKbWcwaGV2WnA5c2JvTGtKZ0JpbThDRXZKc3FrRTFoaHVEYk5hQXpHYTQ5dG1Bb0ZvMmo3SnlzUmJKdEM1WGhFbUJFMTN5bDZ6Y1h5bnBWNTY5VysxM1ZWTUtteFMvMUVzZHJ3U0lBWk45QXdNUnZTcVhQQ24xWlBEM1hQcmJodkJrNjJueE1rSWZlMGJoNUcvUzR1UVVlanFxQ29GVHBjWFNWSWx4dWJFbU8zUGgwb2NwcDE3Mkt5N2tJM1k5M3YvWGpyY2RMUlFZUTN0WEExTy8reDlGNkdBajRjZ040QnJsanJJYXpSV1NjZDZiZUZ2NDEyR3UzQ3NLVkZDbG15OTBBUmlDeWozVFVDQXdFQUFUQU5CZ2txaGtpRzl3MEJBUTBGQUFPQ0FZRUFkb0pBeXVhTGIrd09JaFAvRlFqdUVQa1BpOXFZdkxDMGQwTEJZVFQ5Z1BScEtJWU9OUDZpR052cllZenJaQ2pOV0V6dExtbmJrRHlrSzlIWnNvVXQzT1p1M1ArMGs1d1VLMElNWEs2V0dQbVlLa0VtT1hEQUd2VzZUNHdPeGpMRVd5YlpTKzBDY0VtM1dEUFgzYWwzK3IzcVYxRmtZY3pENnM4UEl0TGNJa2w3UEt6R01kK0dVdDNuYkdTUW9HbkNhbkMrb3RLYlIxZE0vTHRjR3I5K3BJeEg5YUl4U2NMSWRLUXJrM0x2bUhpS3BBSGx3MXVhR1FqV3pRRTJxdHdaZlJJT3g2bkFrVFVDN0p3OFJERmpTaVFCZnlaREg0WXZGMFZKeEhCWHZEb3hYWklVejFlS1pmYU56R3NuQWQ3SjJCY25yemdEbk5ndnh5R2pmNFZsWXhHcHpFK3ljdlJKY2c1bE5ranB4ZmxiZUlvVE9hK1djd1lMc2gyQlpMTFRWdzdIQjN3SEFhSXU2MEpNU1NYcjJwcDlQYUsvUXc4VCt0RW5CYXR4bDJ1MzdWNGdXVUhmZ3RHMzhFZTVEem8vY3M5ZmRJRHl6WGJyelJHUEhtd0xhT1l6dFlVS1EwKzArUFdBR0ZFNFA2WHFleldXUDk1c2lnQjE3K0xBRWs4dyIsIk1JSUVTRENDQXJDZ0F3SUJBZ0lRZW1RTUNGVkhTN1NJUGxrbis0ZkdZVEFOQmdrcWhraUc5dzBCQVFzRkFEQWdNUjR3SEFZRFZRUURFeFZOWVhOMFpYSkxaWGt1YzJObGJtVnlZUzVqYjIwd0lCY05NakF3TlRFNU1EUXdPVFEyV2hnUE1qRXlNREExTVRrd05ERTVORFphTUNBeEhqQWNCZ05WQkFNVEZVMWhjM1JsY2t0bGVTNXpZMlZ1WlhKaExtTnZiVENDQWFJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dHUEFEQ0NBWW9DZ2dHQkFKL1dBZWpoT1lSSms2cXNKanN6MTFiWkxLT2YvQ2Y5WmlLWFVoTFdNczN4d1RSVlBlMHFtSDE0MFd4UlJlODFLMnNwRkVBZGhMYktTUUpnR21ENmpXKzMrQlEvQmRFbm81K1NuUmJkNC9Uc01UaWtKcUtjbzF0NkNpNzNEVTBwQVhvSHhLNWNSclR6QnpTdWtlcWNrOVhNclEwMEVyV25zNlhaQXRsUDNaM2RpTGpYdytNQ2l0U0tqTXpuSis5QTFEdnlpSmlFaFJjQVNhTnd6Ky9aN2VRM0JFKytoczZqSXVBZHRac0p2SE10TGJpNC9rMnluZjN4dXhYcEZibTFkTUcvM0JnZ3U5bysvK0pFUFBZZXN5UStSb21BT1IrVnR4aGJ1OEZwanVPTmdNV3liSE0vL2JXRGlFZThhQm1tb3hyN3ppWld6UTNWQXV0SElwOGkrQkFNUndqTVdTQnJXbzZkYWhiUmpjRVVKS2d4eEd6MytMM1l5OG9acnQxeW9uTy85VUVSMGF6MWN3dldnbmE1MkpWTERUWnhPcWZaWDN5RWRWY3U2bGpLbk5mVVFDNysycisvcEdjS3ZYeUVsTnQ0em50bGRoRDEvRXErUS8yL0NzZGcvYzNaUHowck96V0FiMEV4WFJ6OVhwcTRnQ0VKRTc3am5tMTBVYnBYQndJREFRQUJvM3d3ZWpBT0JnTlZIUThCQWY4RUJBTUNCYUF3Q1FZRFZSMFRCQUl3QURBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdId1lEVlIwakJCZ3dGb0FVdWdoLzU2elJ2QTcvU01LazVLSllHWXdJUGtBd0hRWURWUjBPQkJZRUZMb0lmK2VzMGJ3Ty8wakNwT1NpV0JtTUNENUFNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJnUUFQbWFidTVHN0VUK1JISHZscU5aa2RFeFBMNHRsbUVCdXpjQjV1TlVBNTg1RFNTSVlWc2tpTDJ1V0lSdFZUa2NNUWFiNVVxQ0JsQm9MYWpjVnRmSW5HS0dHeGxIcTNxL0I3YXQyRDJZWXJnUEdsZFg5OTRFQk5sR1plQm5lOEtkTTluUllEeTF6bkpqMmM4VFFEWm80Z3ZKNm5PemR2NFZqVHZjTFFJREFIcjB0TG5tOTNBaFZ4ZUNnK01RTzgrekxIak5TZXphNEpJOEpvb2xOM0JJaFl1eTROM1IxSHJuUHp6NXhlS21qMnVSelQ0dCtHbFQrZUpYTDIwZmFYc3NoNHdLYU9OMkR6S1pyaXFaQVFGRG9vdmJoWXc0T3gvaVQxZGp4SmU2a2x1TUdpMGdTY0l2WVIxcENKQjZ1cmdTSDlJRE0vTGVkWThPeDRQbFFrNWIzVDQ2WldRclhxdUFxMGF2YTF4UUUrUit4Nm5LNFZLYzdGdU1GeTlCQWNBZ2JmSDhEaVVWWnd5K252VlM0ODEybWN2N0VycWhVaGlXbWszbXBLY05FdXMxdDEvT0ZZOXA1MUYvSm56N01jL0lwa3B3eDBQZTRYcWlpSEJQOGVnejJKNEp3S25IbG1mOTJxNFFLUmdYbHUwY3pSVnk0Rk9FTnFpR2Izakg4ZVB1VT0iXSwiZW5jIjoiQTI1NkdDTSIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJrYVZONVhpaGhOVkxaekNJNnRQTHdYMXl0ZlRvdEp5ODRvLU95VEVEWXF3IiwieSI6ImotWEVJSDBXYUg2aGE1QlRPNXZ5RHlQYm1YSmhEMWNDa0JvRU9CS2M1TTAiLCJjcnYiOiJQLTI1NiJ9fQ.2bs2OECxY6JGxEGoTSy5POdiyyrarn97LgH9tmlXkKmN4Q8P9kcJdg.taDqxhJEbxSXccJM.r_Oavj1a5IFOH6WW9NLOrsmzHN6NTQSNK_gLIQeTwH6MzAfKnGQkXZuYH1CzfMRymU9aqlzpaoL122fU08_3c2GUcH3aot-NoSc1JMc-IVQC60unLLtIprPyexvIaBq0aIuFVrgtjt8r6_we9Rngp6-bzqDlegu7rv-QihSExkKbPy9ooykovt-RlmOqd_uLMhkP8mZuOyS2VZMHpe7K3f7UoCrudI33w34PuTMSMSSOQMO_LYW7SVb6-h9xAYmFxIlCEg7-Bk9ngPBywKZSv3IsSQSntoie5gjRlXT5eBs1kgCifA20uQWj8ap0fHzKfCS9ppe6JWtKpPPR30l6ApV7HIyg126DTRQ4wm-58WM1C7hPv6UCKtkyRTSEYbFFE1I7zmCDzizUrsc9EoPsjNaJ79rrvfpuCkJgaf3_y3HKxKh4EmH4pSgQNutQpYU7B2G11sS24MkvPxc_1nQf575l5laXttxnIl_UFdQDKUkpshJ-ncbvHhAi56wN333pqEGOVmSax7Zj7EoY4eC24rKlhDUrp9v0KJ0X0oLHe2DcNQuW0XOvehEdeKrj59IRxqEpUmI8VQFEmdJOpvTPiqc8ENTx5yQuSmDHEw2bhXWqUXU_SvZnDMoXozYlyMi9gqZbKdditsOifqVcAtOYKnixU-9EL2EAS8UHoBZVanx2laiHGJRGE1NpizwSPqEyE8BU-GD4sA5E5HUQ8sew_jO2lYiwtTLaXccE5s7Frt_JG99yA6MT1AUA0OxdEt5WmQVPx4xc7sRhKIBTRH8npAdJutjypLbMieYyAmHm0ctwnCblwwJY-r3ubgBLfoSerLiZJ6MTr8lIATPzi2cHNIUsIplaJqD_H_JlTi6Ygy8NDSAmHaFK1G-4AO4p5zTQBz4ohn42VgQqcD5aBs_dXgoFQrWnF-aCY1yy7NEOBmnHXDZARPyf2pbjnc-8LGUep432V1yavfwXFxu1ttB1q4I4B7JvIaGRESjwvZQhlhzzPirX7tLNnbvMI6wTfVL32VeiaI67uyx_zGw0Wtr5omsdvoIQ0E7pfEjAV3VomajFp6zzHEUGVb0GuyVZ8gm5VUKJPOv1G3TMuevaTQaPOO7-gDVfhLsq2O8ipyFkXDv_Jr66wj4OO0DGxQiqvVLAu9HV3MzH8V8NU0GqwQpfaUNaoLdAB0M_Vgoefd_xW70M-MhPwGdctsBK2F96gmoCyATXfq9Y1iOy1Q458AgV1VEsqxOJgJ-f8FhA8mMaTKCSyHxBSqHEtsfYDnyZ7VSitLjoU9O6Q-ZVcFXy3pD1AwMM1ow3M-qeSEif-b5aQ5de6HHLhEkMEfiSWfou3v7dwY8fXvfq8nUOMnnW2zu_DsyAKor7TDRh1Hk1fGXwz73d4-Iq30O6-SV3CNh8xq9ezzdeNQshK9yJualBdYs6qf5EmKiGvuzm3QEBfOyrLYjIm6hki5-JOIVRenTEA2XZmAkRTIC6ZHFjZcp-6yAvKfpHP7EGqquwUdsaJ3BAuMTXLHrRasZAr4BwRGp1_ED82965StIwDorClz9_CmIog9FwbDbN2AIoU-fff0F3xJ2JknTChoHX2umrpd0RKxnKneIPVhYjckkKvUCaKNm1vsOhc-V7WULFMe0dy5AijbNc25Pro8lkHA429n3eeyFMa-t1N5HkveJbcP7KVut5HuWjXau7BUoWPeA0KRg4tdq5_voc4X5y66Au_RAprNc6Cutd0MGurZW1I2Bbt_TR65qc__meeeK3EKwRfVQqlGY1xFLTBL_bFX9yRaHJnYFVd6-OUWkX4-VUKmGSRWSjvB_1Z398mKpHIoXib_GETBtn2qxi8gb2w41YBINVQi_AUxz0OwaeRKJ6wTdBmZnSgQjO1vGCtuKe7lYnR3EKrcc5b6DVp8LFjUjBnjyFmiHBiyVo1odxez6zoUGRoi4v2PVp7P456-r0wlHz3Sn0RuhJ26zC57Zm-fypwvh029VK719o1tVDNPy0EhjrVNEpQzMS7lw86RtEAQ1Tnw8auX_Xx4MDODercDI4MvCWCHJ3qr_aRj_44_FydlzfVqR7KgTVnAMqWNT_GVdLLdjafKHlAkYNiyVABiTvg_xJSFg_Ir7WxqtbbBRSGIUjh1YEvXroAsZMJu3vJsCOWJHj3l9s8VuCk1CEJT6_xSXzpJuQJWl4M3dxq1Rdp3JHquUHB6pVK2qPtLXTAZWbHtzStTho_BbzQLtzyGJUgzOmomPmqRBbfphniaXhg-gNvVTb-oAz7AhpeH0F8wtURULsuLkQ-5-LkHj5dbQ8EgXS06brcxhq5R0G0NRgNvXxzH6SVIbqqFMyL_ATibheO3FEtkBv5X5R5zT7zbtUjUvW9EFa392nsaYeOm1vL1zLqvVq2CpJV2WiaDBSywAMBAVQtYl8ltbIalVEUa7kRDpdri50Ww9wPhc6jM3Dp2kD-c4y5RgdwCqWtexSW5J_vRxmRSu0SSCfwHFcEZs04xAJ6cD0UXEpE_WpRWYpxTJ6Q2tEXf49tVQTvJ-ULrEHm8B4hv_0CzVC_B1ximgKinT3f5e2GBebv6r5hK2ABowrxaZnVxqPZHZpLnNzXlL3PI9A7yr8gDG9jFUR-D8JCXFp_J2WMU3QwaOxmtoPwdxPA1JKL03yPCtS1r4XqwwE8iOlQA2RVPXoRWL-ZVBfZfW_RiPoB1s07Aon-MdKMoF9y0PRObazo5Hyb_U_IFumuTMeL5c38kQum7yforTklmxrfzvGBN4ryw_tqizj2mzX2MNL63VP8WVYLgSxbt66aZOvSEWAXUE0THz27QO2Zw8nrDx2A5NhnXzds9pxUu4Ra1xb60bla2_zS6YBM5ieBwwjzK057ZzTdA6Q9zL2hffwrcmCmiQ8qIwX2B_4IrK_YZBteVZ7s-3CoEjBiH3GbcbflCqEEfLyO3zH5JIVr-pZl8wDHIRPXGgdJR2wNkD9Wr_jYL-ltoqe5S26POofstqrhpV1-A0VZF_tzV-tdAneqOLi1-A_nXhbTWBmI1WwZt-BLqGt18ZngL4ZhN1beapbCzt8lkEj9lKlWAk-AxVGVWfinHfg5JrUY2uuI37B-sKDAu4zsqnzybKzRP62Mo7h9kUO5WdHdH85OcXex6ER4FJm-k6Pw-gmvq6yCN1xarhYKP-oOU4MvD4w3JFdvJphWKdklNFdTKoYGTC06abYYAZUIikEmF8pTkW9paonKs66OebL1zSnJ_1tIJERDJDPobiR6zzXpjqBOMbDVHemvK-_WmBh0FuAycXodW8wXCEZhZP86jrRXLw2NnY6Mxl7FIkaZsskPHiYiOEfzSlqodwN4ZEjXbcHik5XKvl2k1LRci2hroDSfsLneQAwPQWcCA151YxYTlsnXv8E10AajKPaGAFgkcReW3t8rbCYBwuK1dJoSmAYyuzkUO_BfFBh_B2jjhe0iw7CRfvRMllYcy9LKZ3gzq4S_-Aoxtw6Py9CeDLGYfmPV6an6PUKZ3Q673PkzLa2HPz45ray9YLGbgitAx3QBS5Rcm6jvSQnT2nS8jo5Ds19udA_TblXBbGuvCzvEJ4kimDi5IJ38dKXXH1_RHz_GRCuzse8jV7lyYTcFjKwiBeetkgcXp-xY-jVaDBsBEwu8_aC6H7e7TQzNSa8jtlKVGe0AhIzaQcWFDt_88-3mB-LNC9Eh_pmn-2PAAwYqBDtMnU4-uZyL4GjFcLAv9iT1ASoWasLcwAu9uvSnfPEuRCGxbEYazCdmkd-NhuNMDluQ9sSRc-Rq3U2zaCTzyliS6QYKEZIaER16w2fIoNCmXE5yVYenzLqE7PXjHyIWZCpWIJk9xkdNg3nYmr3-KS5dSTEEMkwjtIbK2I8CxgObrU_cw_HEPuJzuRkbasPceyN6_iNM0-s6DneDE8HjgIq7A4jcGgJePE6c3gsTFQ9z3BXBbJvsJSroBrJxsMPehVLgGu_My_Uk62gRosepQ9nZdunVB4VJJOD4-C8xd0Xo6CjdyMRkl1BjSTWPbKYXKForODgKuKN60uHGH6JfxrdayHD3xFFeA-Uj-Ums1PWzwdGlwW4ZkXPMXemJ7dvJNT0WSQRReLMlVmwwlxn7u3AQyXPo737bc6e90NcvAQozExMT5yUzsSFo_poxVEO2v1IVeolUbbeN-lzI1sgpzS73XB1vKmYpyBPY4GTBRtb1Y1cU7bFxZORV7uFbIk0jrhpHHHW9Pz5KAOhxk6THLTnrhvy3lIWoGi_FvpvKKPzmSWVjIugx2ai-DTmpzpm9JzE36TvuwIPTHRH2Pe4vSS0XEwzuOy-RsKTy105CEXu1ehCzUDLYh5oAU93bHjB0_54XDsJw6PzzUy4iLEnY9R8HXecwIyx9d1PFL6xIzShlbCWQvh7WUDuzPtqbiBz-hCZBP64jtITDy5u1FKxTC2AKtGayGgwDX7fgxHn4K74N70j9Y4ZxkBHi_uQpMLkITEx8c1mLe_gPO3pGP4j4iqyhn3FxJGXVrYf3CIpTuVs-XZUHr-VMYmBpvFDtn-mRKxUfoBY_KkomFrTjSh2HCddoOnsEWB1dOD6gXy8CmhR-LaM3aBFX2EiFRt6WvK8xc42BxZ62LnwNPN3JaGko-WwoZVQVXins_UDV1v95wg9Bom34nu_uyF3D9_FeiXOzlawM06RqZWjlfVHNKmljFfhSWiqk2GGBbdM90U__5K8_xJErKdyHysn-rw1DjNM8Nvta9gLPw398Ca4decWueaWyalzXZhJyfmhT0Izt40v-3YpD1F1RM3inHfOH4YN_drmDq0S38800mgHSvC-v2bQaO7l_Cfbd5MU4YzL6D4kZfROkPBUbSV0-EmctuiUJGZ6cnqn8px0Befke2mtk_yiZAEK4SuXU4-doHcJDXd5m0aKzjv34W1rK06Yl7cCp4PW7Tjip-P8N3aH4kpGOLYlBNZvbuSXpoaAi-Ztg2RxAjS3u0wDchoQWPoGSL8TJKAqyZ321xQurw_zT-ZmuM7t9g9FassrgNQbUAi9soy551t9tT2Xp00KIAWFIWHtDRJQkTNa9T6XYa1_ySgb8xoOPQy-4E7UE9Is3qS3pbg4p-kiSV0jk3ILdiUJXf9A-GgeuSvZu-_vC7Wt-9YhLV8VeOzrJXsaFo-NLt-xLcz61FI2IJ1oVjh1W0eXyJi1ag0L5Fdt3XMPsMyA0jPDamq4o_45sJY8hK-iSlvqNIJv7Tp6SfdrSsIZQmHDc4jHr3W5xTYWA1VdFg6xrVlcrOqvGtTbhFPhUZT9uYjk4cRifrsub7UCaYuqX3AoTU1A_bpDpqNFE1IZI_qvIf9sp0tcXrNxbWsR0__jQOUnPgR6sxbBuRAQNo52hVmbW16zbSd32JizVSaWU-XU91Ok6imljDV-7TMraPi-r18ihYHSR6ZkFk8rWhWQK-CsXXJ-rpyXkJGm93mzeFxyLqU7llQMXfZAwIQQnQIf2goT7Vy3dAGdb-24frRKqykC9lwxBtEgofYYmjQuzMPVXrIPUwW2EJLsSlEmQbGpDkW0vzBa0ONi4e207cCzQSVazGnkPxVEUjClG2fxwWeEzUP9faDYAYOIjCan9WU98I8cGkApt7UhgH2zvdUSimRrZAPkPeNYdTCcKrOW4Eq2Eh-j8od83Dsi0TPo9c2qySNs5E9a67db5ZAEp1ZBGdv0PhJVqaU7gp-SRZoH_OlgaAfXjcLwmhX0TAPyv7y6jXPeoexXoq0JW_4KoHQfF15C5qDFRTXiPsH5c7sQLMhs_cI9KJAdIM4OgxHlXb-bK0ZCICWcfiZhrbCuifuMWxvCpaohPCWwqMWHnaLeqrB7YixvVAoC5zy0YjB30RPY731nIcKw1x0xF2OvHA1-gJ9_wghkMHh03H3F0hVRc7vz38xE-GOmcTZELDvzT92LB7yEjxEMY52GcFjA9ssr78vW_zlCOtg6-C1sM1Jk2sw4uxkxSpxUUGktLdtzHntgPkagpP_CGtvOTlwJDss8Ou8r7XMececs71soSq5zDjAfoX-TRYUWBLVbjLzP8svLDsp28MTKUNDuSWIe6d_idvfWZrve27Cec1gESiRBW4EDI98P1wIZz7Yl3dQXeUVstplh4yu4BLnylPuggLqhBKSThBw19k82D7DdsmGiAuXwfFAEiThV6zE0LJ8JjFnnM6hjVZjejlu-fq__n7m54m3a2V31TsyNmiwcOpe8NgDqBwM7HHUimnyJxxcNLm1p53rl22nSH8M2m_yEfaYi3Mve02MeJc621EXdEssRi9axiyVzy4G77TqO1yJjpeeLg20U_2t6KfBzDj6BJXfQ_l2J4Nd1gJqzBPzoHgjzii0qXxMsziOGRPBs7NndtIgwLth6BBEWepe6_-79nbNeVPKM-nL0Xs8texjE5FnGiHDhrF4-IL5NaieOV3OU1GF1VafedPkRb2T5Uu0NrSOt-LAakLD0tnk2ZnMN4AJX3Dd9cxsXMHZKvXqutr-vAMKp_JxSog4TDkHh5_XtLrJGafjvMYPJ-_vkCUT9hl5-GadGWhhGXrrJtmIXFM79mbKVA37GgiI_sxyDI9QfThV-qDpjz3V_Qg45lbkLcQYzd9LxkLAlZZh41vjcTmGj321Ge89WCXvfD0OuVsOjrhLOPgBGekLc9y4IjQPWZpAQF62qb9zlOJTUxw95-o8p66XYni9oJ5fIoFvAal5Q3wFGspkrE1tU7SWN09p2MxKe5MEz02G-0LqZzYunZg3K0x8Wgr-vZZWuPf-1hBEEUkw7qIFG7jl7gLblMfVoObSvz3M2Je1Oj_IiiAsj8_LNh1xKy735rj8m1LxFu18jDyrcy5C67IFGToQwbCqyffr9OYAKc16Cj9R_co3HD9y8hXRfqq0CjkzkyD04dgshJ6onXNzt3PBmnv765VJxRnEYd3myXpAw7HihCJMnzJeDfrShTlwqEJSTp9cI_rml7D5983VazLUUFy4yaZeTA4Ric-Kdse6eZRHgdDFuPrTotEsISSAW71wBSuKhsW2XsJrc1NFnZljJVhp1KFVvAYVp6q7lacj-jkHGymSLgRtp_S5XRF-MKVDWr94fv7jGzYQy6xPgixLP-LoTNjhbL8mt0atL7MEK3A5WevJj437w6wvgQ9T9mtvFi0w3bkHabvU1u1YhgjuNmjTZ6KgzNVLyq4ZH5XawZ2CtKDaX1pE-uiiyQu15KOiE0-FcwsHZajZEoH4C5zbMHNSsjp_n6uKMwZE0Cg8x6oCaTSFicgPcY85HHrCOst6UTwEi_eJdVvQJYhCC2KNaeahubQuZvRY68VcR-26Zr4qAdQMXMNj6XqXnQjpx88k0pS5vdkRKjF6RgrpK-u7akYSAQTGPCsd6hXPOUWKpSA6-vqjeqzj6OHVE-ehapTPdsQ-tlqUfMdsOgFyYUIBOQHOV8n77Vj5I7SnQYkdV23HEXa0lNYmlWD1J4j3hACtcgg6JrVOA6RxAIPD_nOh8lLYVUdGQm3v1CDPMHUtd4iEHKVUwkX375EOd7zR3G9wh6BYlFdDT2r6s7TSdTRw6MLwmYf_D45e-3AiB_f35xOcRlWpMVRnXLSn33Kam4P8NPIQ8GVCWjU95cSubar3muOVUdjcX90xhTmUl5ECmmvepCYIU34yTviJWg2XcrWXc4tGoBeVYtoK2uFnD87OQk0qOB_SogSWCECnhIIBLCDLT-QugXbchza1NIYOucNI99rAuaI34LSNySL6yXPjBP32LsHKGClMDqpl-KmabBwYlB9UI0tgiRaFTvDMlD-UgtTKgBu3ndikcGGl8QoBpdyK680uT6_iTCJ8Hz2ZKWUuFLj3G5CWvrjrfA0uofsLuCo8zk8KeZ-GvRGpzyqnonbXndUqf464F-lJGNpcgWXfkXAxm5hm42o5oJzMrkzUei1eRSZRXtWVv-r5CxmdmelffN4NZeqDDB1c1V8xCnlOLB2FL169li2Ge1mLfWQ4cao3EpnPaqSXfwuhO1yg3kEYLdnJ6I8NevgwsgxjCsSrA372wKjXT_u7f4OAS2rW1eBTZjcXKyd2I6xhKwPdnTrHpGdF1Dc-8WbhWJSfoWvAt-7ZYP8ca9DVOQlLde946zo8IIrKbt7GtbxN9TsfiyIVU2CfYXoJHQDwtkBJZ3z6g0e3KALc1KJAVTRYzGFJELHdjVdCM44RNXU0qnpJKB3Ax6wVVp13-axgkkJfzdf6Liy_U7hE4AfpfNnkvVlffvVFp96NxilXzOIvuBqO8SMpv80Cg1ZYbdyVXD9MPeRKK4OVeiLxEG-PvD8uX5bZFJ0bYnXJ4LcKqwqOsNJLy5uT3YuLU-j11CFHByEMtpk7wWhddjTTnu4QUxu4qY1-Ry3U00TdiWL9mlQ6ho3FF1QKIh3ZiVAi3RkUoPURYkkslwual4X6a_4vP83gALVoN3LC0_2NHWBGHR20M1FESotQ_k-wF14wP98oxxpt2tUh1Kzzz9tb0YcIOvOFSFgApp0I7LRlD-aX3LUpOemeZudSUk9TCrvT93CRSgASqHuJ3f909VbEnGHktPe9Ok-9-6lzk6D9-GK5P2WwBPnTIrIM3tDyViLc1FT26aTZTxhuVn2yAL1htu5qn_rvdFW_uLixfNBkU4Fxe1BRHkywavULLBNUzldxmDwnFQPOjpgXKetyBVe-1RhhFuKEGCPKFo47qTFDT9e6jz4iDbhVOPprEPGG-wrD53CDyJ7LEoLFjVfeYqpkBTeH7ogDJAQPtxfIDZi6vojr2KsoRiQl47A0tzTlwl8g0yE0d0gO-rVO2dHygelk58pc7Viio3sRO1dvqAxslWVJazE8b_Knf9x66qgnqSPwqPSJrq5xGnLeVhO1x7rVncWplStgEb1ktH30JmBXhmVyzWqI97NWIb-9ysV7h7yy2b3UIeMOYO63CHvmB7FYGTuHz_uMWliLNuD7NNI4aan3M6SCEYjlzRB2IbdLZVre2WraBF1cV-sVoKuEzL6ldWPvtdBUL164PJZSL4QaHjgWlgIIh5ML4LQj2SCtWav_mjwhX0XG7xGAyoSDFFpdiFas7-MpXCXvAuG_hLf6qE349G7uEGUpefMqx-T6kMMm8haPb_rlP4KcUIoXSNA_1v3GEeL_hG-IhIZAz5FN2oUoPE7QFBuXJSFfMK17Fj_P6WPv5QjX0WBundwaEri4koHivNW8tomyHeE7C1A68bSowcwZyhEka7qJ_MRQ9isP2MhDRL4x9Z1d7ce0FPfnozKp6-E7PvKLJsw5Hu1k1C6-j3uGEs8FmPYcLgYJa8F7G_no84qyPS2l_CFKRuxQiv3xJtjdFihHkLNK1Bl1XXzMK24MS5AyUxxXzqJwImm2BfpDfuc5sN9LBsqt-H7KB4SjaB0xztB_cIeExYWYHSWnAK-0--mxUCLyR401t-VmNzpJJdKZ5j5xculeUXZLpONpvN5t8rB1ZT_rCte83MWZZ1RvYLJaOyufuKVvLee3ZTimIILW045FXd6cezK3HX9n3Tighkb833iPVlijJVw-UKtRTqAow9S3hQm4gtGwCORVjl1Urun9tMf4k0O2JAbUj8ijKaJc-evopL7t7eGcpkSIwrsLaVyVCL_-5ySMIHSSdOPtehnL6QBmkiL3fQxwcVRFASuSYK3zgEelEuGfXTdm959doW1ZlHgwpZd3IuWzDs0KPYfswL3aaTjqdB1gLWVIz0oXU5GD8R9XF0Pmf6jo3ksGlRh8sz-c3CyrYFk2ReCwhFiwOZ8hVAUCDNY-Bfi7Ei7t1tJm0dJ7OhXPWkS7QBraUT2gx3HHX80CLywjhex89xm7YaL-fWQddAtCamBSgd_TZtyS_isPjL4aDHNi5W1rgQbQlYsts9OtjHTSmB7rCACHxozlkeWy2N03LZve15mMrJ0r956R14C_rr-CPadb8aHRw7lIspxTfJ9q8i4X7Wt35zYd96x4I6SH5YiiP1vzfvYxPES_zP0USYJlegnHbPxBZx-uSamtuLxADzuWOtpXUmOPvn_3TFJDR1lo7e_IzNAT5pUsRtMybIek05KedL03dbSdnuIckvujzX_VnELoyHJy50QIkQEpQZ6QroZAkCN_9y-WeCKwt06YpmKMlJgDAmaEFf52U1zba1itQtMIlCHCtH2Jlv05Ium1HniEDxR1NRsZhMVNTOsYtoGOOyDRG2UxQrti47OrVZaA8bB5MAxqYSABS_AlGAre_AKJOpG32-ycq2DPV0hQ2JaHhYPMymrb-82SJsejD9sZF0PyrJrRx-ugYt-ytM3tQQfb4hi1mmfsYxuZcjZmDeL-1cUiE0FiDoK5YFZkRjxVOVVll4K314EjMnsPc9zSFkZaOD6JZTsBt7dn4st2uQcrW8tjauBV9Vf2-OlMHoDUcY1ar1xcj_-_Z2UED4T6ugTDZzM6roeLzRw1kyEWFGa0oRX6p817GP39AoH3ty-JJDF8le8vtkmCOUbXutg3zi7qUeZSDDc9RXoSCA9Dp5de5PDoI3tjEjnBTw2qdg8QLjKQpKaXtut9Xv5fIGcR7YN6syWC1gMqWI48rvYs-Ez4Xp8B3fYsj0Jru4RzP7ftprukUXicA5a1lMf2wXUP9AsWea2tl0hlq2PPWeYzC_0f2mfbdmvgP9pc96uYYaKZNlTDPERnzUrk-Q2iVbTV4hMlDAKXfRFF3-S22SLQKLkSqCz4t19XHiAzFWuIBQ33fq8SMnEpI8sOFPcz5L2MEVxFgzkMEsOjA1kHqWcA1QLBR_erY5aMsft2gp4Tdyr8v3SO-ofHuYT4d4lSYCiVP5UOYNEy2Bln7l8h1bK3lUYJoA7Hx6MVXgo700ly92g4MhQFS1oFqfY24HGt-O2CAhIVMKDeZkatmBKE7nICK0rvUQ2j0gvKKi9ZwR5s58-_Vo9NmpaJ8jGrVul5T21GW_mJf55VXSooTPJafX0xHHaB8T_F3xLrq1L0gS5N0Ls816YTNBuE4-IuqaMheObH_9CGI0owc0KMobtKXN0POQD8qafd2-QvTzB1LUeDWyj_lNN45g4yYcGJEf8DKXcz8SxwhjoSfZEkiJif-TxB3MqO2KFTtYkhwAkDRHXvL9OHEPZNKcOGS5Ifsd32KeelD5HJidLaXxXplow5r9EmLPJ-RoJjq2aI9kDYqBY9S23tPBRzz44P4aWF84qizg2429ALE8XXnB3_91CeevyB_0Zi5KtgZ17ooeez4Fv3Kg1ql-9IkxSp8MO-9wUQcc0cZSh7KabqA0pNnDYc7T-b7pOw4E0xez8zyiPycO3TswVHQ2iHMF4gUHv2SfRoJABr983tSxOfdZFAbqNJZagwJbhUBawjo9xLe4JPG_dqNzhXz53An2qln0xw10jgWiLA-wTQkJOHYOqK3F1bYUMocXz6Lw_Ifw9rf9w4PMyUEAg2JS8z8rVuazBU-qsxEbv1qzBQ-o5rRi2t8gAhgMXTd9DNfuI-dYuI4Atzxfq3D3wGVsx3ZPI7NnOk6wXdes-SokWlaiHFnCEmnY3RBN-vemz7MLSEEK6ov_Jlpl4ibGPswyv_p7veCDX1SdU9EuZl0I-W_F3nKNljZTrQrjcSb6OVW3aRxJeLjzwY1CtvhrQDH_ZPh5l1XDwvCNm5TcpAYnSNMPN7lQXYMev72GkblaLf8QBH24roK77PoL2ovBnMQHRImNLd-kFSKqKUrX4Bg2VGlBac_99hUQzetrAN2TMkxcdz76zLRO2YXK_MKuUnHvH6oTS8hpWFR77cmoDAU-F9MlWlxdgqV6Cbn8mtHa80AVH9nm_VZwQF20xXSr3yxYc0otfoQ2WHIGKOQDhhbQBr7_gmJ8KsVdMAwz3XIdC8RYC8YtSRl829LB68ci2F0GY6GO7KjjzmlME_wj8OtLJbNM3Q3lD3p_Rn_JwUBYD2il4ACt4ln-odSszDlKdSxZC8UKx2hWVBh5EQXkuFgRljja4i1ppQzm6Z3CZ0jzaqC9c65lLTUy4lDHVcta-lFyXb3_XjFNA4G_47bll2N5ZgCaM7wBVUr4cMrI9-eQrkbhf0kbMbRVSDA-L-pldhUQNWI8Z4CjbQLbnax8CZUNFKASBieWJDYUu-kUAsRK0GyNpF79m7OGuN2neBkDfmsbuywzmaJFD7_LWkqsQE4x-iERgn6NJKuC25nEIui71hm9yCVR-z9yhL7AHCVJKcTWhJf-WlUjdUics04xMT_X1VSjgIgcK7gbqV6jNiIRgIo-Y9lu-e-MBruIszB2b5-Tkr1QMSpfkOi-D_x-XxfxEWYm5kIt3J8nqxj6MSkwA0X9ucxpnIaEi-1--UL01ral7s4ke5Aa-ZWeNSvg9rB-MVG2jzenBzLrNKQVNHBA2fehs527RWpsj7acq_svCWlPKRtdtJR1WzV2LKtO2L8Zs4FQ-XVtItrecOsdee5hopV-U1dnq-zJuwSYZs-7LBnn13gpR0SP7BJlab5eTKI1O0dTHtgEG0VlwYwAQA6uW0DkvIk7QU7iwDA8uwwJutEJmxWYbsKu9EPpN1oBWaK8DZg1Bj8zr95nkNqdJd_WdBx5T8y01ZyPaP-Ar4Nbh5O9ELy6XaDsrVX87MMM3hmDmlh8ENnFJGH61qEOrjYs45-W5VxQ8IPJK586ftkJ1S8KMiwqJ22VmQRISohUfE71VsqmuyZlh4--KIuCo9sA0H8nrfvmu22W8BX21kNgcpv5RJo1zx9ERn8dHmzQ8feN4sOSpUmspX6DGS_Y6syAFl6Drj8xQCYkiycflC6oqQdYMsHOtrJGoICB_BXC9mybnvM7YMZOJGyS9krZFZX_mlIv3aRGDLU3ckSWTIebONZYbJas3sdtoxRhFRqqWsKZ87X9kPFN4ZxlhtprZWMwkBjdKmTTjfOyerWKif-3KKh8BOwexLBDmLveo421_lcEASehREfIH7SexI3hx1PJGyKd3HBNIFaDY39PUngLn1PvWVWBvcCXa7FXdN8PufmCn92CoerteUe36o4B34-fN6Cm8uRqdUQP2aFOCKISLq1hAlYDGzNnT8RvfjeC_AmLV9UFJT_k9pa5-BJIue-sfcq_8dIk73H_4WNhkqIOmFCJj1SeY0_ZCkl245-5_27t1qY3QypUuDgiFkGm6M2H8IqKKV4b9gwY9cgyEnkFudxhPblc0xj-OpQB0W0FuG6Ngm1ypAq.yogbOpDRmVGBzBw-ItUJhQ'

    __DUMMY_DECRYPT_JWE_TOKEN = b'{"Payload":{"Body":{"Version":"1.0","AppEndPoint":{"NICEIdentifier":"00000001-5cdd-280b-8002-000000000000","AccessToken":"eyJhbGciOiJSUzUxMiIsIng1YyI6WyJNSUlEdkRDQ0FpU2dBd0lCQWdJR0FYS0NoWGdBTUEwR0NTcUdTSWIzRFFFQkRRVUFNQ0F4SGpBY0JnTlZCQU1NRlUxaGMzUmxja3RsZVM1elkyVnVaWEpoTG1OdmJUQWdGdzB5TURBMk1EVXdNekk0TURSYUdBOHlNVEl3TVRJek1UQTRNREF3TUZvd0hERWFNQmdHQTFVRUF4TVJRVk5TYjI5MExuTmpaVzVsY3k1amIyMHdnZ0dpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCandBd2dnR0tBb0lCZ1FDaTJkZ2hQN3krYlA2dHZrSm1tUllicVc1MFcwSk5hOUo1K0QySW1mRksrN2lwTXorRzQ0MzFieWxzUHlmdEl3amhEdkMxTWVobDNuV3dUbUtJeEJHT1ludUliRWt1cVYyLytKbWpDeW1qZCt6Z2E2SVFtKzBIZTJ0N05JcjhwVDNnMnJ3amYxZGJScllNQ1V0RENQT1dWY2VCREVuQ3FpMHUxUkpCS0p0aDZlc09UR0RVckF4MzNxVjNhbXhUNVgxWlpmSjZKZ3A2KzBsWTkrVzl1bU0rako5a2E2bEtRczJVL0g5enI2ZlNmVnZjK05RZXdwdDNMNXlRa3VuSnlYZWw2alpWcmFVTUJhRlN3a2hQdUVCTVNEa0lSM1ByemlNOFIwM0YzSEhDdkEvS3E1Slg2SGxqb1ZPTWErM2dnd2lXNE9jQW1ybDFxbXROZDN0Z0JLZHVsN1E3M0lZYjFvUTh3NmRjbWZRNUsvbGlRVTZIUkVGR1Z0UHRteG01ZWNVZncxbC9aUDR5R0JxN1ZYaUJnNUlkZ3RkSWJXaytuSitJbjQvMWtsRzlUZ1BqdWIvcHBGT1BCNHY0cWw2aCtnZkZaSjlhalplOHJueVlLQ1l6SFhEcENrQzRuQlprcFd0KzBrY3ovdDVKVm56VDRKZTB6b1Q5RVhKWUR6dDhPQzBDQXdFQUFUQU5CZ2txaGtpRzl3MEJBUTBGQUFPQ0FZRUFtNC94bDZ5MjEwYytGS1JCQ1RMeENHRG1qbkc1SDkrQ1QyVnQ2K291QkpuYk42UHRwZ0kvNWZTMWRVSmNyUkpGZkpzWjNacXlyVG1RY20xSU5kdWRaOXk5RmpEUVJmTkhjM2p2emFGazZMRm0rcUpQYklvUjRLLzB0d2FJUVFQS2w0OFdiZExBaDNLeHZ6NDl2Uk1wbDVSTVZFMFo2SkYzWWh0eUJiZXIwWnZuMS9KUE43MGgxOHIySks1U0hpTXBKMHBET1FuRVptQ0ZnVjZkRzVXNkVyRjVjV05saHlkVEQ1dTZSY1grYmFBdC9JSThhT0VvQW9kaGJGS1QraTRRQ0ZHbnNuRGlmNFVyUXdOWXVXdXdhK3B3QS9kSVRSbnptcDRUelN4aG5paTdBR24wWHV1WFJvTGZtMHVDUDVBbTREbUkzRWJlZi9NdXRxUERidEk2U05mRllkcDArTVJSZ280R1NtUlVRdHMvaTRnUnRnZUFhTDF6bGdCeXNhcGNJeHR0NHFIVS9Zak95TmhKQ0hINXM3SFVBV0Y3ZGdtWFN3amtoeG1EU2o3Qkk4NzJ1NmJZd0V3VHY1T3F5YXN4T3JEUi9rYjdVSnZPTFViMSt1MnhGa2FlTnNRSkE1STJLanYzSmlEL0FVY09CeXlBWWQwY09wc2NSWC9nM1dNYSIsIk1JSUVTRENDQXJDZ0F3SUJBZ0lRZW1RTUNGVkhTN1NJUGxrbis0ZkdZVEFOQmdrcWhraUc5dzBCQVFzRkFEQWdNUjR3SEFZRFZRUURFeFZOWVhOMFpYSkxaWGt1YzJObGJtVnlZUzVqYjIwd0lCY05NakF3TlRFNU1EUXdPVFEyV2hnUE1qRXlNREExTVRrd05ERTVORFphTUNBeEhqQWNCZ05WQkFNVEZVMWhjM1JsY2t0bGVTNXpZMlZ1WlhKaExtTnZiVENDQWFJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dHUEFEQ0NBWW9DZ2dHQkFKL1dBZWpoT1lSSms2cXNKanN6MTFiWkxLT2YvQ2Y5WmlLWFVoTFdNczN4d1RSVlBlMHFtSDE0MFd4UlJlODFLMnNwRkVBZGhMYktTUUpnR21ENmpXKzMrQlEvQmRFbm81K1NuUmJkNC9Uc01UaWtKcUtjbzF0NkNpNzNEVTBwQVhvSHhLNWNSclR6QnpTdWtlcWNrOVhNclEwMEVyV25zNlhaQXRsUDNaM2RpTGpYdytNQ2l0U0tqTXpuSis5QTFEdnlpSmlFaFJjQVNhTnd6Ky9aN2VRM0JFKytoczZqSXVBZHRac0p2SE10TGJpNC9rMnluZjN4dXhYcEZibTFkTUcvM0JnZ3U5bysvK0pFUFBZZXN5UStSb21BT1IrVnR4aGJ1OEZwanVPTmdNV3liSE0vL2JXRGlFZThhQm1tb3hyN3ppWld6UTNWQXV0SElwOGkrQkFNUndqTVdTQnJXbzZkYWhiUmpjRVVKS2d4eEd6MytMM1l5OG9acnQxeW9uTy85VUVSMGF6MWN3dldnbmE1MkpWTERUWnhPcWZaWDN5RWRWY3U2bGpLbk5mVVFDNysycisvcEdjS3ZYeUVsTnQ0em50bGRoRDEvRXErUS8yL0NzZGcvYzNaUHowck96V0FiMEV4WFJ6OVhwcTRnQ0VKRTc3am5tMTBVYnBYQndJREFRQUJvM3d3ZWpBT0JnTlZIUThCQWY4RUJBTUNCYUF3Q1FZRFZSMFRCQUl3QURBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdId1lEVlIwakJCZ3dGb0FVdWdoLzU2elJ2QTcvU01LazVLSllHWXdJUGtBd0hRWURWUjBPQkJZRUZMb0lmK2VzMGJ3Ty8wakNwT1NpV0JtTUNENUFNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJnUUFQbWFidTVHN0VUK1JISHZscU5aa2RFeFBMNHRsbUVCdXpjQjV1TlVBNTg1RFNTSVlWc2tpTDJ1V0lSdFZUa2NNUWFiNVVxQ0JsQm9MYWpjVnRmSW5HS0dHeGxIcTNxL0I3YXQyRDJZWXJnUEdsZFg5OTRFQk5sR1plQm5lOEtkTTluUllEeTF6bkpqMmM4VFFEWm80Z3ZKNm5PemR2NFZqVHZjTFFJREFIcjB0TG5tOTNBaFZ4ZUNnK01RTzgrekxIak5TZXphNEpJOEpvb2xOM0JJaFl1eTROM1IxSHJuUHp6NXhlS21qMnVSelQ0dCtHbFQrZUpYTDIwZmFYc3NoNHdLYU9OMkR6S1pyaXFaQVFGRG9vdmJoWXc0T3gvaVQxZGp4SmU2a2x1TUdpMGdTY0l2WVIxcENKQjZ1cmdTSDlJRE0vTGVkWThPeDRQbFFrNWIzVDQ2WldRclhxdUFxMGF2YTF4UUUrUit4Nm5LNFZLYzdGdU1GeTlCQWNBZ2JmSDhEaVVWWnd5K252VlM0ODEybWN2N0VycWhVaGlXbWszbXBLY05FdXMxdDEvT0ZZOXA1MUYvSm56N01jL0lwa3B3eDBQZTRYcWlpSEJQOGVnejJKNEp3S25IbG1mOTJxNFFLUmdYbHUwY3pSVnk0Rk9FTnFpR2Izakg4ZVB1VT0iXX0.eyJWZXJzaW9uIjoiMS4wIiwiRW5mb3JjZUVuY3J5cHRpb24iOnRydWUsImlzcyI6IjAwMDAwMDAxLTVjZGQtMjgwYi04MDAyLTAwMDAwMDAwMDAwMCIsInN1YiI6IjAwMDAwMDA5LTYwZmUtNWUxNS04MDAyLTAwMDAwMDAwMTk1NCIsImF1ZCI6IjAwMDAwMDAwLTVjZGQtMjgwYi04MDAzLTAwMDAwMDAwMDAwMCIsImV4cCI6IjIwMzItMDItMTdUMDY6NDQ6MDMuMzkzWiIsIm5iZiI6IjIwMjItMDItMTdUMDY6NDQ6MDMuMzkzWiIsImlhdCI6IjIwMjItMDItMTdUMDY6NDQ6MDMuMzkzWiIsImp0aSI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA0ODAxMTIiLCJQZXJtaXNzaW9ucyI6WyJNYW5hZ2VtZW50Il19.SonLgVSXtDR-PrDPC0TtgJ1CHya40Hoc7EQMMOORLOYwdMZH6pwUU42Zhh_VcdJayWnLDc7JJyaIte2xoF2FB-AevPApWHSUNKbIHasOYF5RMDAZv5GIS-YFymPXE9rLt42WB0_lmO7S_zsAFgBdriVjEk3D_Tduf1Frgem272jJAS-2DS6HH-ZOmqXy97pcbhI4pjza69tYDG6eMq8qwvClYi3G5fn92_nDFz31e6ch_VapCu9NP06wdiIQKgnc24JqR53788gslD1BhUymZmQ-Op8F0-qlYUjW7Hfy264YnCwSQAfTwn9bs0VGCYxfmCLAZx8qp5FnZKAsg0ezbGKzv7OqFF5GWorSdO5hFQOg91b3q7dmwopzfoogjNvKFRnjeZT3ovyPT4QWNgfgSpwO7MytAsSBBHYRMSrmcEKhXyYsSb49ZCb1qMuuNyAPwAEJEZ34YJxulD2y_PWCuHLSx4bCOr4am3At7JokOjjN8XyOcJ5ywNfXvKRrKBuP","X.509Certificate":"Certificate chain for the NICE LA that is stored in the NICE LA DataBase."},"NetEndPoint":{"APIVersion":"1.0","EndPointID":"00000001-5cdd-280b-8002-000000000000","Scheme":[{"Protocol":"WebAPI","Authority":"nicela-prod.scenera.live:3001","Role":"Client","AccessToken":"eyJhbGciOiJSUzUxMiIsIng1YyI6WyJNSUlEdkRDQ0FpU2dBd0lCQWdJR0FYS0NoWGdBTUEwR0NTcUdTSWIzRFFFQkRRVUFNQ0F4SGpBY0JnTlZCQU1NRlUxaGMzUmxja3RsZVM1elkyVnVaWEpoTG1OdmJUQWdGdzB5TURBMk1EVXdNekk0TURSYUdBOHlNVEl3TVRJek1UQTRNREF3TUZvd0hERWFNQmdHQTFVRUF4TVJRVk5TYjI5MExuTmpaVzVsY3k1amIyMHdnZ0dpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCandBd2dnR0tBb0lCZ1FDaTJkZ2hQN3krYlA2dHZrSm1tUllicVc1MFcwSk5hOUo1K0QySW1mRksrN2lwTXorRzQ0MzFieWxzUHlmdEl3amhEdkMxTWVobDNuV3dUbUtJeEJHT1ludUliRWt1cVYyLytKbWpDeW1qZCt6Z2E2SVFtKzBIZTJ0N05JcjhwVDNnMnJ3amYxZGJScllNQ1V0RENQT1dWY2VCREVuQ3FpMHUxUkpCS0p0aDZlc09UR0RVckF4MzNxVjNhbXhUNVgxWlpmSjZKZ3A2KzBsWTkrVzl1bU0rako5a2E2bEtRczJVL0g5enI2ZlNmVnZjK05RZXdwdDNMNXlRa3VuSnlYZWw2alpWcmFVTUJhRlN3a2hQdUVCTVNEa0lSM1ByemlNOFIwM0YzSEhDdkEvS3E1Slg2SGxqb1ZPTWErM2dnd2lXNE9jQW1ybDFxbXROZDN0Z0JLZHVsN1E3M0lZYjFvUTh3NmRjbWZRNUsvbGlRVTZIUkVGR1Z0UHRteG01ZWNVZncxbC9aUDR5R0JxN1ZYaUJnNUlkZ3RkSWJXaytuSitJbjQvMWtsRzlUZ1BqdWIvcHBGT1BCNHY0cWw2aCtnZkZaSjlhalplOHJueVlLQ1l6SFhEcENrQzRuQlprcFd0KzBrY3ovdDVKVm56VDRKZTB6b1Q5RVhKWUR6dDhPQzBDQXdFQUFUQU5CZ2txaGtpRzl3MEJBUTBGQUFPQ0FZRUFtNC94bDZ5MjEwYytGS1JCQ1RMeENHRG1qbkc1SDkrQ1QyVnQ2K291QkpuYk42UHRwZ0kvNWZTMWRVSmNyUkpGZkpzWjNacXlyVG1RY20xSU5kdWRaOXk5RmpEUVJmTkhjM2p2emFGazZMRm0rcUpQYklvUjRLLzB0d2FJUVFQS2w0OFdiZExBaDNLeHZ6NDl2Uk1wbDVSTVZFMFo2SkYzWWh0eUJiZXIwWnZuMS9KUE43MGgxOHIySks1U0hpTXBKMHBET1FuRVptQ0ZnVjZkRzVXNkVyRjVjV05saHlkVEQ1dTZSY1grYmFBdC9JSThhT0VvQW9kaGJGS1QraTRRQ0ZHbnNuRGlmNFVyUXdOWXVXdXdhK3B3QS9kSVRSbnptcDRUelN4aG5paTdBR24wWHV1WFJvTGZtMHVDUDVBbTREbUkzRWJlZi9NdXRxUERidEk2U05mRllkcDArTVJSZ280R1NtUlVRdHMvaTRnUnRnZUFhTDF6bGdCeXNhcGNJeHR0NHFIVS9Zak95TmhKQ0hINXM3SFVBV0Y3ZGdtWFN3amtoeG1EU2o3Qkk4NzJ1NmJZd0V3VHY1T3F5YXN4T3JEUi9rYjdVSnZPTFViMSt1MnhGa2FlTnNRSkE1STJLanYzSmlEL0FVY09CeXlBWWQwY09wc2NSWC9nM1dNYSIsIk1JSUVTRENDQXJDZ0F3SUJBZ0lRZW1RTUNGVkhTN1NJUGxrbis0ZkdZVEFOQmdrcWhraUc5dzBCQVFzRkFEQWdNUjR3SEFZRFZRUURFeFZOWVhOMFpYSkxaWGt1YzJObGJtVnlZUzVqYjIwd0lCY05NakF3TlRFNU1EUXdPVFEyV2hnUE1qRXlNREExTVRrd05ERTVORFphTUNBeEhqQWNCZ05WQkFNVEZVMWhjM1JsY2t0bGVTNXpZMlZ1WlhKaExtTnZiVENDQWFJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dHUEFEQ0NBWW9DZ2dHQkFKL1dBZWpoT1lSSms2cXNKanN6MTFiWkxLT2YvQ2Y5WmlLWFVoTFdNczN4d1RSVlBlMHFtSDE0MFd4UlJlODFLMnNwRkVBZGhMYktTUUpnR21ENmpXKzMrQlEvQmRFbm81K1NuUmJkNC9Uc01UaWtKcUtjbzF0NkNpNzNEVTBwQVhvSHhLNWNSclR6QnpTdWtlcWNrOVhNclEwMEVyV25zNlhaQXRsUDNaM2RpTGpYdytNQ2l0U0tqTXpuSis5QTFEdnlpSmlFaFJjQVNhTnd6Ky9aN2VRM0JFKytoczZqSXVBZHRac0p2SE10TGJpNC9rMnluZjN4dXhYcEZibTFkTUcvM0JnZ3U5bysvK0pFUFBZZXN5UStSb21BT1IrVnR4aGJ1OEZwanVPTmdNV3liSE0vL2JXRGlFZThhQm1tb3hyN3ppWld6UTNWQXV0SElwOGkrQkFNUndqTVdTQnJXbzZkYWhiUmpjRVVKS2d4eEd6MytMM1l5OG9acnQxeW9uTy85VUVSMGF6MWN3dldnbmE1MkpWTERUWnhPcWZaWDN5RWRWY3U2bGpLbk5mVVFDNysycisvcEdjS3ZYeUVsTnQ0em50bGRoRDEvRXErUS8yL0NzZGcvYzNaUHowck96V0FiMEV4WFJ6OVhwcTRnQ0VKRTc3am5tMTBVYnBYQndJREFRQUJvM3d3ZWpBT0JnTlZIUThCQWY4RUJBTUNCYUF3Q1FZRFZSMFRCQUl3QURBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdId1lEVlIwakJCZ3dGb0FVdWdoLzU2elJ2QTcvU01LazVLSllHWXdJUGtBd0hRWURWUjBPQkJZRUZMb0lmK2VzMGJ3Ty8wakNwT1NpV0JtTUNENUFNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJnUUFQbWFidTVHN0VUK1JISHZscU5aa2RFeFBMNHRsbUVCdXpjQjV1TlVBNTg1RFNTSVlWc2tpTDJ1V0lSdFZUa2NNUWFiNVVxQ0JsQm9MYWpjVnRmSW5HS0dHeGxIcTNxL0I3YXQyRDJZWXJnUEdsZFg5OTRFQk5sR1plQm5lOEtkTTluUllEeTF6bkpqMmM4VFFEWm80Z3ZKNm5PemR2NFZqVHZjTFFJREFIcjB0TG5tOTNBaFZ4ZUNnK01RTzgrekxIak5TZXphNEpJOEpvb2xOM0JJaFl1eTROM1IxSHJuUHp6NXhlS21qMnVSelQ0dCtHbFQrZUpYTDIwZmFYc3NoNHdLYU9OMkR6S1pyaXFaQVFGRG9vdmJoWXc0T3gvaVQxZGp4SmU2a2x1TUdpMGdTY0l2WVIxcENKQjZ1cmdTSDlJRE0vTGVkWThPeDRQbFFrNWIzVDQ2WldRclhxdUFxMGF2YTF4UUUrUit4Nm5LNFZLYzdGdU1GeTlCQWNBZ2JmSDhEaVVWWnd5K252VlM0ODEybWN2N0VycWhVaGlXbWszbXBLY05FdXMxdDEvT0ZZOXA1MUYvSm56N01jL0lwa3B3eDBQZTRYcWlpSEJQOGVnejJKNEp3S25IbG1mOTJxNFFLUmdYbHUwY3pSVnk0Rk9FTnFpR2Izakg4ZVB1VT0iXX0.eyJWZXJzaW9uIjoiMS4wIiwiRW5mb3JjZUVuY3J5cHRpb24iOnRydWUsImlzcyI6IjAwMDAwMDAxLTVjZGQtMjgwYi04MDAyLTAwMDAwMDAwMDAwMCIsInN1YiI6IjAwMDAwMDA5LTYwZmUtNWUxNS04MDAyLTAwMDAwMDAwMTk1NCIsImF1ZCI6IjAwMDAwMDAwLTVjZGQtMjgwYi04MDAzLTAwMDAwMDAwMDAwMCIsImV4cCI6IjIwMzItMDItMTdUMDY6NDQ6MDMuMzkzWiIsIm5iZiI6IjIwMjItMDItMTdUMDY6NDQ6MDMuMzkzWiIsImlhdCI6IjIwMjItMDItMTdUMDY6NDQ6MDMuMzkzWiIsImp0aSI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA0ODAxMTIiLCJQZXJtaXNzaW9ucyI6WyJNYW5hZ2VtZW50Il19.SonLgVSXtDR-PrDPC0TtgJ1CHya40Hoc7EQMMOORLOYwdMZH6pwUU42Zhh_VcdJayWnLDc7JJyaIte2xoF2FB-AevPApWHSUNKbIHasOYF5RMDAZv5GIS-YFymPXE9rLt42WB0_lmO7S_zsAFgBdriVjEk3D_Tduf1Frgem272jJAS-2DS6HH-ZOmqXy97pcbhI4pjza69tYDG6eMq8qwvClYi3G5fn92_nDFz31e6ch_VapCu9NP06wdiIQKgnc24JqR53788gslD1BhUymZmQ-Op8F0-qlYUjW7Hfy264YnCwSQAfTwn9bs0VGCYxfmCLAZx8qp5FnZKAsg0ezbGKzv7OqFF5GWorSdO5hFQOg91b3q7dmwopzfoogjNvKFRnjeZT3ovyPT4QWNgfgSpwO7MytAsSBBHYRMSrmcEKhXyYsSb49ZCb1qMuuNyAPwAEJEZ34YJxulD2y_PWCuHLSx4bCOr4am3At7JokOjjN8XyOcJ5ywNfXvKRrKBuP"}]}}}}'
    
    __jwe_decrypt = Decrypt(__DUMMY_DECRYPT_KEY)

    def test_decrypt_01(self, mocker: MockerFixture):
        """
        If an Exception occurs in decrypt,
        empty token returned.
        """    
        # mock set
        mocker.patch('authlib.jose.JsonWebEncryption.deserialize_compact', side_effect=Exception)

        # test
        success, jwe_token = self.__jwe_decrypt(self.__DUMMY_DECRYPT_JWE)

        # check
        assert success is False
        assert jwe_token is None

    def test_decrypt_02(self, mocker: MockerFixture):
        """
        Nomal test,
        JWE token returned.
        """    
        # test
        success, jwe_token = self.__jwe_decrypt(self.__DUMMY_DECRYPT_JWE)

        # check
        assert success is True
        assert jwe_token == self.__DUMMY_DECRYPT_JWE_TOKEN


class TestEncrypt:
    """Encrypt test class."""

    __DUMMY_KID = '00000001-5cdd-280b-8002-000000000000'

    __DUMMY_CRT = 'MIIDvDCCAiSgAwIBAgIGAXKCg+HeMA0GCSqGSIb3DQEBDQUAMCAxHjAcBgNVBAMMFU1hc3RlcktleS5zY2VuZXJhLmNvbTAgFw0yMDA2MDUwMzI2MjBaGA8yMTIwMTIzMTA4MDAwMFowHDEaMBgGA1UEAxMRTEFSb290LnNjZW5lcy5jb20wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCuOSjirBX+pKkdiCHO2zsdTHOW4nTewQdgYfG+npRJ2/79ooiS8PkXFEY98eCUD9YyQuhxKIbGBbD2+YZGPv1TCdShRu0J+LuwVq3e/0r64c67HdUt7LMSjtSCVPF82RW083C8rUDXSBWondXiAHYjriOsl12X5FOK17aYNlvHh9Hzx6XCT5lUNpEu+fcAH9G1+j1XI/gLcsGML3iJ2N0wsPR1ryaSVM5JvsXE57aa77Qk6uN7P3RbJmg0hevZp9sboLkJgBim8CEvJsqkE1hhuDbNaAzGa49tmAoFo2j7JysRbJtC5XhEmBE13yl6zcXynpV569W+13VVMKmxS/1EsdrwSIAZN9AwMRvSqXPCn1ZPD3XPrbhvBk62nxMkIfe0bh5G/S4uQUejqqCoFTpcXSVIlxubEmO3Ph0ocpp172Ky7kI3Y93v/XjrcdLRQYQ3tXA1O/+x9F6GAj4cgN4BrljrIazRWScd6beFv412Gu3CsKVFClmy90ARiCyj3TUCAwEAATANBgkqhkiG9w0BAQ0FAAOCAYEAdoJAyuaLb+wOIhP/FQjuEPkPi9qYvLC0d0LBYTT9gPRpKIYONP6iGNvrYYzrZCjNWEztLmnbkDykK9HZsoUt3OZu3P+0k5wUK0IMXK6WGPmYKkEmOXDAGvW6T4wOxjLEWybZS+0CcEm3WDPX3al3+r3qV1FkYczD6s8PItLcIkl7PKzGMd+GUt3nbGSQoGnCanC+otKbR1dM/LtcGr9+pIxH9aIxScLIdKQrk3LvmHiKpAHlw1uaGQjWzQE2qtwZfRIOx6nAkTUC7Jw8RDFjSiQBfyZDH4YvF0VJxHBXvDoxXZIUz1eKZfaNzGsnAd7J2BcnrzgDnNgvxyGjf4VlYxGpzE+ycvRJcg5lNkjpxflbeIoTOa+WcwYLsh2BZLLTVw7HB3wHAaIu60JMSSXr2pp9PaK/Qw8T+tEnBatxl2u37V4gWUHfgtG38Ee5Dzo/cs9fdIDyzXbrzRGPHmwLaOYztYUKQ0+0+PWAGFE4P6XqezWWP95sigB17+LAEk8w'

    __DUMMY_PLAINTEXT = b'{"AccessToken": "eyJhbGciOiJSUzUxMiIsImtpZCI6IjAwMDAwMDAyLTVjZGQtMjgwYi04MDAzLTAwMDAwMDAwMDAwMCIsIng1YyI6WyJNSUlEdkRDQ0FpU2dBd0lCQWdJR0FYS0NoWGdBTUEwR0NTcUdTSWIzRFFFQkRRVUFNQ0F4SGpBY0JnTlZCQU1NRlUxaGMzUmxja3RsZVM1elkyVnVaWEpoTG1OdmJUQWdGdzB5TURBMk1EVXdNekk0TURSYUdBOHlNVEl3TVRJek1UQTRNREF3TUZvd0hERWFNQmdHQTFVRUF4TVJRVk5TYjI5MExuTmpaVzVsY3k1amIyMHdnZ0dpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCandBd2dnR0tBb0lCZ1FDaTJkZ2hQN3krYlA2dHZrSm1tUllicVc1MFcwSk5hOUo1K0QySW1mRksrN2lwTXorRzQ0MzFieWxzUHlmdEl3amhEdkMxTWVobDNuV3dUbUtJeEJHT1ludUliRWt1cVYyLytKbWpDeW1qZCt6Z2E2SVFtKzBIZTJ0N05JcjhwVDNnMnJ3amYxZGJScllNQ1V0RENQT1dWY2VCREVuQ3FpMHUxUkpCS0p0aDZlc09UR0RVckF4MzNxVjNhbXhUNVgxWlpmSjZKZ3A2KzBsWTkrVzl1bU0rako5a2E2bEtRczJVL0g5enI2ZlNmVnZjK05RZXdwdDNMNXlRa3VuSnlYZWw2alpWcmFVTUJhRlN3a2hQdUVCTVNEa0lSM1ByemlNOFIwM0YzSEhDdkEvS3E1Slg2SGxqb1ZPTWErM2dnd2lXNE9jQW1ybDFxbXROZDN0Z0JLZHVsN1E3M0lZYjFvUTh3NmRjbWZRNUsvbGlRVTZIUkVGR1Z0UHRteG01ZWNVZncxbC9aUDR5R0JxN1ZYaUJnNUlkZ3RkSWJXaytuSitJbjQvMWtsRzlUZ1BqdWIvcHBGT1BCNHY0cWw2aCtnZkZaSjlhalplOHJueVlLQ1l6SFhEcENrQzRuQlprcFd0KzBrY3ovdDVKVm56VDRKZTB6b1Q5RVhKWUR6dDhPQzBDQXdFQUFUQU5CZ2txaGtpRzl3MEJBUTBGQUFPQ0FZRUFtNC94bDZ5MjEwYytGS1JCQ1RMeENHRG1qbkc1SDkrQ1QyVnQ2K291QkpuYk42UHRwZ0kvNWZTMWRVSmNyUkpGZkpzWjNacXlyVG1RY20xSU5kdWRaOXk5RmpEUVJmTkhjM2p2emFGazZMRm0rcUpQYklvUjRLLzB0d2FJUVFQS2w0OFdiZExBaDNLeHZ6NDl2Uk1wbDVSTVZFMFo2SkYzWWh0eUJiZXIwWnZuMS9KUE43MGgxOHIySks1U0hpTXBKMHBET1FuRVptQ0ZnVjZkRzVXNkVyRjVjV05saHlkVEQ1dTZSY1grYmFBdC9JSThhT0VvQW9kaGJGS1QraTRRQ0ZHbnNuRGlmNFVyUXdOWXVXdXdhK3B3QS9kSVRSbnptcDRUelN4aG5paTdBR24wWHV1WFJvTGZtMHVDUDVBbTREbUkzRWJlZi9NdXRxUERidEk2U05mRllkcDArTVJSZ280R1NtUlVRdHMvaTRnUnRnZUFhTDF6bGdCeXNhcGNJeHR0NHFIVS9Zak95TmhKQ0hINXM3SFVBV0Y3ZGdtWFN3amtoeG1EU2o3Qkk4NzJ1NmJZd0V3VHY1T3F5YXN4T3JEUi9rYjdVSnZPTFViMSt1MnhGa2FlTnNRSkE1STJLanYzSmlEL0FVY09CeXlBWWQwY09wc2NSWC9nM1dNYSIsIk1JSUVTRENDQXJDZ0F3SUJBZ0lRZW1RTUNGVkhTN1NJUGxrbis0ZkdZVEFOQmdrcWhraUc5dzBCQVFzRkFEQWdNUjR3SEFZRFZRUURFeFZOWVhOMFpYSkxaWGt1YzJObGJtVnlZUzVqYjIwd0lCY05NakF3TlRFNU1EUXdPVFEyV2hnUE1qRXlNREExTVRrd05ERTVORFphTUNBeEhqQWNCZ05WQkFNVEZVMWhjM1JsY2t0bGVTNXpZMlZ1WlhKaExtTnZiVENDQWFJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dHUEFEQ0NBWW9DZ2dHQkFKL1dBZWpoT1lSSms2cXNKanN6MTFiWkxLT2YvQ2Y5WmlLWFVoTFdNczN4d1RSVlBlMHFtSDE0MFd4UlJlODFLMnNwRkVBZGhMYktTUUpnR21ENmpXKzMrQlEvQmRFbm81K1NuUmJkNC9Uc01UaWtKcUtjbzF0NkNpNzNEVTBwQVhvSHhLNWNSclR6QnpTdWtlcWNrOVhNclEwMEVyV25zNlhaQXRsUDNaM2RpTGpYdytNQ2l0U0tqTXpuSis5QTFEdnlpSmlFaFJjQVNhTnd6Ky9aN2VRM0JFKytoczZqSXVBZHRac0p2SE10TGJpNC9rMnluZjN4dXhYcEZibTFkTUcvM0JnZ3U5bysvK0pFUFBZZXN5UStSb21BT1IrVnR4aGJ1OEZwanVPTmdNV3liSE0vL2JXRGlFZThhQm1tb3hyN3ppWld6UTNWQXV0SElwOGkrQkFNUndqTVdTQnJXbzZkYWhiUmpjRVVKS2d4eEd6MytMM1l5OG9acnQxeW9uTy85VUVSMGF6MWN3dldnbmE1MkpWTERUWnhPcWZaWDN5RWRWY3U2bGpLbk5mVVFDNysycisvcEdjS3ZYeUVsTnQ0em50bGRoRDEvRXErUS8yL0NzZGcvYzNaUHowck96V0FiMEV4WFJ6OVhwcTRnQ0VKRTc3am5tMTBVYnBYQndJREFRQUJvM3d3ZWpBT0JnTlZIUThCQWY4RUJBTUNCYUF3Q1FZRFZSMFRCQUl3QURBZEJnTlZIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdId1lEVlIwakJCZ3dGb0FVdWdoLzU2elJ2QTcvU01LazVLSllHWXdJUGtBd0hRWURWUjBPQkJZRUZMb0lmK2VzMGJ3Ty8wakNwT1NpV0JtTUNENUFNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJnUUFQbWFidTVHN0VUK1JISHZscU5aa2RFeFBMNHRsbUVCdXpjQjV1TlVBNTg1RFNTSVlWc2tpTDJ1V0lSdFZUa2NNUWFiNVVxQ0JsQm9MYWpjVnRmSW5HS0dHeGxIcTNxL0I3YXQyRDJZWXJnUEdsZFg5OTRFQk5sR1plQm5lOEtkTTluUllEeTF6bkpqMmM4VFFEWm80Z3ZKNm5PemR2NFZqVHZjTFFJREFIcjB0TG5tOTNBaFZ4ZUNnK01RTzgrekxIak5TZXphNEpJOEpvb2xOM0JJaFl1eTROM1IxSHJuUHp6NXhlS21qMnVSelQ0dCtHbFQrZUpYTDIwZmFYc3NoNHdLYU9OMkR6S1pyaXFaQVFGRG9vdmJoWXc0T3gvaVQxZGp4SmU2a2x1TUdpMGdTY0l2WVIxcENKQjZ1cmdTSDlJRE0vTGVkWThPeDRQbFFrNWIzVDQ2WldRclhxdUFxMGF2YTF4UUUrUit4Nm5LNFZLYzdGdU1GeTlCQWNBZ2JmSDhEaVVWWnd5K252VlM0ODEybWN2N0VycWhVaGlXbWszbXBLY05FdXMxdDEvT0ZZOXA1MUYvSm56N01jL0lwa3B3eDBQZTRYcWlpSEJQOGVnejJKNEp3S25IbG1mOTJxNFFLUmdYbHUwY3pSVnk0Rk9FTnFpR2Izakg4ZVB1VT0iXX0.ZXlKaGJHY2lPaUpGUTBSSUxVVlRLMEV5TlRaTFZ5SXNJbXRwWkNJNklqQXdNREF3TURBeUxUVmpaR1F0TWpnd1lpMDRNREF6TFRBd01EQXdNREF3TURBd01DSXNJbmcxWXlJNld5Sk5TVWxFZGtSRFEwRnBVMmRCZDBsQ1FXZEpSMEZZUzBOb1dHZEJUVUV3UjBOVGNVZFRTV0l6UkZGRlFrUlJWVUZOUTBGNFNHcEJZMEpuVGxaQ1FVMU5SbFV4YUdNelVteGphM1JzWlZNMWVsa3lWblZhV0Vwb1RHMU9kbUpVUVdkR2R6QjVUVVJCTWsxRVZYZE5la2swVFVSU1lVZEJPSGxOVkVsM1RWUkplazFVUVRSTlJFRjNUVVp2ZDBoRVJXRk5RbWRIUVRGVlJVRjRUVkpSVms1VFlqSTVNRXh1VG1wYVZ6VnNZM2sxYW1JeU1IZG5aMGRwVFVFd1IwTlRjVWRUU1dJelJGRkZRa0ZSVlVGQk5FbENhbmRCZDJkblIwdEJiMGxDWjFGRGFUSmtaMmhRTjNrcllsQTJkSFpyU20xdFVsbGljVmMxTUZjd1NrNWhPVW8xSzBReVNXMW1Sa3NyTjJsd1RYb3JSelEwTXpGaWVXeHpVSGxtZEVsM2FtaEVka014VFdWb2JETnVWM2RVYlV0SmVFSkhUMWx1ZFVsaVJXdDFjVll5THl0S2JXcERlVzFxWkN0NloyRTJTVkZ0S3pCSVpUSjBOMDVKY2pod1ZETm5NbkozYW1ZeFpHSlNjbGxOUTFWMFJFTlFUMWRXWTJWQ1JFVnVRM0ZwTUhVeFVrcENTMHAwYURabGMwOVVSMFJWY2tGNE16TnhWak5oYlhoVU5WZ3hXbHBtU2paS1ozQTJLekJzV1RrclZ6bDFiVTByYWtvNWEyRTJiRXRSY3pKVkwwZzVlbkkyWmxObVZuWmpLMDVSWlhkd2RETk1OWGxSYTNWdVNubFlaV3cyYWxwV2NtRlZUVUpoUmxOM2EyaFFkVVZDVFZORWEwbFNNMUJ5ZW1sTk9GSXdNMFl6U0VoRGRrRXZTM0UxU2xnMlNHeHFiMVpQVFdFck0yZG5kMmxYTkU5alFXMXliREZ4YlhST1pETjBaMEpMWkhWc04xRTNNMGxaWWpGdlVUaDNObVJqYldaUk5Vc3ZiR2xSVlRaSVVrVkdSMVowVUhSdGVHMDFaV05WWm5jeGJDOWFVRFI1UjBKeE4xWllhVUpuTlVsa1ozUmtTV0pYYXl0dVNpdEpialF2TVd0c1J6bFVaMUJxZFdJdmNIQkdUMUJDTkhZMGNXdzJhQ3RuWmtaYVNqbGhhbHBsT0hKdWVWbExRMWw2U0ZoRWNFTnJRelJ1UWxwcmNGZDBLekJyWTNvdmREVktWbTU2VkRSS1pUQjZiMVE1UlZoS1dVUjZkRGhQUXpCRFFYZEZRVUZVUVU1Q1oydHhhR3RwUnpsM01FSkJVVEJHUVVGUFEwRlpSVUZ0TkM5NGJEWjVNakV3WXl0R1MxSkNRMVJNZUVOSFJHMXFia2MxU0RrclExUXlWblEySzI5MVFrcHVZazQyVUhSd1owa3ZOV1pUTVdSVlNtTnlVa3BHWmtweldqTmFjWGx5VkcxUlkyMHhTVTVrZFdSYU9YazVSbXBFVVZKbVRraGpNMnAyZW1GR2F6Wk1SbTByY1VwUVlrbHZValJMTHpCMGQyRkpVVkZRUzJ3ME9GZGlaRXhCYUROTGVIWjZORGwyVWsxd2JEVlNUVlpGTUZvMlNrWXpXV2gwZVVKaVpYSXdXblp1TVM5S1VFNDNNR2d4T0hJeVNrczFVMGhwVFhCS01IQkVUMUZ1UlZwdFEwWm5WalprUnpWWE5rVnlSalZqVjA1c2FIbGtWRVExZFRaU1kxZ3JZbUZCZEM5SlNUaGhUMFZ2UVc5a2FHSkdTMVFyYVRSUlEwWkhibk51UkdsbU5GVnlVWGRPV1hWWGRYZGhLM0IzUVM5a1NWUlNibnB0Y0RSVWVsTjRhRzVwYVRkQlIyNHdXSFYxV0ZKdlRHWnRNSFZEVURWQmJUUkViVWt6UldKbFppOU5kWFJ4VUVSaWRFazJVMDVtUmxsa2NEQXJUVkpTWjI4MFIxTnRVbFZSZEhNdmFUUm5VblJuWlVGaFRERjZiR2RDZVhOaGNHTkplSFIwTkhGSVZTOVphazk1VG1oS1EwaElOWE0zU0ZWQlYwWTNaR2R0V0ZOM2FtdG9lRzFFVTJvM1FrazROekoxTm1KWmQwVjNWSFkxVDNGNVlYTjRUM0pFVWk5cllqZFZTblpQVEZWaU1TdDFNbmhHYTJGbFRuTlJTa0UxU1RKTGFuWXpTbWxFTDBGVlkwOUNlWGxCV1dRd1kwOXdjMk5TV0M5bk0xZE5ZU0lzSWsxSlNVVlRSRU5EUVhKRFowRjNTVUpCWjBsUlpXMVJUVU5HVmtoVE4xTkpVR3hyYmlzMFprZFpWRUZPUW1kcmNXaHJhVWM1ZHpCQ1FWRnpSa0ZFUVdkTlVqUjNTRUZaUkZaUlVVUkZlRlpPV1ZoT01GcFlTa3hhV0d0MVl6Sk9iR0p0Vm5sWlV6VnFZakl3ZDBsQ1kwNU5ha0YzVGxSRk5VMUVVWGRQVkZFeVYyaG5VRTFxUlhsTlJFRXhUVlJyZDA1RVJUVk9SRnBoVFVOQmVFaHFRV05DWjA1V1FrRk5WRVpWTVdoak0xSnNZMnQwYkdWVE5YcFpNbFoxV2xoS2FFeHRUblppVkVORFFXRkpkMFJSV1VwTGIxcEphSFpqVGtGUlJVSkNVVUZFWjJkSFVFRkVRME5CV1c5RFoyZEhRa0ZLTDFkQlpXcG9UMWxTU21zMmNYTkthbk42TVRGaVdreExUMll2UTJZNVdtbExXRlZvVEZkTmN6TjRkMVJTVmxCbE1IRnRTREUwTUZkNFVsSmxPREZMTW5Od1JrVkJaR2hNWWt0VFVVcG5SMjFFTm1wWEt6TXJRbEV2UW1SRmJtODFLMU51VW1Ka05DOVVjMDFVYVd0S2NVdGpiekYwTmtOcE56TkVWVEJ3UVZodlNIaExOV05TY2xSNlFucFRkV3RsY1dOck9WaE5jbEV3TUVWeVYyNXpObGhhUVhSc1VETmFNMlJwVEdwWWR5dE5RMmwwVTB0cVRYcHVTaXM1UVRGRWRubHBTbWxGYUZKalFWTmhUbmQ2S3k5YU4yVlJNMEpGS3l0b2N6WnFTWFZCWkhSYWMwcDJTRTEwVEdKcE5DOXJNbmx1WmpONGRYaFljRVppYlRGa1RVY3ZNMEpuWjNVNWJ5c3ZLMHBGVUZCWlpYTjVVU3RTYjIxQlQxSXJWblI0YUdKMU9FWndhblZQVG1kTlYzbGlTRTB2TDJKWFJHbEZaVGhoUW0xdGIzaHlOM3BwV2xkNlVUTldRWFYwU0Vsd09Ha3JRa0ZOVW5kcVRWZFRRbkpYYnpaa1lXaGlVbXBqUlZWS1MyZDRlRWQ2TXl0TU0xbDVPRzlhY25ReGVXOXVUeTg1VlVWU01HRjZNV04zZGxkbmJtRTFNa3BXVEVSVVduaFBjV1phV0RONVJXUldZM1UyYkdwTGJrNW1WVkZETnlzeWNpc3ZjRWRqUzNaWWVVVnNUblEwZW01MGJHUm9SREV2UlhFclVTOHlMME56Wkdjdll6TmFVSG93Y2s5NlYwRmlNRVY0V0ZKNk9WaHdjVFJuUTBWS1JUYzNhbTV0TVRCVlluQllRbmRKUkVGUlFVSnZNM2QzWldwQlQwSm5UbFpJVVRoQ1FXWTRSVUpCVFVOQ1lVRjNRMUZaUkZaU01GUkNRVWwzUVVSQlpFSm5UbFpJVTFWRlJtcEJWVUpuWjNKQ1owVkdRbEZqUkVGUldVbExkMWxDUWxGVlNFRjNTWGRJZDFsRVZsSXdha0pDWjNkR2IwRlZkV2RvTHpVMmVsSjJRVGN2VTAxTGF6VkxTbGxIV1hkSlVHdEJkMGhSV1VSV1VqQlBRa0paUlVaTWIwbG1LMlZ6TUdKM1R5OHdha053VDFOcFYwSnRUVU5FTlVGTlFUQkhRMU54UjFOSllqTkVVVVZDUTNkVlFVRTBTVUpuVVVGUWJXRmlkVFZITjBWVUsxSklTSFpzY1U1YWEyUkZlRkJNTkhSc2JVVkNkWHBqUWpWMVRsVkJOVGcxUkZOVFNWbFdjMnRwVERKMVYwbFNkRlpVYTJOTlVXRmlOVlZ4UTBKc1FtOU1ZV3BqVm5SbVNXNUhTMGRIZUd4SWNUTnhMMEkzWVhReVJESlpXWEpuVUVkc1pGZzVPVFJGUWs1c1IxcGxRbTVsT0V0a1RUbHVVbGxFZVRGNmJrcHFNbU00VkZGRVdtODBaM1pLTm01UGVtUjJORlpxVkhaalRGRkpSRUZJY2pCMFRHNXRPVE5CYUZaNFpVTm5LMDFSVHpncmVreElhazVUWlhwaE5FcEpPRXB2YjJ4T00wSkphRmwxZVRST00xSXhTSEp1VUhwNk5YaGxTMjFxTW5WU2VsUTBkQ3RIYkZRclpVcFlUREl3Wm1GWWMzTm9OSGRMWVU5T01rUjZTMXB5YVhGYVFWRkdSRzl2ZG1Kb1dYYzBUM2d2YVZReFpHcDRTbVUyYTJ4MVRVZHBNR2RUWTBsMldWSXhjRU5LUWpaMWNtZFRTRGxKUkUwdlRHVmtXVGhQZURSUWJGRnJOV0l6VkRRMldsZFJjbGh4ZFVGeE1HRjJZVEY0VVVVclVpdDRObTVMTkZaTFl6ZEdkVTFHZVRsQ1FXTkJaMkptU0RoRWFWVldXbmQ1SzI1MlZsTTBPREV5YldOMk4wVnljV2hWYUdsWGJXc3piWEJMWTA1RmRYTXhkREV2VDBaWk9YQTFNVVl2U201Nk4wMWpMMGx3YTNCM2VEQlFaVFJZY1dscFNFSlFPR1ZuZWpKS05FcDNTMjVJYkcxbU9USnhORkZMVW1kWWJIVXdZM3BTVm5rMFJrOUZUbkZwUjJJemFrZzRaVkIxVlQwaVhTd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltVndheUk2ZXlKcmRIa2lPaUpGUXlJc0luZ2lPaUl5YWtWWkxURnBNVW81YkVOaFpFZE5kMTlNVFRKblJEaHVWV0l5TVVsblV6WjFZemxVUTNsMWJsWmpJaXdpZVNJNkluSmhMVkozZW5vMWVuRnJWMjQzV2s5Q1ExOWtlblpuY2pKQ1JHNWhhMVJwTWt4TVUzbElORVJ1YkZFaUxDSmpjbllpT2lKUUxUSTFOaUo5ZlEuOFF5bUdUXzc1SWxZZGxTR0J3dE5lNFpfWGFqbVdlX2hHaWp6TjlWR1hWbEFkVy1od1ZualBBLkx2MXpFU01yQ3pEaHVyUDguY0I3dTJsMzVUOFExeC1Pd3FEenBQdEpVZnNjUjNLR3YwZlV2bTl4cEJyU1F0ZUhLUzU3WjB1Z1hEYk4tZHg4UlpZTWJlMjN6WlluN2dVR09vUXFaQ2NWZGdZVFlXcFc0c1ZJUy1TUTBGVHBlbW5MSlk1R3RxaTg3MnVMRU94YUVPcXJwXy1RbWZ0V3BVaFVDc1BEZGhMb3FzdXFyc2NvTEtlUm00RUI3MDZKd29TS0VUb1k1SHFQNEFOMHB0R0d3ZVVhaWRDX083a1Uxc25ka2ZfNHNqR2llWmxDQWxVRGVrYVZvQzgxckNCUUh1YkNEd3dMcHJmR3NxQmtUUGxvam9HMmt5VXMybF9KenJDckhRSjhIcm83NTgzeXZ6WUlSbHUwMktyWEZTaDQ1azRwS01xRTFpcDVIX3prM2hLUTVYRlV5ZHFjWHZiTkhQTWZNeXgzcVFvcEFYNjFuTVNCaHUteHp6Qm9MMTBCZ2hOVGZSUVNPUFpJVWo5aWxwOC1STFdLVmtibVRpbnJweVV0SlFMVS1RdFZlakY0SGs3UDJFeVFyejRraGZ5c20wQXpacGp0LTdERU1MeC1KRE9hRkZTT0c5S0xZMlp3eHN0dlVaVUVkeDlwUE1TN0tBY05Ea0ZscUpaNGNJb1Mwdkc5d2FiSGc2LW9jZ3ZXM0VzMEE2MU1Ta0FzRGxGZFhXakFHZGxxYU9XbG9OemJaTzRZNERTQ05BNk5xUFE1ZjRYSkVFZ05odDFSN3RaZG1jZDZoMW93LWtveXZGVzFQVHJkY2lab1NCWVdvZTJuQ3hUeFdaY2k4LU1NTkROZ01FaVg1dDhWbS1aWUZId201WHdCakZpXzRGaEFiUVM4cEZvSUhMVkxmaU5KOFpNMTBKTGRqLkhpbm13VHlDN1ctMVFNOGwyQUNwZVE.Nn2pamBtEWJkv-LVJ5xQITriQSk-90JGq7aJn5jSlPg4K0Y8WGWuFkUDrAcuNbqWI_-nIJCsAO1y_mSvYXW-PL0lZFI05ioQZtW7UO4dRqjnqR3dFCuJBCCz6BOzWWrBszPkvtdkzu81r2uMq30Kghqx3exEwJlvMvADWGy4C0qrotO9bboCcd4Qhjgg-wt9WF9HgcUHjeqheBw_QVNS1ggFSK9DMbEfvQhHoskGjTDb3gohUDSCNA5PzDJfeWEbBfF6dRHIiCxuCGuM5-p-85wTMiagleBTOzIHVmbYzzXZcF2LhybVubySgbjzXnSC2-EP6RnqHGqc_chv8GgvA-NTRzIPd_-V2MPTwTppB2DXv6vajIrs812U6dWl8w0fEuMySzzBZ7TgRUw9LKQAomABhTPM9pAzs3ViM6JTen0hI47lgiw8jUX05m7fwlP6BQSYKJvEQ2B1YiZ9Hw3NtiHDlXdE74sRgJPm8MSw1EhhLJf99FHnp2ZbMf46vn_C", "PayloadObject": {"Body": {"DeviceID": "00000009-60fe-5e15-8002-000000001954"}}}'

    __DUMMY_JWE_HEADER = 'eyJlbmMiOiJBMjU2R0NNIiwia2lkIjoiMDAwMDAwMDEtNWNkZC0yODBiLTgwMDItMDAwMDAwMDAwMDAwIiwiYWxnIjoiUlNBMV81In0'

    __jwe_encrypt = Encrypt(__DUMMY_KID, __DUMMY_CRT)

    def test_encrypt_01(self, mocker: MockerFixture):
        """
        If an Exception occurs in encrypt,
        empty token returned.
        """    
        # mock set
        mocker.patch('authlib.jose.JsonWebEncryption.serialize_compact', side_effect=Exception)

        # test
        success, jwe = self.__jwe_encrypt(self.__DUMMY_PLAINTEXT)

        # check
        assert success is False
        assert jwe is None

    def test_encrypt_02(self, mocker: MockerFixture):
        """
        Crtificate type other,
        empty token returned.
        """    
        # mock set
        def create_dummy_dsa_cert(tmp):
            one_day = timedelta(1, 0, 0)
            private_key = dsa.generate_private_key(
                key_size=2048
            )
            public_key = private_key.public_key()
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
            ]))
            builder = builder.issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
            ]))
            builder = builder.not_valid_before(datetime.today() - one_day)
            builder = builder.not_valid_after(datetime.today() + (one_day * 30))
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.public_key(public_key)
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(u'cryptography.io')]
                ),
                critical=False
            )
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            )
            certificate = builder.sign(
                private_key=private_key, algorithm=hashes.SHA256(),
            )
            return certificate

        mocker.patch('cryptography.x509.load_der_x509_certificate', side_effect=create_dummy_dsa_cert)
        serialize_compact_mock = mocker.patch('authlib.jose.JsonWebEncryption.serialize_compact', side_effect=Exception)

        # test           
        success, jwe = self.__jwe_encrypt(self.__DUMMY_PLAINTEXT)

        # check
        assert success is False
        assert jwe is None
        serialize_compact_mock.assert_not_called()

    def test_encrypt_03(self, mocker: MockerFixture):
        """
        Crtificate type EC,
        jwe token returned.
        """    
        # mock set
        mocker.patch('authlib.jose.JsonWebEncryption.serialize_compact', return_value=b'abc')

        # test
        crt = 'MIIDHzCCAYegAwIBAgIUe0aQc1v0OzUdgAyxFSDCNT/8EnowDQYJKoZIhvcNAQELBQAwQDELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMRAwDgYDVQQKDAdFWEFNUExFMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjIwMjE0MDAwOTUwWhcNMzcxMjMxMjM1OTU5WjBeMQswCQYDVQQGEwJKUDEOMAwGA1UECAwFVG9reW8xEDAOBgNVBAoMB0VYQU1QTEUxLTArBgNVBAMMJDAwMDAwMDA5LTYwZmUtNWUxNS04MDAyLTAwMDAwMDAwMTk1NDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCoHUTJU5A9QOEplayjGMqHhKq6SsmnTZL6zje9OpSA5seKdkG5Ukygg1fvsm0hNvtnItC11RX/afqfK/v65oeejPjA8MAkGA1UdEwQCMAAwLwYDVR0RBCgwJoIkMDAwMDAwMDktNjBmZS01ZTE1LTgwMDItMDAwMDAwMDAxOTU0MA0GCSqGSIb3DQEBCwUAA4IBgQCG+3a/g7Rav70kuQFisElEw25u4Zypr8njiX0WRSUwqDQfV/kKJkmLalbYJwxQHc1ogDs6qiqFkSyhEkXQlDJwGvTT2ziy94816Mp3YG/c56wz2XgRqtNkpx2VY3HYJPVfck8siLHgI6UHTp1KbWF8lUBWthDCaLcfc9edGnllJ9fLZnSzOzBnL7mGUAr9X0+ViBZC/z7d4pXBkQ/ckjU5hKhIb7ung4U5LS7qn9aV/VtBg/wxgO1diF3fww2opPs6c+pOrNbfl0vr4aUHHbxYisPfCUj33Kw8Z8DAfzgMoyfDfXnrEUm4IulwlvUIhzHzenqP4ITODHH3GAgUeF1oXwJqwMlsZrgPmJpKcVdI4sjG0uC5yicEtzivqlYlEvIE4fAoiQlYc4zsEI7xuqn9hDA/MZOuSvObxFGBu4cvk7SkSbn2xpELA7XMIGO6hlrFxMY0bxrbGV1T81+2BRxoBMOgpHFuLZg3gVeAdFcN+nBZL1QVb5+CfPEtnLPk+IQ='
        encrypt = Encrypt(self.__DUMMY_KID, crt)
        success, jwe = encrypt(self.__DUMMY_PLAINTEXT)

        # check
        assert success is True
        assert jwe == 'abc'

    def test_encrypt_04(self, mocker: MockerFixture):
        """
        Crtificate type RSA,
        jwe token returned.
        """    
        # test           
        success, jwe = self.__jwe_encrypt(self.__DUMMY_PLAINTEXT)
        jew_list = jwe.split('.')

        # check
        assert success is True
        # JWE changes every time, so check only the header.
        assert jew_list[0] == self.__DUMMY_JWE_HEADER

    def test_encrypt_05(self, mocker: MockerFixture):
        """
        if certificate is None when should error.
        """    
        self.__jwe_encrypt = Encrypt(self.__DUMMY_KID, None)

        # test
        success, jwe = self.__jwe_encrypt(self.__DUMMY_PLAINTEXT)

        # check
        assert success is False
        assert jwe is None

class TestJoseOps:
    """JoseOps test class."""

    __DUMMY_SIGN_KID = '00000009-60fe-5e15-8002-000000001954'

    __DUMMY_SIGN_KEY = {'crv': 'P-256', 'd': 'q9oqUvmn60v0xJU8FSCu__JpBrHcXLDxt2vgVUXMzzs', 'kty': 'EC', 'x': 'S1tYZTnQKtM5KNDNNmBfL3NRLyB_QV3jwMBZR-u0TBo', 'y': 'IsxOTEPzHeXSOQSHDEiStaw6Er-B5vrVvUntKRxZVLc'}

    __DUMMY_SIGN_CRT = '-----BEGIN CERTIFICATE-----\nMIICeDCB4aADAgECAgYBeuGfkIkwDQYJKoZIhvcNAQENBQAwFTETMBEGA1UEAwwK\nS2V5U2VydmljZTAgFw0yMTA3MjYwNzAyNDhaGA8yMTIxMDcwMjA3MDI0OFowLzEt\nMCsGA1UEAwwkMDAwMDAwMDktNjAxMy1mMGVhLTgwMDItMDAwMDAwMDAwMDAwMFkw\nEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAES1tYZTnQKtM5KNDNNmBfL3NRLyB/QV3j\nwMBZR+u0TBoizE5MQ/Md5dI5BIcMSJK1rDoSv4Hm+tW9Se0pHFlUtzANBgkqhkiG\n9w0BAQ0FAAOCAYEAEX/grJqq6P+S9Fssb4pC0YB28KFUxsy+jqak1XwRoeoB94Sy\ny2EUxy0Tk/EQYNARSjrwalbvkBeBNSqxsXZy+yV0Se/CxtwebfKkqLcoWIgwQwpQ\nBKj12bOAII+uml2GXCR45BcflGX/Yc6k2HtgjBZ3EUMddyE9MZm6nQW5sI0UifTM\ncMCmIECuBVQxXHW6pKzxL0poCmolhYjb3tIvcTEl7/9LNqMyfojWGYhVIK7LFV/I\n8+HdLDMVQY2DsY3qG2qpFJP/mU0BJUc6jFL2gb7HKt8iNz7/MF5NkeeZBON4ILi7\n0Zdr9srR06syIqktiub41Q95RwoDweiKoRWZ9Or+js81rW/zRycizDDKapns0Hme\njKtRYLn0iEFZtolR96UwbxTfrh1ZzS9DTWLBVTkO9As0YDByyqimJsg62JXx5RK0\nlBaFR2kdSOKPOvV/U3F/QdQGGXHUfWz2Uj3xj5M67PAMkKe7oE31mUKDp1LN/Q9M\nPasHxYwr8zRAiaBt\n-----END CERTIFICATE-----'

    __DUMMY_STR_ROOT_CERT = ''
    __DUMMY_LIST_ROOT_CERT = ['']

    __jose_ops = JoseOps()
    __jose_ops_str = JoseOps(False, __DUMMY_STR_ROOT_CERT)
    __jose_ops_list = JoseOps(False, __DUMMY_LIST_ROOT_CERT)

    def test_property_01(self):
        """
        property test.
        """    
        # test           
        assert self.__jose_ops.verify is not None
        assert self.__jose_ops.sign_ops is not None
        assert self.__jose_ops.decrypt_ops is not None
        assert self.__jose_ops.encrypt_ops is not None

    def test_register_la_cert_01(self):
        """
        LA Certificate be registered.
        """    
        # test
        self.__jose_ops.register_la_cert(self.__DUMMY_SIGN_CRT)
        assert self.__jose_ops.verify._la_root_cert_key

    def test_register_la_cert_02(self):
        """
        LA Certificate be registered.
        """    
        # test
        self.__jose_ops_str.register_la_cert(self.__DUMMY_SIGN_CRT)
        assert self.__jose_ops_str.verify._la_root_cert_key

    def test_register_la_cert_03(self):
        """
        LA Certificate be registered.
        """    
        # test
        self.__jose_ops_list.register_la_cert(self.__DUMMY_SIGN_CRT)
        assert self.__jose_ops_list.verify._la_root_cert_key

    def test_register_local_key_cert_01(self):
        """
        Certificate be registered(single crt).
        """    
        # test
        self.__jose_ops.register_local_key_cert(self.__DUMMY_SIGN_KID, self.__DUMMY_SIGN_KEY, self.__DUMMY_SIGN_CRT)
        assert self.__jose_ops.sign_ops[self.__DUMMY_SIGN_KID]
        assert self.__jose_ops.decrypt_ops[self.__DUMMY_SIGN_KID]

    def test_register_local_key_cert_02(self):
        """
        Certificate be registered(crts list).
        """    
        # test
        self.__jose_ops.register_local_key_cert(self.__DUMMY_SIGN_KID, self.__DUMMY_SIGN_KEY, [self.__DUMMY_SIGN_CRT])
        assert self.__jose_ops.sign_ops[self.__DUMMY_SIGN_KID]
        assert self.__jose_ops.decrypt_ops[self.__DUMMY_SIGN_KID]

    def test_register_remote_cert_01(self):
        """
        Certificate be registered.
        """    
        # test
        self.__jose_ops.register_remote_cert(self.__DUMMY_SIGN_KID, self.__DUMMY_SIGN_CRT)
        assert self.__jose_ops.encrypt_ops[self.__DUMMY_SIGN_KID]

class TestJoseFuncs:
    """function test class."""

    KEY = "OTA2M0JERDBGMDY2ODVFNjI5REIxOEQwQkE4NURCMzE"

    def test_jwe_encrypt_decrypt(self):
        """
        JWE decrypt with common key
        """
        # test
        msg = "Hello"
        key = base64.urlsafe_b64decode(self.KEY + "=" * (4 - len(self.KEY) % 4))
        encrypted = _jwe_encrypt(msg.encode(), "A256KW", "A256GCM", "0123", key)
        decrypted = _jwe_decrypt(encrypted, key)
        assert msg == decrypted.decode()
        invalid_key = b""
        assert _jwe_encrypt(msg.encode(), "A256KW", "A256GCM", "0123", invalid_key) == None
        assert _jwe_decrypt(encrypted, invalid_key) == None
