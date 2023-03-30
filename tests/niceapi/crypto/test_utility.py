"""Test for utility."""
from src.niceapi.crypto._utility import (
    _check_certificate,
    _to_b64, _to_pem,
    _get_random_hex,
    _aes_gcm_encrypt,
    _aes_gcm_decrypt,
)
import base64
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.x509.oid import NameOID

class Testutility:
    """utility test class."""

    __DUMMY_CRT = 'MIIDlzCCAn8CFCL6J2nMHEk8bgycTYAi7JBwohp9MA0GCSqGSIb3DQEBCwUAMIGHMQswCQYDVQQGEwJKUDEOMAwGA1UECAwFT3Nha2ExDjAMBgNVBAcMBU9zYWthMQwwCgYDVQQKDANzc3MxDDAKBgNVBAsMA3NzczEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMSIwIAYJKoZIhvcNAQkBFhNzb21lb25lQGV4YW1wbGUuY29tMB4XDTIyMDMyMjAxMzYwNVoXDTMyMDMxOTAxMzYwNVowgYcxCzAJBgNVBAYTAkpQMQ4wDAYDVQQIDAVPc2FrYTEOMAwGA1UEBwwFT3Nha2ExDDAKBgNVBAoMA3NzczEMMAoGA1UECwwDc3NzMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20xIjAgBgkqhkiG9w0BCQEWE3NvbWVvbmVAZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMbsd67QjTaanaB74wcfOlvafcsDT7+aBTyRI36luKhBYUf0zNwJXReeRGrm4uJVL8Lp8+ia3la0rWgzduk/vO5jzOkcjF7urOpezVwwKEnpuxKQr1zHFWzh+W7XN8Zl6Y4PQ1ErKjeNg+sWEKepedkNsoDRLpbu3kXobRIM5bvxGsMwPlBYF1glKPXfS3KWUBSUcX32S0WYlSY+81n4ru2McVVJ1W8ta2KBR2HxFzGnv1jamF97GcG2XS13q3f5BT3iQQi2UUwd7si1db3nh89xkUNsyiupQ1f4TJOD9sIi/r1UfsYdkjcZTiFZ2tuDsxDV2CVgbKfOzdAUGSAsR9AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAIjyPqzWk2Oo9RIpWcjJbSg4UHsJGo6jN9/bXtM4Wu/ngA0ciA0SxVRdAfUjp/IqmmOdQrTJb3/8COhwYEQh67EHFyVpxruXjbuZ7OJVLq7p0Vk2BEUOQJfwlz6FJc7YCnIm8IjqvgOtuwf1P6zJ7Q89FplZg985GuAtJpEGS3LmcQreHs/K5h1FAL4JVG88tfa/bd06tgldbnx+eESsImsj5Wh8eenf0Y0tf50E2Yr4quKeg6Iq/XdeWcNDrwfp3OHGCfsE74C5CVVJ0cI123e0VYN7dnssxXXJ5G+MNJia9zHex3/Q1Ozo/ErwggWZljW2fb44izHoxtui5UoBWXQ='

    __DUMMY_PEM = b'-----BEGIN CERTIFICATE-----\nMIIDlzCCAn8CFCL6J2nMHEk8bgycTYAi7JBwohp9MA0GCSqGSIb3DQEBCwUAMIGH\nMQswCQYDVQQGEwJKUDEOMAwGA1UECAwFT3Nha2ExDjAMBgNVBAcMBU9zYWthMQww\nCgYDVQQKDANzc3MxDDAKBgNVBAsMA3NzczEYMBYGA1UEAwwPd3d3LmV4YW1wbGUu\nY29tMSIwIAYJKoZIhvcNAQkBFhNzb21lb25lQGV4YW1wbGUuY29tMB4XDTIyMDMy\nMjAxMzYwNVoXDTMyMDMxOTAxMzYwNVowgYcxCzAJBgNVBAYTAkpQMQ4wDAYDVQQI\nDAVPc2FrYTEOMAwGA1UEBwwFT3Nha2ExDDAKBgNVBAoMA3NzczEMMAoGA1UECwwD\nc3NzMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20xIjAgBgkqhkiG9w0BCQEWE3Nv\nbWVvbmVAZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\nAQDMbsd67QjTaanaB74wcfOlvafcsDT7+aBTyRI36luKhBYUf0zNwJXReeRGrm4u\nJVL8Lp8+ia3la0rWgzduk/vO5jzOkcjF7urOpezVwwKEnpuxKQr1zHFWzh+W7XN8\nZl6Y4PQ1ErKjeNg+sWEKepedkNsoDRLpbu3kXobRIM5bvxGsMwPlBYF1glKPXfS3\nKWUBSUcX32S0WYlSY+81n4ru2McVVJ1W8ta2KBR2HxFzGnv1jamF97GcG2XS13q3\nf5BT3iQQi2UUwd7si1db3nh89xkUNsyiupQ1f4TJOD9sIi/r1UfsYdkjcZTiFZ2t\nuDsxDV2CVgbKfOzdAUGSAsR9AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAIjyPqzW\nk2Oo9RIpWcjJbSg4UHsJGo6jN9/bXtM4Wu/ngA0ciA0SxVRdAfUjp/IqmmOdQrTJ\nb3/8COhwYEQh67EHFyVpxruXjbuZ7OJVLq7p0Vk2BEUOQJfwlz6FJc7YCnIm8Ijq\nvgOtuwf1P6zJ7Q89FplZg985GuAtJpEGS3LmcQreHs/K5h1FAL4JVG88tfa/bd06\ntgldbnx+eESsImsj5Wh8eenf0Y0tf50E2Yr4quKeg6Iq/XdeWcNDrwfp3OHGCfsE\n74C5CVVJ0cI123e0VYN7dnssxXXJ5G+MNJia9zHex3/Q1Ozo/ErwggWZljW2fb44\nizHoxtui5UoBWXQ=\n-----END CERTIFICATE-----\n'

    def create_dummy_cert(self, before, after):
        dsa.generate_private_key
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
        builder = builder.not_valid_before(before)
        builder = builder.not_valid_after(after)
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

    def base64url_decode(self, b64url):
        return base64.urlsafe_b64decode(b64url + "=" * (4 - len(b64url) % 4))

    def test_check_certificate_01(self, mocker):
        """
        If an Exception occurs in check_certificate,
        False returned.
        """
        # mock set
        mocker.patch('cryptography.x509.load_der_x509_certificate', side_effect=Exception)

        # test
        result = _check_certificate(self.__DUMMY_CRT)

        # check
        assert result is False

    def test_check_certificate_02(self, mocker):
        """
        Certificate is too new.
        True returned because of no expiration check.
        """
        # mock set
        def create_cert(tmp):
            one_day = datetime.timedelta(1, 0, 0)
            before = datetime.datetime.today() + one_day
            after = datetime.datetime.today() + (one_day * 30)
            certificate = self.create_dummy_cert(before, after)
            return certificate

        mocker.patch('cryptography.x509.load_der_x509_certificate', side_effect=create_cert)

        # test
        result = _check_certificate(self.__DUMMY_CRT)

        # check
        assert result is True

    def test_check_certificate_03(self, mocker):
        """
        Certificate is too old.
        True returned because of no expiration check.
        """
        # mock set
        def create_cert(tmp):
            one_day = datetime.timedelta(1, 0, 0)
            before = datetime.datetime.today() - (one_day * 9000)
            after = datetime.datetime.today() - (one_day * 8000)
            certificate = self.create_dummy_cert(before, after)
            return certificate

        mocker.patch('cryptography.x509.load_der_x509_certificate', side_effect=create_cert)

        # test
        result = _check_certificate(self.__DUMMY_CRT)

        # check
        assert result is True

    def test_check_certificate_04(self):
        """
        Normal certificate.
        True returned.
        """
        # test
        result = _check_certificate(self.__DUMMY_CRT)

        # check
        assert result is True

    def test_check_certificate_05(self):
        """
        empty certificate.
        True returned.
        """
        # test
        result = _check_certificate("")

        # check
        assert result is True

    def test_to_b64_01(self):
        """
        Convert to base64.
        """
        # test
        result = _to_b64(self.__DUMMY_PEM)

        # check
        assert result == self.__DUMMY_CRT

    def test_to_b64_02(self):
        """
        Convert to base64.
        """
        # test
        result = _to_b64(self.__DUMMY_PEM.decode())

        # check
        assert result == self.__DUMMY_CRT

    def test_to_pem_01(self):
        """
        Convert to PEM.
        """
        # test
        result = _to_pem(self.__DUMMY_CRT)

        # check
        assert result == self.__DUMMY_PEM

    def test_get_random_hex_01(self):
        """
        Random string can be obtained.
        """
        # test
        result = _get_random_hex(None)

        # check
        assert len(result) == 64

    def test_aes_gcm(self):
        """
        AES-GCM encrypt/decrypt
        """
        msg = "Hello"
        KEY = "OTA2M0JERDBGMDY2ODVFNjI5REIxOEQwQkE4NURCMzE"
        IV = "ODlCMEY5NDE4OTU4QkFERg"

        key = self.base64url_decode(KEY)
        iv = self.base64url_decode(IV)

        #test
        encrypted = _aes_gcm_encrypt(msg.encode(), key, iv)
        decrypted = _aes_gcm_decrypt(encrypted, key, iv)

        #check
        assert msg == decrypted.decode()
