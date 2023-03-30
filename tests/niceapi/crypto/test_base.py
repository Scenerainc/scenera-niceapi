"""Test for base."""
from src.niceapi.crypto.base import JoseFunction, JWSVerify, JWSSign, JWEDecrypt, JWEEncrypt


class TestJoseFunction:
    """JoseFunction test class."""
   
    class DummyVerify(JoseFunction):

        def __call__(self, arg1):
            return super().__call__(arg1)

    __verify = DummyVerify()

    def test___call___01(self):
        """
        Call a function of base class.
        """
        # test
        self.__verify(1)

        #check
        assert True


class TestJWSVerify:
    """JWSVerify test class."""
   
    class DummyJWSVerify(JWSVerify):

        def __call__(self, jws):
            return self.verify(jws)

        def verify(self, jws):
            super().verify(jws)
            pass

    __jws_verify = DummyJWSVerify()

    def test_verify_01(self):
        """
        Call a function of base class.
        """
        # test
        self.__jws_verify('abc')

        #check
        assert True


class TestJWSSign:
    """JWSSign test class."""
   
    class DummyJWSSign(JWSSign):

        def __call__(self, payload):
            return self.sign(payload)

        def sign(self, payload):
            super().sign(payload)
            pass

    __jws_sign = DummyJWSSign()

    def test_sign_01(self):
        """
        Call a function of base class.
        """
        # test
        self.__jws_sign('abc')

        #check
        assert True


class TestJWEDecrypt:
    """JWEDecrypt test class."""
   
    class DummyJWEDecrypt(JWEDecrypt):

        def __call__(self, jwe):
            return self.decrypt(jwe)

        def decrypt(self, jwe):
            super().decrypt(jwe)
            pass

    __jwe_decrypt = DummyJWEDecrypt()

    def test_decrypt_01(self):
        """
        Call a function of base class.
        """
        # test
        self.__jwe_decrypt('abc')

        #check
        assert True


class TestJWEEncrypt:
    """JWEEncrypt test class."""
   
    class DummyJWEEncrypt(JWEEncrypt):

        def __call__(self, plaintext):
            return self.encrypt(plaintext)

        def encrypt(self, plaintext):
            super().encrypt(plaintext)
            pass

    __jwe_encrypt = DummyJWEEncrypt()

    def test_encrypt_01(self):
        """
        Call a function of base class.
        """
        # test
        self.__jwe_encrypt('abc')

        #check
        assert True
