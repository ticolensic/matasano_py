import base64
import sys
import unittest
from random import randint

from Crypto.Cipher import AES

from ch01 import Base64, from_base64
from ch09 import pkcs7_pad
from ch10 import encrypt_cbc, decrypt_cbc, strip_padding
from ch11 import generate_bytes, encryption_oracle_ecb_cbc, ecb_or_cbc
from ch12 import crack_ecb_simple, encryption_oracle_ecb, unknown_string
from ch13 import kv_parse, check_email, kv_return, encrypt_profile, decrypt_profile, attack_profile
from ch14 import crack_ecb_hard, encryption_oracle_ecb_hard
from ch15 import pkcs7_validate
from ch16 import encrypt_wrapper, check_admin, flip_bits, encrypt_cbc_fix, decrypt_cbc_fix, crack_admin


class TestSet2(unittest.TestCase):
    main = [9, 10, 11, 12, 13, 14, 15, 16]
    supplementary = ["cbc", "oracle", "kv", "email", "profile", "pre16", "flip"]

    # noinspection PyTypeChecker
    # tests = supplementary

    # noinspection PyTypeChecker
    tests = main + supplementary

    def test_challenge09(self):
        if 9 not in self.tests:
            self.skipTest("external resource not available")

        from ch09 import pkcs7_pad

        test = b"YELLOW SUBMARINE"
        expected = b"YELLOW SUBMARINE\x04\x04\x04\x04"
        actual = pkcs7_pad(test, 20)
        self.assertEqual(expected, actual)

    def test_encrypt_cbc(self):
        if "cbc" not in self.tests:
            self.skipTest("external resource not available")

        test = b"1234567890"
        expected = b"8vSCtvqVqJ1nFiDO39gBfg=="
        key = b"YELLOW SUBMARINE"
        actual = base64.b64encode(encrypt_cbc(test, key))
        self.assertEqual(expected, actual)

    def test_cbc(self):
        if "cbc" not in self.tests:
            self.skipTest("external resource not available")
        data = b"1234567890"
        key = b"YELLOW SUBMARINE"
        iv = 16 * b"\0"

        cipher = AES.new(key, AES.MODE_CBC, iv)
        expected = cipher.encrypt(pkcs7_pad(data, AES.block_size))
        actual = encrypt_cbc(data, key, iv)
        self.assertEqual(expected, actual)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        expected = strip_padding(cipher.decrypt(expected))
        actual = decrypt_cbc(actual, key, iv)
        self.assertEqual(expected, actual)

    def test_decrypt_cbc(self):
        if "cbc" not in self.tests:
            self.skipTest("external resource not available")

        expected = b"1234567890"
        test = base64.b64decode(b"8vSCtvqVqJ1nFiDO39gBfg==")
        key = b"YELLOW SUBMARINE"
        actual = decrypt_cbc(test, key)
        self.assertEqual(expected, actual)

    def test_challenge10(self):
        if 10 not in self.tests:
            self.skipTest("external resource not available")

        key = b"YELLOW SUBMARINE"

        with open("materials\\10.txt") as f:
            _input = Base64(f.read())
            _input = from_base64(_input)

        actual = decrypt_cbc(_input, key)
        expected = b"I'm back and I'm ringin'"

        self.assertEqual(expected, actual[:len(expected)])

    def test_oracle(self):
        if 'oracle' not in self.tests:
            self.skipTest("external resource not available")
        expected = generate_bytes(randint(1, 5))
        actual = encryption_oracle_ecb_cbc(expected, randint(1, 2) == 1)
        self.assertLess(len(expected), len(actual))

    def test_challenge11(self):
        if 11 not in self.tests:
            self.skipTest("external resource not available")
        sys.setrecursionlimit(1500)  # due to recursive functions, which was probably not a good idea
        for _ in range(1000):
            expected = randint(1, 2) == 1
            actual = ecb_or_cbc(lambda x: encryption_oracle_ecb_cbc(x, expected))
            self.assertEqual(expected, actual)

    def test_challenge12(self):
        if 12 not in self.tests:
            self.skipTest("external resource not available")
        expected = unknown_string
        actual = crack_ecb_simple(encryption_oracle_ecb)
        self.assertEqual(expected, actual[:len(expected)])

    def test_kv(self):
        if 'kv' not in self.tests:
            self.skipTest("external resource not available")
        expected = {'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'}
        actual = kv_parse("foo=bar&baz=qux&zap=zazzle")
        self.assertEqual(expected, actual)

        actual = kv_return({'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'})
        expected = "foo=bar&baz=qux&zap=zazzle"
        self.assertEqual(expected, actual)

    def test_check_email(self):
        if 'email' not in self.tests:
            self.skipTest("external resource not available")

        actual = check_email("foo@bar.com")
        expected = True
        self.assertEqual(expected, actual)

        actual = check_email("foo@bar.com&")
        expected = False
        self.assertEqual(expected, actual)

        actual = check_email("asdasd123123@.com")
        expected = False
        self.assertEqual(expected, actual)

        actual = check_email("foo@bar.com&role=admin")
        expected = False
        self.assertEqual(expected, actual)

    def test_profile(self):
        if 'profile' not in self.tests:
            self.skipTest("external resource not available")
        expected = "foo@bar.com"
        actual = encrypt_profile(expected)
        actual = decrypt_profile(actual)["email"]
        self.assertEqual(expected, actual)

    def test_challenge13(self):
        if 13 not in self.tests:
            self.skipTest("external resource not available")
        expected = "admin"
        actual = attack_profile()
        actual = decrypt_profile(actual)
        self.assertEqual(expected, actual["role"])

    def test_challenge14(self):
        if 14 not in self.tests:
            self.skipTest("external resource not available")
        expected = unknown_string
        actual = crack_ecb_hard(encryption_oracle_ecb_hard)
        self.assertEqual(expected, actual[:len(expected)])

    def test_challenge15(self):
        if 15 not in self.tests:
            self.skipTest("external resource not available")
        expected = True
        test = b"ICE ICE BABY\x04\x04\x04\x04"
        actual = pkcs7_validate(test)
        self.assertEqual(expected, actual)

        expected = False
        test = b"ICE ICE BABY\x05\x05\x05\x05"
        actual = pkcs7_validate(test)
        self.assertEqual(expected, actual)

        expected = False
        test = b"ICE ICE BABY\x01\x02\x03\x04"
        actual = pkcs7_validate(test)
        self.assertEqual(expected, actual)

    def test_ch16_mint(self):
        if "pre16" not in self.tests:
            self.skipTest("external resource not available")

        userData = b";admin=true;"
        enc = encrypt_wrapper(userData)
        isAdmin = check_admin(enc)
        self.assertFalse(isAdmin)

    def test_ch16_flip(self):
        if "flip" not in self.tests:
            self.skipTest("external resource not available")
        expected = b"MARSHALL Qg3!"
        temp = encrypt_cbc_fix(b"B" * 16 + b"A" * 48)

        flipped = flip_bits(temp, expected, 18)
        actual = decrypt_cbc_fix(flipped)
        self.assertIn(expected, actual)

    def test_ch16_flip_exception(self):
        if "flip" not in self.tests:
            self.skipTest("external resource not available")
        self.assertRaises(Exception, flip_bits, b"A" * 32, b"A" * 7, 30)
        self.assertRaises(Exception, flip_bits, b"A" * 32, b"A" * 7, 10)

    def test_challenge16(self):
        if 16 not in self.tests:
            self.skipTest("external resource not available")
        temp = crack_admin()
        actual = check_admin(temp)
        self.assertTrue(actual)
