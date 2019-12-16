import base64
import unittest
from random import randint

from ch01 import Base64, from_base64
from ch10 import encrypt_cbc, decrypt_cbc
from ch11 import generate_bytes, encryption_oracle


class TestSet2(unittest.TestCase):
    tests = [9, 10, 11, 12, 13, 14, 15, 16, "cbc", "oracle"]

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
        actual = encryption_oracle(expected)
        self.assertLess(len(expected), len(actual))
