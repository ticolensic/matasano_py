import base64
import sys
import unittest
from random import randint

from ch01 import Base64, from_base64
from ch10 import encrypt_cbc, decrypt_cbc
from ch11 import generate_bytes, encryption_oracle_ecb_cbc, ecb_or_cbc
from ch12 import crack_ecb_simple, encryption_oracle_ecb, unknown_string
from ch13 import kv_parse, check_email, kv_return, encrypt_profile, decrypt_profile, attack_profile


class TestSet2(unittest.TestCase):
    main = [9, 10, 11, 12, 13, 14, 15, 16]
    supplementary = ["cbc", "oracle", "kv", "email", "profile"]
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
