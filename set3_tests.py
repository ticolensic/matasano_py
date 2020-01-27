import string
import unittest
import random

from ch10 import decrypt_cbc
from ch17 import encrypt_random_string, decrypt_check_padding, padding_oracle_attack, fixkey


class TestSet3(unittest.TestCase):
    main = [17, 18, 19, 20, 21, 22, 23, 24]
    main = [17]
    supplementary = ["17routines"]
    # noinspection PyTypeChecker
    tests = main + supplementary

    def test_r17routines(self):
        if "17routines" not in self.tests:
            self.skipTest("")
        for _ in range(30):
            data = encrypt_random_string()
            decrypt_check_padding(data)
            # self.assertTrue(actual)

    def test_challenge17(self):
        if 17 not in self.tests:
            self.skipTest("")
        # for i in range(16, 32):
        #     bs = string.ascii_uppercase + string.digits
        #     expected = bytes(''.join(random.choices(bs, k=i)), "ascii")
        #     data = encrypt_random_string(teststring=expected)
        #     actual = padding_oracle_attack(data)
        #     self.assertEqual(expected, actual)

        data = encrypt_random_string()
        actual = padding_oracle_attack(data)
        print(bytes(actual))

    def test_challenge18(self):
        if 18 not in self.tests:
            self.skipTest("")

    def test_challenge19(self):
        if 19 not in self.tests:
            self.skipTest("")

    def test_challenge20(self):
        if 20 not in self.tests:
            self.skipTest("")

    def test_challenge21(self):
        if 21 not in self.tests:
            self.skipTest("")

    def test_challenge22(self):
        if 22 not in self.tests:
            self.skipTest("")

    def test_challenge23(self):
        if 23 not in self.tests:
            self.skipTest("")

    def test_challenge24(self):
        if 24 not in self.tests:
            self.skipTest("")


if __name__ == '__main__':
    unittest.main()
