import unittest

from ch17 import encrypt_random_string, decrypt_check_padding, padding_oracle_attack


class TestSet3(unittest.TestCase):
    main = [17, 18, 19, 20, 21, 22, 23, 24]
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

    # this tests would run into padding collision:
    # sample b'6TT8JZQQHFSRGTAGWEEBEVAXDJFJQW6IGF7VJRE0QPPB25USY4LLNWFW3YYDNAIOM035F9F'
    # iv b"\xcf\xd5(\x94\xb0H\x14\xde\xd6\xd25\xb8`\xaa@"
    #####
    # iv b'\xb7\xcb\xf2\x1c\x10\xa2{\x99\x98m\x13\x00\xd78m\x1a'
    # sample - one of answers

    def test_challenge17(self):
        if 17 not in self.tests:
            self.skipTest("")
        # for i in range(1, 1024):
        #     bs = string.ascii_uppercase + string.digits
        #     expected = bytes(''.join(random.choices(bs, k=i)), "ascii")
        #     data = encrypt_random_string(teststring=expected)
        #     actual = padding_oracle_attack(data)
        #     self.assertEqual(expected, actual)
        answers = [
            b'000000Now that the party is jumping@',
            b"000001With the bass kicked in and the Vega's are pumpin'@",
            b'000002Quick to the point, to the point, no faking\x00@',
            b"000003Cooking MC's like a pound of bacon\x00@",
            b"000004Burning 'em, if you ain't quick and nimble",
            b'000005I go crazy when I hear a cymbal\x00@',
            b'000006And a high hat with a souped up tempo\x00@',
            b"000007I'm on a roll, it's time to go solo@",
            b"000008ollin' in my five point oh@",
            b'000009ith my rag-top down so my hair can blow'
        ]
        data = encrypt_random_string()
        actual = padding_oracle_attack(data)
        self.assertIn(actual, answers)

    # def test_challenge18(self):
    #     if 18 not in self.tests:
    #         self.skipTest("")
    #
    # def test_challenge19(self):
    #     if 19 not in self.tests:
    #         self.skipTest("")
    #
    # def test_challenge20(self):
    #     if 20 not in self.tests:
    #         self.skipTest("")
    #
    # def test_challenge21(self):
    #     if 21 not in self.tests:
    #         self.skipTest("")
    #
    # def test_challenge22(self):
    #     if 22 not in self.tests:
    #         self.skipTest("")
    #
    # def test_challenge23(self):
    #     if 23 not in self.tests:
    #         self.skipTest("")
    #
    # def test_challenge24(self):
    #     if 24 not in self.tests:
    #         self.skipTest("")


if __name__ == '__main__':
    unittest.main()
