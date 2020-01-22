import unittest

from ch01 import to_base64, from_hex, to_hex, from_base64, Hex, Base64
from ch02 import fixed_xor
from ch03 import crack_sb_xor_v2, english_scoring
from ch04 import detect_xor
from ch05 import repeating_xor
from ch06 import hamming_distance, break_repeating_xor
from ch07 import decrypt_aes_128_ecb
from ch08 import detect_ecb


class TestSet1(unittest.TestCase):
    # tests = [6]
    tests = [1, 2, 3, 4, 5, 6, 7, 8, "hd", "base64", "scoring"]

    def test_challenge1(self):
        if 1 not in self.tests:
            self.skipTest("")
        string = Hex("49276d206b696c6c696e6720796f757220627261696e206c"
                     "696b65206120706f69736f6e6f7573206d757368726f6f6d")
        test_string = Base64("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBs"
                             "aWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

        b64 = to_base64(from_hex(string))
        self.assertEqual(b64, test_string)

    def test_challenge2(self):
        if 2 not in self.tests:
            self.skipTest("")
        data = Hex("1c0111001f010100061a024b53535009181c")
        key = Hex("686974207468652062756c6c277320657965")
        answer = Hex("746865206b696420646f6e277420706c6179")

        output = fixed_xor(from_hex(data), from_hex(key))
        self.assertEqual(output, from_hex(answer))

    def test_challenge3(self):
        if 3 not in self.tests:
            self.skipTest("")
        test_string = Hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        output = crack_sb_xor_v2(from_hex(test_string))
        answer = b"Cooking MC's like a pound of bacon"
        self.assertEqual(output, answer)

    def test_challenge4(self):
        if 4 not in self.tests:
            self.skipTest("")
        answer = b"Now that the party is jumping\n"
        with open("materials\\4.txt") as f:
            _input = list(map(from_hex, f.read().splitlines()))
        output = detect_xor(_input)
        self.assertEqual(output, answer)

    def test_challenge5(self):
        if 5 not in self.tests:
            self.skipTest("")
        answer1 = Hex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272")
        answer2 = Hex("a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
        key = b"ICE"
        test = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

        output = repeating_xor(test, key)
        self.assertEqual(to_hex(output), answer1 + answer2)

    def test_challenge6(self):
        if 6 not in self.tests:
            self.skipTest("")
        expected_output = b'Terminator X: Bring the noise'

        with open("materials\\6.txt") as f:
            _input = Base64(f.read())
            _input = from_base64(_input)
        result = break_repeating_xor(_input)

        self.assertEqual(result, expected_output)

    def test_challenge7(self):
        expected = b"I'm back and I'm ringin"
        if 7 not in self.tests:
            self.skipTest("")
        key = b"YELLOW SUBMARINE"
        with open("materials\\7.txt") as f:
            _input = Base64(f.read())
            _input = from_base64(_input)
        actual = decrypt_aes_128_ecb(_input, key)
        self.assertEqual(actual[:len(expected)], expected)

    def test_challenge8(self):
        if 8 not in self.tests:
            self.skipTest("")
        answer = Hex(
            "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744c"
            "d283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c"
            "744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2"
            "d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4f"
            "d5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2"
            "c123c58386b06fba186a")
        with open("materials\\8.txt") as f:
            _input = f.read()
            _input = [from_hex(Hex(x)) for x in _input.splitlines()]
        result = [x for x in _input if detect_ecb(x)]
        self.assertEqual(len(result), 1)
        result = to_hex(result[0])
        self.assertEqual(answer, result)

    def test_from_base64(self):
        if "base64" not in self.tests:
            self.skipTest("")
        test_input = Base64("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
        answer = Hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
        output = to_hex(from_base64(test_input))
        self.assertEqual(output, answer)

    def test_hd(self):
        if "hd" not in self.tests:
            self.skipTest("")
        test_input1 = b"this is a test"
        test_input2 = b"wokka wokka!!!"
        result = hamming_distance(test_input1, test_input2)
        self.assertEqual(result, 37)

    def test_scoring(self):
        """
        This function shows various scoring results against a couple of strings. English must be positive.
        """
        if "scoring" not in self.tests:
            self.skipTest("")
        test_input = {
            "english":   [
                b"This function shows various scoring results against a couple of strings.English must be positive."
            ],
            "gibberish": [
                b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
            ]
        }
        english = list(filter(lambda x: english_scoring(x) < 0, test_input["english"]))
        gibberish = list(filter(lambda x: english_scoring(x) > 0, test_input["gibberish"]))
        self.assertEqual(len(english), 0)
        self.assertEqual(len(gibberish), 0)

    def test_scoring2(self):
        if "scoring" not in self.tests:
            self.skipTest("")
        with open("materials\\longread.txt") as f:
            text = f.read().encode()
        ret = english_scoring(text)
        self.assertGreater(ret, 0, "Scoring system failed")
