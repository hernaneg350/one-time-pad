import unittest
import inspect
from io import BytesIO
import xor_cipher


class XORCipherTest(unittest.TestCase):
    def test_apply(self):
        pad = BytesIO(b"A random sequence of bytes")
        sut = xor_cipher.XORCipher(pad)

        encoded_message_gen = sut.apply(b"A message!")
        assert inspect.isgenerator(encoded_message_gen)

        encoded_message = list(encoded_message_gen)
        assert encoded_message[0] == b"A"[0] ^ b"A"[0]
        assert encoded_message[1] == b" "[0] ^ b" "[0]
        assert encoded_message[2] == b"r"[0] ^ b"m"[0]
        assert encoded_message[3] == b"a"[0] ^ b"e"[0]
        assert encoded_message[4] == b"n"[0] ^ b"s"[0]
        assert encoded_message[5] == b"d"[0] ^ b"s"[0]
        assert encoded_message[6] == b"o"[0] ^ b"a"[0]
        assert encoded_message[7] == b"m"[0] ^ b"g"[0]
        assert encoded_message[8] == b" "[0] ^ b"e"[0]
        assert encoded_message[9] == b"s"[0] ^ b"!"[0]

    def test_end_of_key_stream(self):
        pad = BytesIO(b"A short sequence of bytes")
        sut = xor_cipher.XORCipher(pad)

        self.assertRaises(xor_cipher.MessageOutOfRangeException, sut.apply, b"A very long sequence of bytes!")

    def test_end_of_key_stream_after_successive_calls(self):
        pad = BytesIO(b"A short sequence of bytes")
        sut = xor_cipher.XORCipher(pad)

        sut.apply(b"A short sequence")

        self.assertRaises(xor_cipher.MessageOutOfRangeException, sut.apply, b", that turned out to be very long")

    def test_end_of_key_stream_exception(self):
        pad = BytesIO(b"A short sequence of bytes")
        sut = xor_cipher.XORCipher(pad)

        sut.apply(b"A short sequence")

        try:
            sut.apply(b", that turned out to be very long")
        except xor_cipher.MessageOutOfRangeException as mor_ex:
            assert mor_ex.message == b"A short sequence, that turned out to be very long"
            assert mor_ex.key_length == 25


