class XORCipher:
    _full_message = b""
    _key_length = 0

    def __init__(self, key_stream):
        self.key_stream = key_stream

    def apply(self, message):
        message_length = len(message)
        key = self.key_stream.read(message_length)
        self._key_length += len(key)

        self._full_message += message

        if len(key) < message_length:
            raise MessageOutOfRangeException(self._full_message, self._key_length)

        def get_bytes():
            for i_byte in range(len(message)):
                key_byte = key[i_byte]
                message_byte = message[i_byte]

                yield key_byte ^ message_byte

        return get_bytes()


class MessageOutOfRangeException(Exception):
    def __init__(self, message, key_length):
        self.message = message
        self.key_length = key_length