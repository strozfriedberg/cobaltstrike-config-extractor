## Copyright 2021 Aon plc
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
## http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.

from base64 import b64encode as b64_encode
from io import BytesIO
import json
import struct
from typing import Any, ByteString, Union

from libcsce.typing import ConfigBuffer


class JSONEncoderWithBinarySupport(json.JSONEncoder):
    """JSON encoder that supports binary data with Base64."""

    def default(self, o: Any) -> Any:
        if isinstance(o, (bytearray, bytes)):
            return b64_encode(o).decode("utf-8", errors="replace")
        return super().default(o)


def bytes_as_string(buffer: ConfigBuffer) -> str:
    """Convert bytes to string representation.

    Intended to mimic the byte literal syntax used in Malleable C2 profiles
    (see: `<https://www.cobaltstrike.com/help-malleable-postex>`_).

    :param buffer: bytes to convert to string
    :returns: string representation of the buffer

    :Examples:

    Convert NOOP sled bytes to a string:

    >>> from libcsce.utils import bytes_as_string
    >>> buffer = b"\\x90\\x90\\x90\\x90\\x90"
    >>> bytes_as_string(buffer)
    '\\\\x90\\\\x90\\\\x90\\\\x90\\\\x90'
    """
    return "".join(f"\\x{byte:0x}" for byte in buffer)


def _read_encoded_string_from_buffer(
    encoded_str: ConfigBuffer, length_format: str
) -> str:
    length_size = struct.calcsize(length_format)
    length = struct.unpack(length_format, encoded_str[:length_size])[0]
    return encoded_str[length_size : (length_size + length)].decode(
        "utf-8", errors="replace"
    )


def _read_encoded_string_from_stream(stream: BytesIO, length_format: str) -> str:
    length_size = struct.calcsize(length_format)
    length = struct.unpack(length_format, stream.read(length_size))[0]
    return stream.read(length).decode("utf-8", errors="replace")


def read_encoded_string(
    buffer_or_stream: Union[BytesIO, ConfigBuffer], length_format: str
) -> str:
    """Read and decode length-value encoded string.

    Some settings in Beacon configs contain encoded strings with a length prefix:
    ``<length of string><string content>``. This function unpacks the length
    using ``length_format``, then reads that many bytes and decodes them as UTF-8.

    :param buffer_or_stream: source to read data from
    :param length_format: format to use when unpacking the length
        (see: `struct formats <https://docs.python.org/3/library/struct.html#format-characters>`_)
    :returns: decoded string
    :raises:
        UnicodeDecodeError: if the encoded string contains non-UTF-8 characters

    :Examples:

    Read encoded string ``"hello, world!"`` from a buffer:

    >>> from libcsce.utils import read_encoded_string
    >>> buffer = b"\\x0Dhello, world!"
    >>> read_encoded_string(buffer, "B")
    'hello, world!'
    """
    if isinstance(buffer_or_stream, BytesIO):
        return _read_encoded_string_from_stream(buffer_or_stream, length_format)
    return _read_encoded_string_from_buffer(buffer_or_stream, length_format)


def xor_decode(buffer: ByteString, raw_key: Union[ByteString, int]) -> bytes:
    """XOR-decode buffer with key.

    :param buffer: buffer to decode bytes from
    :param raw_key: key to XOR with
    :returns: new decoded buffer

    :Examples:

    Decode buffer with key ``0x6D``:

    >>> from libcsce.utils import xor_decode
    >>> buffer = b"\\x0Dhello, world!"
    >>> xor_decode(buffer, 0x6D)
    b'`\\x05\\x08\\x01\\x01\\x02AM\\x1a\\x02\\x1f\\x01\\tL'

    Decode buffer with key ``b"\\x01\\x02\\x03\\x04"``:

    >>> from libcsce.utils import xor_decode
    >>> buffer = b"\\x0Dhello, world!"
    >>> xor_decode(buffer, b"\\x01\\x02\\x03\\x04")
    b'\\x0cjfhmm/$vmqhe#'
    """
    if isinstance(raw_key, int):
        key: ByteString = raw_key.to_bytes(1, "little")
    else:
        key = raw_key
    key_length = len(key)

    return bytes(byte ^ key[idx % key_length] for idx, byte in enumerate(buffer))
