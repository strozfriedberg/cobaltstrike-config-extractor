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

import logging
from mmap import mmap as MemoryMap, ACCESS_READ
from pathlib import Path
import re
from typing import Any, BinaryIO, ByteString, Dict, Optional, Set, Tuple

import pefile

from libcsce.error import (
    ConfigNotFoundError,
    InvalidCSVersionError,
    MissingDataSectionError,
    UnsupportedFileTypeError,
)
from libcsce.setting import BeaconSettings
from libcsce.typing import CobaltStrikeSource, ConfigSourceBuffer, ConfigBuffer
from libcsce.utils import xor_decode


logger = logging.getLogger(__name__)


class CobaltStrikeConfigParser:
    """Cobalt Strike Beacon config parser.

    Supports parsing both encrypted and/or encoded Beacon configs from PE files (DLL/EXE) and
    memory dumps taken from systems where a Beacon was running. Currently, Beacons generated
    using CobaltStrike versions 3.x and 4.x (latest major version) can be decrypted and decoded.
    The class should be used as a context manager *if parsing from a file on disk*, as that will
    ensure it closes any file handles before exiting. If parsing from a buffer (:class:`libcsce.typing.ConfigBuffer`)
    using as a context manager is not necessary.

    :param source: buffer containing, or file path pointing to, PE file or memory dump
    :param version: Cobalt Strike version (must be one of :attr:`.CobaltStrikeConfigParser.SUPPORTED_VERSIONS`)
    :param disable_decryption: disable decryption attempt of Beacon config data
    :param decryption_threshold: override the ``threshold`` used during decryption key search
                                 (see: :meth:`.CobaltStrikeConfigParser.gen_config_from_encrypted`)

    :ivar version: Cobalt Strike version (must be one of :attr:`.CobaltStrikeConfigParser.SUPPORTED_VERSIONS`)

    :Examples:

    Parse config from Beacon file on disk:

    >>> from pathlib import Path
    >>> from libcsce import CobaltStrikeConfigParser
    >>> with CobaltStrikeConfigParser(Path("testdata/exe-sample-01.bin"), 4) as beacon:
    ...     config = beacon.parse_config()
    >>> config["dns-beacon"]["dns_idle"]
    '0.0.0.0'

    Read Beacon to buffer then parse config:

    >>> from pathlib import Path
    >>> from libcsce import CobaltStrikeConfigParser
    >>> beacon_buffer = Path("testdata/exe-sample-01.bin").read_bytes()
    >>> beacon = CobaltStrikeConfigParser(beacon_buffer, 4)
    >>> config = beacon.parse_config()
    >>> config["dns-beacon"]["dns_idle"]
    '0.0.0.0'
    """

    __slots__ = (
        "_decryption_threshold",
        "_disable_decryption",
        "_source",
        "_tmp_file",
        "version",
    )

    #: Decoded Beacon config signature.
    #: Used to verify that decryption and/or decoding worked successfully.
    DECODED_SIGNATURE: bytes = (
        b"\x00\x01\x00\x01\x00\x02\x2e\x2e\x00\x02\x00\x01\x00\x02\x2e\x2e\x00"
    )
    #: Default for minimum occurrences of decryption key in encrypted Beacon config
    #: (see: :meth:`.CobaltStrikeConfigParser.gen_config_from_encrypted`).
    DEFAULT_DECRYPTION_THRESHOLD: int = 1100
    #: Static encoding keys for each supported Beacon version.
    ENCODE_XOR_KEYS: Dict[int, int] = {
        3: 0x69,
        4: 0x2E,
    }
    #: Encoded Beacon config signatures for each supported Beacon version.
    #: Use to detect encoded config data during the parsing process
    #: (see: :meth:`.CobaltStrikeConfigParser.gen_config_from_encoded`).
    ENCODED_SIGNATURES: Dict[int, bytes] = {
        3: b"\x69\x68\x69\x68\x69\x6b\x2e\x2e\x69\x6b\x69\x68\x69\x6b\x2e\x2e\x69\x6a",
        4: b"\x2e\x2f\x2e\x2f\x2e\x2c\x2e\x2e\x2e\x2c\x2e\x2f\x2e\x2c\x2e\x2e\x2e",
    }
    #: Size in bytes of the config data.
    SIZE: int = 4096
    #: Set of supported Beacon versions.
    SUPPORTED_VERSIONS: Set[int] = {3, 4}

    @classmethod
    def _find_encryption_xor_key(
        cls, buffer: ByteString, threshold: int
    ) -> Tuple[Optional[ByteString], Optional[int]]:
        """Find the XOR key to decrypt the Beacon config settings data.

        :param buffer: Buffer containing data from the ``.data`` section
        :param threshold: Minimum required number of occurrences of key in section
        :returns: XOR key and offset if found.
        """
        # make a histogram of 4-byte sequences aligned to 4-byte boundaries
        candidates = {}
        for offset in range(4, len(buffer), 4):
            candidate_key = buffer[offset : offset + 4]
            if candidate_key != b"\x00\x00\x00\x00":
                count, init_pos = candidates.get(candidate_key, (0, offset))
                candidates[candidate_key] = (count + 1, init_pos)

        # sort the sequences by initial appearance
        sequences = sorted(candidates.items(), key=lambda item: item[1][1])

        # return the earliest occuring sequence meeting the threshold
        return next(
            ((key, offset) for key, (count, offset) in sequences if count >= threshold),
            (None, None),
        )

    @classmethod
    def gen_config_from_encrypted(
        cls, source_buffer: ConfigSourceBuffer, threshold: Optional[int] = None
    ) -> Optional[ConfigBuffer]:
        """Decrypt config data from the ``.data`` section of a PE file.

        The ``.data`` section in Beacon PE files are often much larger than :attr:`CobaltStrikeConfigParser.SIZE`.
        Since XOR-ing with `0x00` produces the identity, a large portion of the ``.data`` section
        turns out to be the randomly-generated XOR key.  This function exploits that fact to find
        the key by counting the number of occurrences of each 4-byte sequence in the section,
        and choosing the sequence that occurs at least ``threshold`` times.
        Empirically the number of occurrences for the this sequence is much larger than the second
        most frequent sequence (hundreds more), and significantly larger than the third, fourth, fifth, etc.
        `RomanEmelyanov's parser <https://github.com/RomanEmelyanov/CobaltStrikeForensic/blob/master/L8_get_beacon.py>`_
        on GitHub provides another way to decrypt Beacon configs from non-PE files.
        This method will likely be included once it's understood more and can be tested.

        :param source_buffer: buffer to decrypt Beacon config data from
        :param threshold: override the ``threshold`` used during decryption key search
        :returns: If an encryption key is found, new buffer containing the decrypted config data, otherwise ``None``.
        """
        try:
            pe_file = pefile.PE(data=source_buffer)
        except pefile.PEFormatError as exc:
            raise UnsupportedFileTypeError(exc.value) from exc

        try:
            data_section_buffer = memoryview(
                next(sec for sec in pe_file.sections if b".data" in sec.Name).get_data()
            )
        except StopIteration as exc:
            raise MissingDataSectionError from exc

        if not threshold:
            threshold = cls.DEFAULT_DECRYPTION_THRESHOLD

        key, offset = cls._find_encryption_xor_key(data_section_buffer, threshold)
        if key:
            encrypted_size = int.from_bytes(
                data_section_buffer[offset - 4 : offset], "little"
            )
            encrypted_offset = ((offset << 4) + 1) >> 4
            encrypted_data = data_section_buffer[
                encrypted_offset : encrypted_offset + encrypted_size
            ]
            logger.debug(
                "Format: encrypted, offset: %s, key: %s, size: %s",
                encrypted_offset,
                key.tobytes(),
                encrypted_size,
            )
            return xor_decode(encrypted_data, key)

        return None

    @classmethod
    def gen_config_from_decoded(
        cls, source_buffer: ConfigSourceBuffer
    ) -> Optional[ConfigBuffer]:
        """Generate config data buffer from decoded Beacon.

        This function should be used after decrypting and/or decoding the Beacon config data
        using :meth:`.CobaltStrikeConfigParser.gen_config_from_encrypted` and
        :meth:`.CobaltStrikeConfigParser.gen_config_from_encoded`.

        :param source_buffer: buffer to extract Beacon config data from
        :returns: If the decoded config data signature is found, buffer containing config data, otherwise ``None``.
        """
        decoded_offset = re.search(cls.DECODED_SIGNATURE, source_buffer)  # type: ignore
        if decoded_offset and decoded_offset.start() > -1:
            logger.debug(
                "Format: decoded, offset: %s, size: %s",
                decoded_offset.start(),
                cls.SIZE,
            )
            return source_buffer[
                decoded_offset.start() : (decoded_offset.start() + cls.SIZE)
            ]
        return None

    @classmethod
    def gen_config_from_encoded(
        cls, source_buffer: ConfigSourceBuffer, version: int
    ) -> Optional[ConfigBuffer]:
        """Decode config data from the provided buffer.

        Cobalt Strike can encode Beacon config data with a static key, which depends on the version
        (see: :attr:`.CobaltStrikeConfigParser.ENCODE_XOR_KEYS`). Each version also has a distinct
        signature for encoded data (see: :attr:`.CobaltStrikeConfigParser.ENCODED_SIGNATURES`), which
        this function uses to determine the data offset. This function should be used after decrypting
        config data with :meth:`.CobaltStrikeConfigParser.gen_config_from_encrypted`, if necessary.

        :param source_buffer: buffer to decode Beacon config data from
        :param version: Cobalt Strike version
        :returns: If the encoded config data signature is found,
                  buffer containing decoded config data, otherwise ``None``.
        """
        encoded_offset = re.search(cls.ENCODED_SIGNATURES[version], source_buffer)  # type: ignore
        if encoded_offset and encoded_offset.start() > -1:
            logger.debug(
                "Format: encoded, offset: %s, size: %s",
                encoded_offset.start(),
                cls.SIZE,
            )
            config_buffer: ConfigBuffer = source_buffer[
                encoded_offset.start() : (encoded_offset.start() + cls.SIZE)
            ]
            return xor_decode(config_buffer, cls.ENCODE_XOR_KEYS[version])
        return None

    def __init__(
        self,
        source: CobaltStrikeSource,
        version: int,
        disable_decryption: bool = False,
        decryption_threshold: Optional[int] = None,
    ) -> None:
        if version not in self.SUPPORTED_VERSIONS:
            raise InvalidCSVersionError

        self._decryption_threshold = decryption_threshold
        self._disable_decryption = disable_decryption
        self._source = source
        self._tmp_file: Optional[BinaryIO] = None
        self.version = version

    def __enter__(self) -> "CobaltStrikeConfigParser":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if self._tmp_file:
            self._tmp_file.close()

    def gen_config_from_source(self) -> ConfigBuffer:
        """Decrypt and/or decode Beacon config data from the provided source.

        This function works in three steps:

        1. If decryption isn't disabled, attempt to decrypt the Beacon config data.
        2. Search the decoded data signature and, if found, return the decoded data.
        3. Otherwise, attempt to decode the config data and return it.

        :returns: If decryption and/or decoding were successful,
                  buffer containing Beacon config data, otherwise ``None``
        :raises ConfigNotFoundError: No config data identified after decryption and/or decoding
        """
        if isinstance(self._source, Path):
            self._tmp_file = self._source.open("rb")
            # ACCESS_READ is cross-platform, unlike prot, and should be used here
            source_buffer: ConfigSourceBuffer = MemoryMap(
                self._tmp_file.fileno(), 0, access=ACCESS_READ
            )
        else:
            source_buffer = self._source

        if not self._disable_decryption:
            try:
                decrypted_config_buffer = self.gen_config_from_encrypted(
                    source_buffer, self._decryption_threshold
                )
                if decrypted_config_buffer:
                    source_buffer = decrypted_config_buffer
            except UnsupportedFileTypeError as exc:
                logger.warning("Could not parse source as PE file (%s)", exc)

        config_buffer = self.gen_config_from_decoded(source_buffer)
        if config_buffer:
            return config_buffer

        config_buffer = self.gen_config_from_encoded(source_buffer, self.version)
        if config_buffer:
            return config_buffer
        raise ConfigNotFoundError

    def parse_config(self) -> Dict[str, Any]:
        """Parse Beacon config settings.

        Uses :meth:`.CobaltStrikeConfigParser.gen_config_from_source` to extract the Beacon config data
        and parse the settings using :class:`libcsce.setting.BeaconSettings`.

        :returns: Dictionary containing config settings
        """
        config_buffer = self.gen_config_from_source()
        settings = dict()
        for setting_name, value_parser in BeaconSettings().items():
            try:
                settings[setting_name] = value_parser.from_config(config_buffer)
            except Exception as exc:
                logger.warning(
                    "Failed to parse setting %s (%s)",
                    setting_name,
                    exc,
                )
        return settings
