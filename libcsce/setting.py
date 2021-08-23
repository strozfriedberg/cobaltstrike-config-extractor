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

from collections import OrderedDict
from enum import Enum
from io import BytesIO
from ipaddress import IPv4Address
import logging
import struct
from typing import Any, Dict, List, Optional, Set, Union

from libcsce.typing import ConfigBuffer
from libcsce.utils import bytes_as_string, read_encoded_string


logger = logging.getLogger(__name__)


class BeaconSettingType(Enum):
    """Cobalt Strike beacon settings types.

    Each Beacon setting has one of three basic types:

    1. :attr:`.BeaconSettingType.SHORT`
    2. :attr:`.BeaconSettingType.INT`
    3. :attr:`.BeaconSettingType.STR`

    These types can mean different things depending on the setting.
    For example, the ``SHORT`` type is used for enum settings, like ``beacontype``, that have a small number of options.
    Another example is that the ``INT`` type is used to store IPv4 addresses.
    Each custom setting parser has a setting type, which determines the setting's signature,
    then implements parsing logic on top of that type.
    """

    #: 2 byte integer
    SHORT = 1
    #: 4 byte integer, also used for IPv4 addresses and dates
    INT = 2
    #: Variable length string or binary blob
    STR = 3

    def length(self) -> Optional[int]:
        """Length of beacon setting type.

        .. note::
            :attr:`.BeaconSettingType.STR` types are variable length so this function returns ``None`` for them.

        :returns: Length in bytes of the type
        """
        if self == self.SHORT:
            return 2
        if self == self.INT:
            return 4
        return None


class BeaconSetting:
    """Base config setting parser class.

    Each Beacon config is effectively an ordered (binary) list of settings, where each setting
    is assigned a number, or ``position``, and a fundamental type (see: :class:`.BeaconSettingType`).
    The binary signature of each setting is six bytes and is comprised of its
    ``position``, fundamental type, and length (sometimes called TLV format).
    This class implements the base functionality required to discover and parse Beacon config settings,
    including generating the setting signature and finding that signature in a buffer.

    :param position: position number of the setting
    :param length_override: manually set the setting length instead of using :attr:`VALUE_TYPE.length`
                            (required for string/binary settings)

    :ivar length: length of the setting in bytes
    :ivar position: position number of the setting
    :ivar signature: six byte signature of the setting

    .. note::
        The :attr:`VALUE_TYPE` class variable declares the fundamental type of the setting.
        It is arbitrarily set to :attr:`.BeaconSettingType.SHORT` in this class and
        must be overridden for non-``SHORT`` settings.

    .. automethod:: _from_setting_data
    """

    __slots__ = ("length", "position", "signature")
    #: Fundamental type of the setting (see: :class:`.BeaconSettingType`)
    VALUE_TYPE: BeaconSettingType = BeaconSettingType.SHORT

    def __init__(self, position: int, length_override: Optional[int] = None) -> None:
        if self.VALUE_TYPE == BeaconSettingType.STR and length_override is None:
            raise ValueError("length_override is required for string settings")
        self.position = position
        self.length = (
            length_override if length_override is not None else self.VALUE_TYPE.length()
        )
        self.signature = self.gen_signature()

    def gen_signature(self) -> bytearray:
        """Generate six byte signature for the setting.

        The signature is comprised of its position number, integer representation of its fundamental type, and length.
        The signature cannot be static because the STR setting type is variable length.
        This function is used in the constructor, and must be called after setting position and length.
        """
        signature = bytearray(6)
        signature[1] = self.position
        signature[3] = self.VALUE_TYPE.value
        # NOTE: The check in __init__ ensures self.length isn't None
        signature[4:6] = self.length.to_bytes(2, "big")  # type: ignore
        return signature

    def _from_setting_data(self, setting_data: ConfigBuffer) -> Any:
        """Parse the setting data.

        All logic for parsing settings should be contained within this function,
        and it **must be overridden in child classes**. :meth:`BeaconSetting.from_config`
        implements basic logic to detect the setting signature and calls this method.
        If child class implementations can trigger exceptions, those should be documented in
        the child class docstrings.

        :param setting_data: buffer to parse setting data from
        :returns: Parsed setting data
        """
        raise NotImplementedError

    def from_config(self, config: ConfigBuffer) -> Any:
        """Detect setting signature in config and parse the setting data.

        If the setting signature is present in the config buffer, this method calls
        :meth:`.BeaconSetting._from_setting_data` with a buffer containing just the setting data,
        which is generated using the setting length (plus the signature). Otherwise returns ``None``.
        Consequently, the return type of this function in child classes should always be ``Optional[T]``
        where ``T`` is the return type of :meth:`.BeaconSetting._from_setting_data`.

        :param config: config buffer to parse setting data from
        :returns: Parsed setting data
        """
        signature_len = len(self.signature)
        offset = config.find(self.signature)
        if offset == -1:
            return None

        setting_data = config[(offset + signature_len) : (offset + signature_len + self.length)]  # type: ignore
        return self._from_setting_data(setting_data)


class NestedBeaconSetting(BeaconSetting):  # pylint: disable=abstract-method
    """Nested mapping of beacon settings.

    Cobalt Strike Malleable C2 profiles contain "groups" of settings,
    such as ``http-get``, that are nested under the group name in the profile.
    For example, the ``http-get`` group may look something like the following::

        http-get {
            set uri "/foobar";
            client {
                metadata {
                    base64;
                    prepend "user=";
                    header "Cookie";
                }
            }
        }

    This class allows for parsing the settings from the ``http-get`` and other groups
    into a nested ``dict`` structure that mimics the Malleable C2 profile itself.

    :param setting_map: mapping of setting names to setting parsers (:class:`.BeaconSetting`)

    :Examples:

    Replicate the ``http-get`` structure in the example above:

    .. code-block:: python

        http_get = NestedBeaconSetting(
            {
                "uri": HttpGetUriSetting(8),
                "client": NestedBeaconSetting(
                    {
                        "metadata": MalleableC2HttpClientTransformSetting(12, 0),
                    }
                ),
            }
        )
        # use http_get to parse a config buffer with http_get.from_config(config_buffer)
    """

    __slots__ = ("_setting_map",)

    def __init__(  # pylint: disable=super-init-not-called
        self, setting_map: Dict[str, BeaconSetting]
    ) -> None:
        self._setting_map = setting_map

    def from_config(self, config: ConfigBuffer) -> Dict[str, Any]:
        return {
            setting_name: value_parser.from_config(config)
            for setting_name, value_parser in self._setting_map.items()
        }


class ShortIntSetting(BeaconSetting):
    """Short setting (2 byte integer)."""

    __slots__ = ()
    VALUE_TYPE = BeaconSettingType.SHORT

    def _from_setting_data(self, setting_data: ConfigBuffer) -> int:
        return struct.unpack(">H", setting_data)[0]


class BoolSetting(ShortIntSetting):
    """Boolean setting.

    Parses a :attr:`.BeaconSettingType.SHORT` as a boolean, where ``0`` means ``False`` by default.

    :param false_value: The integer value to use as ``False`` (any other value is considered ``True``)
    """

    __slots__ = ("_false_value",)

    def __init__(self, *args, false_value: int = 0, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._false_value = false_value

    def _from_setting_data(self, setting_data: ConfigBuffer) -> bool:
        value = super()._from_setting_data(setting_data)
        return value != self._false_value


class EnumSetting(ShortIntSetting):
    """Enum setting.

    Parses a :attr:`.BeaconSettingType.SHORT` and looks that value up in the provided ``value_mapping``.

    :param value_map: mapping from integer values to string representations of those values

    :Examples:

    Beacons support connecting to and using proxies, which is configurable in the Aggressor UI when generating a beacon.
    There are three options:

    1. Use a direct connection to the C2
    2. Use the IE settings on the compromised (Windows) system
    3. Use a specific proxy server

    This setting is a good use case for a simple enum mapping:

    >>> from libcsce.setting import EnumSetting
    >>> proxy_behavior = EnumSetting(
    ...     35,
    ...     value_map={
    ...         0x1: "Use direct connection",
    ...         0x2: "Use IE settings",
    ...         0x4: "Use proxy server",
    ...     },
    ... )
    """

    __slots__ = ("_value_map",)

    def __init__(self, *args, value_map: Dict[int, str], **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._value_map = value_map

    def _from_setting_data(self, setting_data: ConfigBuffer) -> str:  # type: ignore
        value = super()._from_setting_data(setting_data)
        return self._value_map[value]


class FlagEnumSetting(EnumSetting):
    """Bitmask-like setting.

    Similar to an :class:`.EnumSetting` except that the integer value represents a
    bitmask of values from an enum, and thus this setting produces a list of options.

    :Examples:

    Beacons can communicate with a Team Server or parent Beacon through different channels,
    including HTTP(S), DNS, SMB and TCP:

    >>> from libcsce.setting import FlagEnumSetting
    >>> beacontype = FlagEnumSetting(
    ...     1,
    ...     value_map={
    ...         0x0: "HTTP",
    ...         0x1: "Hybrid HTTP DNS",
    ...         0x2: "SMB",
    ...         0x4: "TCP",
    ...         0x8: "HTTPS",
    ...         0x10: "Bind TCP",
    ...     },
    ... )

    .. note::
        It's currently unclear whether the ``beacontype`` setting is truly a bitmask or really just an enum.
        This may be updated in the future based on additional research.
    """

    __slots__ = ()

    def _from_setting_data(self, setting_data: ConfigBuffer) -> List[str]:  # type: ignore
        value = ShortIntSetting._from_setting_data(self, setting_data)
        flags = list()
        for flag_value, flag_label in self._value_map.items():
            if flag_value == 0 and flag_value == value:
                flags.append(flag_label)
            elif flag_value & value:
                flags.append(flag_label)
        return flags


class IntSetting(BeaconSetting):
    """Int setting (4 byte integer)."""

    __slots__ = ()
    VALUE_TYPE = BeaconSettingType.INT

    def _from_setting_data(self, setting_data: ConfigBuffer) -> int:
        return struct.unpack(">I", setting_data)[0]


class IpAddressSetting(IntSetting):
    """IPv4 address setting.

    Used to parse the ``dns_idle`` setting.
    """

    __slots__ = ()

    def _from_setting_data(self, setting_data: ConfigBuffer) -> str:  # type: ignore
        value = super()._from_setting_data(setting_data)
        return IPv4Address(value).exploded


class DateSetting(IntSetting):
    """Date setting.

    Used to parse the ``kill_date`` setting.
    """

    __slots__ = ()

    def _from_setting_data(self, setting_data: ConfigBuffer) -> Optional[str]:  # type: ignore
        value = super()._from_setting_data(setting_data)
        if value == 0:
            return None

        date_str = str(value)
        return f"{date_str[0:4]}-{date_str[4:6]}-{date_str[6:]}"


class VariableLengthStringSetting(BeaconSetting):
    """Variable length string or binary blob setting.

    All non-binary blobs are decoded using UTF-8.

    :param is_binary: treat the setting data as a binary blob
    """

    __slots__ = ("_is_binary",)
    VALUE_TYPE = BeaconSettingType.STR

    def __init__(self, *args, is_binary: bool = False, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._is_binary = is_binary

    def _from_setting_data(
        self, setting_data: ConfigBuffer
    ) -> Union[str, ConfigBuffer]:
        if self._is_binary:
            return setting_data
        return setting_data.rstrip(b"\x00").decode("utf-8", errors="replace")


class Length256StrSetting(BeaconSetting):
    """:attr:`.BeaconSettingType.STR`-type setting with length 256 bytes."""

    __slots__ = ()
    VALUE_TYPE = BeaconSettingType.STR

    def __init__(self, *args, **kwargs) -> None:
        kwargs["length_override"] = 256
        super().__init__(*args, **kwargs)

    def _from_setting_data(self, setting_data: ConfigBuffer) -> Any:
        return setting_data


class ServerHostnameSetting(Length256StrSetting):
    """C2 server hostname setting.

    The C2 server and HTTP GET URI are stored in the same setting as a comma-separated string
    of the form ``<hostname>,<http_get_uri>``. This class parses the hostname from that string,
    and :class:`HttpGetUriSetting` parses the URI.

    .. todo:: Determine what happens when multiple C2 IPs/hostnames are present (if that's possible).
    """

    __slots__ = ()

    def _from_setting_data(self, setting_data: ConfigBuffer) -> str:
        return (
            setting_data.rstrip(b"\x00")
            .split(b",")[0]
            .decode("utf-8", errors="replace")
        )


class HttpGetUriSetting(ServerHostnameSetting):
    """HTTP GET URI setting.

    The C2 server and HTTP GET URI are stored in the same setting as a comma-separated string
    of the form ``<hostname>,<http_get_uri>``. This class parses the HTTP GET URI from that string,
    and :class:`ServerHostnameSetting` parses the hostname.
    """

    __slots__ = ()

    def _from_setting_data(self, setting_data: ConfigBuffer) -> Optional[str]:  # type: ignore
        uri_data = setting_data.rstrip(b"\x00").split(b",")
        if len(uri_data) > 1:
            return uri_data[1].decode("utf-8", errors="replace")
        return None


class MalleableC2Transform(Enum):
    """Data transform language actions.

    Cobalt Strike has a data transform language that describes how the Team Server and Beacon
    should transform data before sending or receiving and interpreting it. Some statements take a parameter
    (``append``) and some don't (``base64``). All data transforms end with a termination statement,
    of which there are four (see :meth:`.MalleableC2Transform.is_termination_transform`).
    The ``Data Transform Language`` section on the
    `Malleable C2 support page <https://cobaltstrike.com/help-malleable-c2>`_
    has a listing of all the transforms and more information on how they're used.

    .. note::
        Need to determine what ``9`` and ``10`` mean, and if there are values above ``15``.
    """

    #: ``append "<string>"`` -> remove last LEN(``<string>``) characters
    APPEND = 1
    #: ``prepend "<string>"`` -> remove first LEN(``<string>``) characters
    PREPEND = 2
    #: ``base64`` -> Base64 decode
    BASE64 = 3
    #: ``print`` -> send data as transaction body
    PRINT = 4
    #: ``parameter "<name>"`` -> store data in URI parameter ``<name>`` (HTTP comms)
    PARAMETER = 5
    #: ``header "<name>"`` -> store data in HTTP header ``<name>`` (HTTP comms)
    HEADER = 6
    #: Purpose unknown
    BUILD = 7
    #: ``netbios`` -> netbios decode 'a'
    NETBIOS = 8
    #: ``netbiosu`` -> netbios decode 'A'
    NETBIOSU = 11
    #: ``uri-append`` -> append data to URI
    URI_APPEND = 12
    #: ``base64url`` -> URL-safe Base64 decode
    BASE64URL = 13
    #: ``strrep "<find>" "<replace>"`` -> replace ``<find>`` with ``<replace>``
    STRREP = 14
    #: ``mask`` -> XOR mask with random key
    MASK = 15

    def is_termination_transform(self) -> bool:
        """Transform statement is a termination statement.

        All data transforms must end with a termination statement,
        so these statements indicate the end of parsing any transforms.
        """
        return self in {
            self.HEADER,
            self.PARAMETER,
            self.PRINT,
            self.URI_APPEND,
        }

    def has_associated_data(self) -> bool:
        """Transform statement takes at least one parameter.

        Some transform statements take parameters, which means those parameters need to be parsed.
        This function can be used to determine whether a statement requires further parsing of parameter data.
        """
        return self in {
            self.APPEND,
            self.PREPEND,
            self.PARAMETER,
            self.HEADER,
            self.STRREP,
        }


class MalleableC2HttpClientHeadersSetting(Length256StrSetting):
    """HTTP client headers.

    HTTP headers can be used to mimic services like Amazon or CDNs that have standard headers in each request.

    .. note::
        The ``http-get`` and ``http-post`` setting groups' ``client`` and ``server`` groups
        are stored in individual config settings with the following structure:

        <arbitrary HTTP headers>0x07<data transform statements>[,0x07<data transform statements>]

        Even though these data are stored in the same setting, *this class specifically parses
        the HTTP headers* and leaves parsing the data transform statements to other classes
        (see: :class:`.MalleableC2TransformSetting`). Splitting up parsing this way allow for
        less complex parser classes and more easily mimicing the Malleable C2 profile structure.
    """

    __slots__ = ()

    def _from_setting_data(self, setting_data: ConfigBuffer) -> List[str]:
        # NOTE: This actually contains the headers and other blocks in the http-get and http-post blocks.
        #       The headers comes first, then other configuration blocks are separated by \x07.
        header_end_offset = setting_data.find(b"\x07")
        if header_end_offset == -1:
            header_data = setting_data
        else:
            header_data = setting_data[:header_end_offset]

        headers = [
            read_encoded_string(header, "B")
            for header in header_data.strip(b"\x00").split(b"\x00")
            if len(header) > 1
        ]
        return headers


class MalleableC2TransformSetting(Length256StrSetting):
    """Base class for parsing HTTP client and server data transform statements.

    Data transform statements and the associated parameters are stored consecutively in the buffer.
    This class implements common functionality for parsing transforms to their string versions,
    as close to how they appear in the Malleable C2 profile as possible.

    .. automethod:: _gen_statement_from_transform
    .. automethod:: _gen_transforms_from_stream
    """

    __slots__ = ()

    @staticmethod
    def _gen_statement_from_transform(
        transform: MalleableC2Transform, stream: BytesIO
    ) -> str:
        """Generate a transform statement string.

        For transform statements that don't take parameters, this function should just return
        the string version of that statement. For those that do, the parameter data should be parsed
        from the provided ``stream``. **Must be overridden in child classes**.

        :param transform: data transform statement enum value
        :param stream: stream of setting data to parse parameter data from, if necessary
        :returns: string version of the transform statement
        """
        raise NotImplementedError

    @classmethod
    def _gen_transforms_from_stream(
        cls, stream: BytesIO, stream_length: int, value_format: str, exclude: Set[int]
    ) -> List[str]:
        """Generate a list of transform statement strings.

        Calls :meth:`.MalleableC2TransformSetting._gen_statement_from_transform` after parsing the transform value.

        :param stream: stream of setting data to parse transform statements from
        :param stream_length: length of the stream
        :param value_format: ``struct`` format to use for unpacking transform statement values
        :param exclude: transform statement values to exclude
        :returns: list of string versions of the transform statements
        """
        value_length = struct.calcsize(value_format)
        transforms = list()

        while stream.tell() < stream_length:
            transform_value = struct.unpack(value_format, stream.read(value_length))[0]
            if transform_value not in exclude:
                try:
                    transform = MalleableC2Transform(transform_value)
                except ValueError:
                    logger.warning("Invalid transform value %s", transform_value)
                    continue
                transforms.append(cls._gen_statement_from_transform(transform, stream))
        return transforms


class MalleableC2HttpClientTransformSetting(MalleableC2TransformSetting):
    """HTTP client data transform statements.

    See :class:`.MalleableC2HttpClientHeadersSetting` for an explanation of the binary structure
    of the settings that contain data transform statements. ``section_idx`` is used to determine
    which transform statement section to parse if the setting contains more than one (i.e., ``http-post -> client``).

    :param section_idx: data transforms section index (from 0)
    :param exclude_transforms: set of transform statement values to exclude, if any
    """

    __slots__ = (
        "_exclude_transforms",
        "_section_idx",
    )

    @staticmethod
    def _gen_statement_from_transform(
        transform: MalleableC2Transform, stream: BytesIO
    ) -> str:
        action = transform.name.lower()
        if transform.has_associated_data():
            action = f"{action} '{read_encoded_string(stream, 'B')}'"
        return action

    def __init__(
        self,
        *args,
        section_idx: int,
        exclude_transforms: Optional[Set[int]] = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._section_idx = section_idx
        self._exclude_transforms = exclude_transforms or set()

    def _from_setting_data(self, setting_data: ConfigBuffer) -> Optional[List[str]]:
        header_end_offset = setting_data.find(b"\x07")
        if header_end_offset == -1:
            return None

        transform_data = (
            setting_data[header_end_offset + 1 :]
            .strip(b"\x00")
            .replace(b"\x00\x00\x00", b"")
            .split(b"\x07")
        )[self._section_idx]
        return self._gen_transforms_from_stream(
            BytesIO(transform_data), len(transform_data), "B", self._exclude_transforms
        )


class MalleableC2ServerOutputTransformSetting(MalleableC2TransformSetting):
    """HTTP C2 server data transform statements.

    Malleable C2 profiles provide constructs for both Team Servers and Beacons to
    transform data before being sent. The ``http-get -> server -> output`` setting
    contains information required for the Beacon to decode data sent from the server
    by reversing the transform steps. For example, if the server appends ``278`` characters
    to each response to the Beacon, the Beacon must know to discard the last ``278`` characters
    of responses from the Team Server. See `<https://www.cobaltstrike.com/help-malleable-c2>`_ and
    `<https://usualsuspect.re/article/cobalt-strikes-malleable-c2-under-the-hood>`_ for more information.
    """

    __slots__ = ()

    @staticmethod
    def _gen_statement_from_transform(
        transform: MalleableC2Transform, stream: BytesIO
    ) -> str:
        action = transform.name.lower()
        if transform in {MalleableC2Transform.APPEND, MalleableC2Transform.PREPEND}:
            num_characters = struct.unpack(">I", stream.read(4))[0]
            action = f"{action} {num_characters} characters"
        return action

    def _from_setting_data(self, setting_data: ConfigBuffer) -> List[str]:
        setting_data = setting_data.rstrip(b"\x00")
        return self._gen_transforms_from_stream(
            BytesIO(setting_data), len(setting_data), ">I", set()
        )


class ProcessInjectionExecuteSetting(BeaconSetting):
    """Win32 APIs to use when executing injected code.

    Once running on a system (post-exploitation), Beacons can perform a number of actions,
    one of which is running code by injecting it into other processes. The ``process-inject -> execute``
    setting determines the Win32 APIs that the Beacon will try depending on the injection context.
    See the ``Process Injection`` section at `<https://www.cobaltstrike.com/help-malleable-postex>`_
    for more information.

    :param value_map: mapping of integer values to Win32 function names
    """

    __slots__ = ("_value_map",)
    VALUE_TYPE = BeaconSettingType.STR

    def __init__(self, *args, value_map: Dict[int, str], **kwargs) -> None:
        kwargs["length_override"] = 128
        super().__init__(*args, **kwargs)
        self._value_map = value_map

    def _from_setting_data(self, setting_data: ConfigBuffer) -> Optional[List[str]]:
        steps = list()
        idx = 0
        while idx < len(setting_data):
            byte = setting_data[idx]
            if byte == 0:
                break

            step = self._value_map[byte]
            if step:
                steps.append(step)
                idx += 1
            else:
                symbol = read_encoded_string(setting_data[(idx + 3) :], ">I")
                spoof_symbol = read_encoded_string(
                    setting_data[(idx + 3 + 4 + len(symbol)) :], ">I"
                )
                steps.append(
                    "CreateThread '{}!{}'".format(
                        symbol.strip("\x00"), spoof_symbol.strip("\x00")
                    )
                )
                idx += len(symbol) + len(spoof_symbol) + 11
        return steps


class ProcessInjectionTransformSetting(Length256StrSetting):
    """Process injection transform statements.

    The ``process-inject -> transform-x*`` settings define the bytes
    that the Beacon will ``prepend`` or ``append`` to code injected into a process.
    """

    __slots__ = ()

    def _from_setting_data(self, setting_data: ConfigBuffer) -> Optional[List[str]]:
        if setting_data == bytes(len(setting_data)):
            return None

        stream = BytesIO(setting_data)
        value_format = ">I"
        value_length = struct.calcsize(value_format)

        transforms: List[str] = list()
        for idx in range(2):
            transform_length = struct.unpack(value_format, stream.read(value_length))[0]
            if transform_length > 0:
                transform_bytes = stream.read(transform_length)
                transform = "prepend" if idx == 0 else "append"
                transforms.append(f"{transform} '{bytes_as_string(transform_bytes)}'")
        return transforms


class BeaconSettings(OrderedDict, Dict[str, BeaconSetting]):
    """Beacon settings and parser mapping.

    Mapping of all known Beacon settings to the parsers for each.
    The structure of this ``dict`` is designed to mimic the Malleable C2 profile
    structure as *closely as possible*, and is used in :meth:`libcsce.parser.CobaltStrikeConfigParser.parse_config`
    as the underlying parsing mechanism.

    :Examples:

    >>> from pathlib import Path
    >>> from libcsce.setting import BeaconSettings
    >>> from libcsce.parser import CobaltStrikeConfigParser
    >>> with CobaltStrikeConfigParser(Path("testdata/dll-sample-01.bin"), 3) as beacon:
    ...     config_buffer = beacon.gen_config_from_source()
    >>> settings = dict()
    >>> for setting_name, value_parser in BeaconSettings().items():
    ...     try:
    ...         settings[setting_name] = value_parser.from_config(config_buffer)
    ...     except:
    ...         pass # do something with the exception
    >>> settings["beacontype"]
    ['HTTP']

    .. note:: Settings 16-18 were apparently deprecated in Cobalt Strike 3.4.

    .. todo:: Determine if ``crypto_scheme`` (setting 31) is an enum and what it controls.
    .. todo:: Determine what ``http_post_chunk`` (setting 28) and ``uses_cookies`` (setting 50) settings control.
    .. todo:: Determine what setting 42 means and what it controls.
    .. todo:: For ``process-inject -> execute`` (setting 51), determine whether ``0x06`` and ``0x07`` mean anything.
    .. todo:: Determine what setting 53 means and what it controls.
    .. todo:: Research the new DNS settings from Cobalt Strike 4.3 (rotation strategy and dns_*).
    """

    def __init__(self):
        super().__init__()
        # General Beacon settings
        self["beacontype"] = FlagEnumSetting(
            1,
            value_map={
                0x0: "HTTP",
                0x1: "Hybrid HTTP DNS",
                0x2: "SMB",
                0x4: "TCP",
                0x8: "HTTPS",
                0x10: "Bind TCP",
            },
        )
        self["sleeptime"] = IntSetting(3)
        self["jitter"] = ShortIntSetting(5)
        self["maxgetsize"] = IntSetting(4)
        self["spawnto"] = VariableLengthStringSetting(
            14, length_override=16, is_binary=True
        )
        self["license_id"] = IntSetting(37)
        self["cfg_caution"] = BoolSetting(39)
        self["kill_date"] = DateSetting(40)

        # HTTP/HTTPS Beacon Settings
        self["server"] = NestedBeaconSetting(
            {
                "hostname": ServerHostnameSetting(8),
                "port": ShortIntSetting(2),
                "publickey": VariableLengthStringSetting(
                    7, length_override=256, is_binary=True
                ),
            }
        )
        self["host_header"] = VariableLengthStringSetting(54, length_override=128)
        self["useragent_header"] = VariableLengthStringSetting(9, length_override=128)
        self["http-get"] = NestedBeaconSetting(
            {
                "uri": HttpGetUriSetting(8),
                "verb": VariableLengthStringSetting(26, length_override=16),
                "client": NestedBeaconSetting(
                    {
                        "headers": MalleableC2HttpClientHeadersSetting(12),
                        "metadata": MalleableC2HttpClientTransformSetting(
                            12, section_idx=0
                        ),
                    }
                ),
                "server": NestedBeaconSetting(
                    {
                        # See: https://www.cobaltstrike.com/help-malleable-c2
                        #      https://usualsuspect.re/article/cobalt-strikes-malleable-c2-under-the-hood
                        "output": MalleableC2ServerOutputTransformSetting(11),
                    }
                ),
            }
        )
        self["http-post"] = NestedBeaconSetting(
            {
                "uri": VariableLengthStringSetting(10, length_override=64),
                "verb": VariableLengthStringSetting(27, length_override=16),
                "client": NestedBeaconSetting(
                    {
                        "headers": MalleableC2HttpClientHeadersSetting(13),
                        "id": MalleableC2HttpClientTransformSetting(13, section_idx=0),
                        "output": MalleableC2HttpClientTransformSetting(
                            13, section_idx=1, exclude_transforms={0x01}
                        ),
                    }
                ),
            }
        )
        self["tcp_frame_header"] = VariableLengthStringSetting(
            58, length_override=128, is_binary=True
        )
        self["crypto_scheme"] = ShortIntSetting(31)
        self["proxy"] = NestedBeaconSetting(
            {
                "type": VariableLengthStringSetting(32, length_override=128),
                "username": VariableLengthStringSetting(33, length_override=64),
                "password": VariableLengthStringSetting(34, length_override=64),
                "behavior": EnumSetting(
                    35,
                    value_map={
                        0x1: "Use direct connection",
                        0x2: "Use IE settings",
                        0x4: "Use proxy server",
                    },
                ),
            }
        )
        self["http_post_chunk"] = IntSetting(28)
        self["uses_cookies"] = BoolSetting(50)

        # Post-Exploitation Settings
        self["post-ex"] = NestedBeaconSetting(
            {
                "spawnto_x86": VariableLengthStringSetting(29, length_override=64),
                "spawnto_x64": VariableLengthStringSetting(30, length_override=64),
            }
        )
        # self["ObfuscateSectionsInfo"] = packedSetting(42, confConsts.TYPE_STR, %d, isBlob=True)
        self["process-inject"] = NestedBeaconSetting(
            {
                "allocator": EnumSetting(
                    52, value_map={0: "VirtualAllocEx", 1: "NtMapViewOfSection"}
                ),
                "execute": ProcessInjectionExecuteSetting(
                    51,
                    value_map={
                        0x1: "CreateThread",
                        0x2: "SetThreadContext",
                        0x3: "CreateRemoteThread",
                        0x4: "RtlCreateUserThread",
                        0x5: "NtQueueApcThread",
                        0x6: None,
                        0x7: None,
                        0x8: "NtQueueApcThread-s",
                    },
                ),
                "min_alloc": IntSetting(45),
                "startrwx": BoolSetting(43, false_value=4),
                "stub": VariableLengthStringSetting(
                    53, length_override=16, is_binary=True
                ),
                "transform-x86": ProcessInjectionTransformSetting(46),
                "transform-x64": ProcessInjectionTransformSetting(47),
                "userwx": BoolSetting(44, false_value=32),
            }
        )

        # DNS Beacon Settings
        # DNS settings moved into the dns-beacon group in version 4.3
        self["dns-beacon"] = NestedBeaconSetting(
            {
                "dns_idle": IpAddressSetting(19),
                "dns_sleep": IntSetting(20),
                "maxdns": ShortIntSetting(6),
                "beacon": VariableLengthStringSetting(60, length_override=33),
                # DNS subhost override options, added in version 4.3
                "get_A": VariableLengthStringSetting(61, length_override=33),
                "get_AAAA": VariableLengthStringSetting(62, length_override=33),
                "get_TXT": VariableLengthStringSetting(63, length_override=33),
                "put_metadata": VariableLengthStringSetting(64, length_override=33),
                "put_output": VariableLengthStringSetting(65, length_override=33),
            }
        )

        # SMB Beacon Settings
        self["pipename"] = VariableLengthStringSetting(15, length_override=128)
        self["smb_frame_header"] = VariableLengthStringSetting(
            57, length_override=128, is_binary=True
        )

        # Stager Settings
        self["stage"] = NestedBeaconSetting(
            {
                "cleanup": BoolSetting(38),
            }
        )

        # SSH Client Settings
        self["ssh"] = NestedBeaconSetting(
            {
                "hostname": VariableLengthStringSetting(21, length_override=256),
                "port": ShortIntSetting(22),
                "username": VariableLengthStringSetting(23, length_override=128),
                "password": VariableLengthStringSetting(24, length_override=128),
                "privatekey": VariableLengthStringSetting(25, length_override=6144),
            }
        )
