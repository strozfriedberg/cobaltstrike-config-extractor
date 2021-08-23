#!/usr/bin/env python3
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
# pylint: disable=invalid-name,wrong-import-position

from argparse import ArgumentParser, Namespace
import json
from pathlib import Path
import typing

from libcsce.error import CobaltStrikeError
from libcsce.parser import CobaltStrikeConfigParser
from libcsce.setting import (
    BeaconSetting,
    IntSetting,
    ShortIntSetting,
    VariableLengthStringSetting,
)
from libcsce.utils import JSONEncoderWithBinarySupport


__version__ = "0.1.0"
SettingsMap = typing.Dict[
    int, typing.Dict[int, typing.Dict[str, typing.Union[int, str]]]
]


def gen_setting_parsers(position: int) -> typing.Tuple[BeaconSetting, ...]:
    """Generate tuple of setting parser instances from configuration setting position."""
    return (
        ShortIntSetting(position),
        IntSetting(position),
        VariableLengthStringSetting(position, length_override=16),
        VariableLengthStringSetting(position, length_override=16, is_binary=True),
        VariableLengthStringSetting(position, length_override=32),
        VariableLengthStringSetting(position, length_override=32, is_binary=True),
        VariableLengthStringSetting(position, length_override=64),
        VariableLengthStringSetting(position, length_override=64, is_binary=True),
        VariableLengthStringSetting(position, length_override=128),
        VariableLengthStringSetting(position, length_override=128, is_binary=True),
        VariableLengthStringSetting(position, length_override=256),
        VariableLengthStringSetting(position, length_override=256, is_binary=True),
        VariableLengthStringSetting(position, length_override=6144),
        VariableLengthStringSetting(position, length_override=6144, is_binary=True),
    )


def list_cs_settings(args: Namespace) -> int:
    """Find Cobalt Strike config settings in source file."""
    source_path: Path = args.source_path
    max_settings: int = args.max_settings

    if not source_path.is_file():
        print("::: ERROR: Source path does not exist or is not file")
        return 1

    settings: SettingsMap = dict()
    for version in CobaltStrikeConfigParser.SUPPORTED_VERSIONS:
        with CobaltStrikeConfigParser(source_path, version) as parser:
            try:
                config_buffer = parser.gen_config_from_source()
                settings[version] = dict()
                for idx in range(max_settings):
                    position = idx + 1
                    for setting_parser in gen_setting_parsers(position):
                        offset = config_buffer.find(setting_parser.signature)
                        if offset == -1:
                            continue

                        try:
                            value = setting_parser.from_config(config_buffer)
                        except Exception:
                            value = None
                        # from_config could return None if the signature for that setting is not found.
                        # This will continue to the next setting if the signature isn't found, or if an exception
                        # is raised (likely due to an encoding attempt failure).
                        if value is None:
                            continue

                        settings[version][position] = {
                            "length": setting_parser.length,  # type: ignore
                            "offset": offset,
                            "value_type": setting_parser.VALUE_TYPE.name,
                            "value": value,
                        }
                        break
                break
            except CobaltStrikeError:
                continue
    print(json.dumps(settings, indent=2, cls=JSONEncoderWithBinarySupport))
    return 0


def gen_command_parser() -> ArgumentParser:
    parser = ArgumentParser(
        description=(
            "Parse listing of options in Cobalt Strike beacon configuration."
            "Intended be used for research into existing or new beacon configuration options."
        )
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-s",
        "--max-settings",
        type=int,
        default=128,
        help="Maximum number of settings to search for",
        dest="max_settings",
    )
    parser.add_argument("source_path", type=Path, help="Path to PE file or memory dump")
    parser.set_defaults(func=list_cs_settings)
    return parser


def main() -> int:
    parser = gen_command_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    main()
