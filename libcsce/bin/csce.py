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

from argparse import ArgumentParser, Namespace
import json
import logging
from pathlib import Path
from typing import Any, Dict

from libcsce.error import CobaltStrikeError
from libcsce.parser import CobaltStrikeConfigParser
from libcsce.utils import JSONEncoderWithBinarySupport


__version__ = "0.1.0"
logger = logging.getLogger("csce")


def csce(args: Namespace):
    """Parse configuration options from Cobalt Strike Beacon."""
    if not args.source.is_file():
        logger.error("Source path does not exist or is not file")
        return 1

    if args.cs_version:
        version_list = [args.cs_version]
    else:
        version_list = list(CobaltStrikeConfigParser.SUPPORTED_VERSIONS)

    config: Dict[str, Any] = dict()
    for version in version_list:
        with CobaltStrikeConfigParser(args.source, version) as parser:
            try:
                config = parser.parse_config()
                break
            except CobaltStrikeError:
                pass
    print(
        json.dumps(
            config,
            indent=(2 if args.pretty else None),
            cls=JSONEncoderWithBinarySupport,
        )
    )

    return 0


def gen_command_parser() -> ArgumentParser:
    parser = ArgumentParser(
        description="Parse Cobalt Strike beacon configuration from PE file or memory dump."
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--pretty", action="store_true", help="Pretty-print JSON output", dest="pretty"
    )
    parser.add_argument(
        "-v",
        "--cs-version",
        type=int,
        choices=CobaltStrikeConfigParser.SUPPORTED_VERSIONS,
        help="Cobalt Strike version. If not specified, will try all supported versions",
        dest="cs_version",
    )
    parser.add_argument("source", type=Path, help="Path to PE file or memory dump")
    parser.set_defaults(func=csce)
    return parser


def main() -> int:
    parser = gen_command_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    main()
