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


"""Custom error types, primarily related to decoding Beacon config data."""


class CobaltStrikeError(Exception):
    """Base library error type."""


class ConfigNotFoundError(CobaltStrikeError):
    """Raised when a Cobalt Strike config could not be found."""


class InvalidCSVersionError(CobaltStrikeError):
    """Raised for unsupported Cobalt Strike versions."""


class MissingDataSectionError(CobaltStrikeError):
    """Raised when trying to decrypt a Cobalt Strike config
    from a PE file without a .data section.
    """


class UnsupportedFileTypeError(CobaltStrikeError):
    """Raised when trying to decrypt a Cobalt Strike config from a non-PE file."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message
