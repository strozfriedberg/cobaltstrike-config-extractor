#################################################
Cobalt Strike Configuration Extractor and Parser
#################################################

Overview
=========

Pure Python library and set of scripts to extract and parse configurations (configs) from `Cobalt Strike Beacons <https://www.cobaltstrike.com/help-beacon>`_.
The library, ``libcsce``, contains classes for building tools to work with Beacon configs.
There are also two CLI scripts included that use the library to parse Beacon config data:

1. ``csce``: Parses all known Beacon config settings to JSON,
   mimicing the `Malleable C2 profile <https://cobaltstrike.com/help-malleable-c2>`_ structure.
2. ``list-cs-settings``: Attempts to find by brute-force the associated Cobalt Strike version, and all settings/their types, of a Beacon config.
   This script is useful for conducting research on Beacon samples.

Installation
=============

Install from Pypi (preferred method)
-------------------------------------

.. code-block:: bash

   > pip install libcsce

Install from GitHub with Pip
-----------------------------

.. code-block:: bash

    > pip install git+ssh://git@github.com/strozfriedberg/cobaltstrike-config-extractor.git#egg=libcsce

Install from Cloned Repo
-------------------------

.. code-block:: bash

    > git clone ssh://git@github.com/strozfriedberg/cobaltstrike-config-extractor.git
    > cd libcsce
    > pip install .

Dependencies
=============

The only external non-development dependency is `pefile <https://github.com/erocarrera/pefile>`_,
which is required to decrypt Beacon configs from the ``.data`` section of PE files.
Requires **Python 3.6+**.

Development dependencies include those specified in ``pyproject.toml`` as well as:

- `Poetry <https://python-poetry.org/docs/>`_
- `Make <https://www.gnu.org/software/make/>`_

Getting Started
================

csce
-----

Both of the CLI scripts support extracting Beacon configs from PE files (DLLs/EXEs) and memory dumps where a Beacon was running.
To parse a Beacon PE file to JSON, use ``csce``:

.. code-block:: bash

    > csce --pretty <path/to/file.{exe,dll,bin,dmp}>

By default, the script will try to parse the Beacon as version ``3`` and, if that fails, try version ``4``.
You can specify a version manually via the ``-v`` flag to save cycles if you know the Beacon is version ``4``
(using ``-v 3`` doesn't technically save cycles because the script tries that version first by default).

list-cs-settings
-----------------

To discover new settings and while conducting research, sometimes it's useful to extract possible all settings and their types from a Beacon sample.
Use ``list-cs-settings`` to detect by brute-force the Cobalt Strike version and all settings/types:

.. code-block:: bash

    > list-cs-settings <path/to/file.{exe,dll,bin,dmp}>

This script produces JSON where the top-level key is the Cobalt Strike version number,
which points to a mapping from setting number to information about that setting, including:

1. length (in bytes)
2. offset from the beginning of the config section
3. fundamental type (short, int, str)

Contributing
==============

Stroz Friedberg wants to work with the security community to make these open source tools the most comprehensive
available for working with Cobalt Strike Beacons. If you encounter a bug, have research to share on Beacons,
spot a typo in the documentation, want to request new functionality, etc. please submit an issue! If you want to contribute code
or documentation to the project, please submit a PR and we will review it!  All contributions will be subject to the license included in the repo.
