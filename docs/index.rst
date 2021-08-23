.. include:: ../README.rst

libcsce Library
================

The library contains two core modules:

1. :doc:`setting <libcsce/libcsce.setting>`: parsers for individual Beacon config settings
2. :doc:`parser <libcsce/libcsce.parser>`: primary Beacon config parser

If you simply need to integrate parsing Beacon configs into another program,
use the :class:`libcsce.parser.CobaltStrikeConfigParser` class. To conduct research on or parse individual settings,
use the classes defined in the setting module. All modules contain extensive documentation regarding usage and
research conducted to date of Beacon config settings.

.. toctree::
    :maxdepth: 3

    libcsce/libcsce


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
