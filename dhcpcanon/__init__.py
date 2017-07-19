# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""__init__ for the DHCP client implementation of the Anonymity Profile
([:rfc:`7844`])."""
from __future__ import absolute_import
# from . import (clientscript, conflog, constants, dhcpcap, dhcpcapfsm,
#                dhcpcaplease, dhcpcaputils, timers)
try:
    from ._version import version
except ImportError:
    try:
        from setuptools_scm import get_version
        version = get_version()
    except (ImportError, LookupError):
        version = '0.3.2'

__version__ = version
__author__ = "juga"
__author_mail__ = "juga@riseup.net"
__description__ = "DHCP client disclosing less identifying information"
__long_description__ = "Python implmentation of the DHCP Anonymity Profiles \
                        (RFC7844) designed for users that \
                        wish to remain anonymous to the visited network \
                        minimizing disclosure of identifying information."
__website__ = 'https://github.com/juga0/dhcpcanon'
__documentation__ = 'http://dhcpcanon.readthedocs.io/en/' + __version__
__authors__ = []
__copyright__ = """Copyright (C) 2016 <juga@riseup.net>
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
For details see the COPYRIGHT file distributed along this program."""

__license__ = """
    This package is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    any later version.

    This package is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this package. If not, see <http://www.gnu.org/licenses/>.
"""
__all__ = ('clientscript', 'conflog', 'dhcpcapfsm', 'dhcpcaplease',
           'dhcpcaputils', 'timers', 'constants', 'dhcpcap')
