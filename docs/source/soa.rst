.. _soa:

==================
State of the Art
==================

on DHCP clients, network managers and libraries in Debian/Ubuntu

ISC-DHCP
-----------

Reference ISC implementation
`ISC License <https://www.isc.org/downloads/software-support-policy/isc-license/>`__

`homepage <https://www.isc.org/downloads/dhcp/>`__
`tar.gz <https://www.isc.org/downloads/file/dhcp-4-3-5/?version=tar-gz>`__


Debian DHCP clients
======================

isc-dhcp-client
------------------

Debian default

`debian <https://packages.debian.org/stretch/isc-dhcp-client>`__
`debian source <https://anonscm.debian.org/cgit/pkg-dhcp/isc-dhcp.git/>`__

network-manager built-in
--------------------------


systemd-networkd
--------------------

    ``man 5 systemd.network`` => DHCP options

udhcpc
-----------

Busybox implementation

`debian <https://packages.debian.org/stretch/udhcpc>`__

Debian network managers
========================

Gnome Network Manager
------------------------

Can use 3 DHCP clients:
- ISC DHCP client: package `isc-dhpc-client`, binarry `dhclient`
- systemd DHCP client
- built-in DHCP client

`debian <https://packages.debian.org/stretch/network-manager>`__

wicd
-----

`debian <https://packages.debian.org/stretch/wicd>`__



Python DHCP libraries/tools
===============================

python-isc-dhcp-leases
--------------------------

Python module for reading dhcp leases files

`debian <https://packages.debian.org/stretch/python-isc-dhcp-leases>`__

pydhcplib
-------------------

Pure Python library.

GPL. Last updated XX. Commiters: 1.

`pypi <https://pypi.python.org/pypi/pydhcplib/0.6.2>`__,
`repo <https://svnweb.tuxfamily.org/log.php?repname=pydhcplib%2Fpydhcplib&path=%2F&isdir=1&>`__,
`wiki <https://pydhcplib.tuxfamily.org/pmwiki>`__
`debian <https://packages.debian.org/stretch/python-pydhcplib>`__

pydhcpd
-----------

DHCP command-line query and testing tool. Uses pydhcplib

GPL. Last updated: 2009

`code <http://ostatic.com/pydhcpd/>`__

staticdhcpd
----------------

is an all-Python, RFC 2131-compliant DHCP server,
with support for most common DHCP extensions and
extensive site-specific customisation.

GPL. Last updated 12/03/2017. Commiters: +3

`repo <http://code.google.com/p/staticdhcpd/>`__

dhquery
----------

DHCP command line query and testing tool

`code <http://code.google.com/p/dhquery/>`__
`one github fork <https://github.com/lcy0321/dhquery>`__ (updated 2016)

dhcpy6d
------------

MAC address aware DHCPv6 server written in Python

Last updated 28/06/2017. Commiters: 2?

`homepage <https://dhcpy6d.ifw-dresden.de/>`__
`repo <https://github.com/HenriWahl/dhcpy6d>`__
`doc <https://dhcpy6d.ifw-dresden.de/documentation/>`__
`debian <https://packages.debian.org/stretch/dhcpy6d>`__

dhcpscapy
-----------

Simple DCHP client and server implemented with scapy

Last updated. 18/05/2014. Commiters: 1

`repo <https://github.com/duy/dhcpscapy>`__
