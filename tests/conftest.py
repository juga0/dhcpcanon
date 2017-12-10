# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""."""
import pytest
from dhcpcanon.dhcpcap import DHCPCAP
from dhcpcanon.dhcpcap6 import DHCPCAP6


@pytest.fixture
def dhcpcap_maker(request):
    """ return a function which creates initialized dhcpcap instances. """

    def maker():
        dhcpcap = DHCPCAP(client_mac="00:01:02:03:04:05", iface='eth0',
                          xid=900000000)
        return dhcpcap
    return maker


@pytest.fixture
def dhcpcap(dhcpcap_maker):
    """ return an initialized dhcpcap instance. """
    return dhcpcap_maker()


@pytest.fixture
def dhcpcap6_maker(request):
    """ return a function which creates initialized dhcpcap instances. """

    def maker():
        dhcpcap6 = DHCPCAP6(client_mac="00:01:02:03:04:05", iface='eth0',
                            client_ip="fe80::a00:27ff:fefe:8f95",
                            xid=900000000)
        return dhcpcap6
    return maker


@pytest.fixture
def dhcpcap6(dhcpcap6_maker):
    """ return an initialized dhcpcap instance. """
    return dhcpcap6_maker()
