# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""."""
import pytest
from dhcpcanon.dhcpcap import DHCPCAP


@pytest.fixture
def dhcpcap_maker(request):
    """ return a function which creates initialized dhcpcap instances. """

    def maker():
        dhcpcap = DHCPCAP(client_mac="00:01:02:03:04:05", iface='eth0')
        return dhcpcap
    return maker


@pytest.fixture
def dhcpcap(dhcpcap_maker):
    """ return an initialized dhcpcap instance. """
    return dhcpcap_maker()
