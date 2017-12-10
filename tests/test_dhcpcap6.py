# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
""""""
import logging

from dhcpcap6_pkts import dhcp_discover

FORMAT = "%(levelname)s: %(filename)s:%(lineno)s - %(funcName)s - " + \
         "%(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
logger = logging.getLogger(__name__)


class TestDHCPCAP6:
    def test_intialize(self, dhcpcap6):
        assert dhcpcap6.client_mac == "00:01:02:03:04:05"
        assert dhcpcap6.iface == "eth0"
        assert dhcpcap6.client_ip == "fe80::a00:27ff:fefe:8f95"

    def test_gen_discover(self, dhcpcap6):
        discover = dhcpcap6.gen_discover()
        logger.debug(discover)
        logger.debug(dhcp_discover)
        assert discover == dhcp_discover
