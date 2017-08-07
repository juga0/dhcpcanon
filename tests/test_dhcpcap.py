# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
""""""
import logging
from datetime import datetime

from dhcpcap_leases import LEASE_ACK, LEASE_REQUEST
from dhcpcap_pkts import dhcp_ack, dhcp_discover, dhcp_offer, dhcp_request

FORMAT = "%(levelname)s: %(filename)s:%(lineno)s - %(funcName)s - " + \
         "%(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
logger = logging.getLogger(__name__)


class TestDHCPCAP:
    def test_intialize(self, dhcpcap):
        assert dhcpcap.client_mac == "00:01:02:03:04:05"
        assert dhcpcap.iface == "eth0"
        # assert dhcpcap.xid == 900000000
        # assert dhcpcap.prl == \
        #     b"\x01\x03\x06\x0f\x1f\x21\x2b\x2c\x2e\x2f\x79\xf9\xfc"
        # assert dhcpcap.client_ip == "0.0.0.0"
        # assert dhcpcap.client_port == 68
        # assert dhcpcap.server_mac == "ff:ff:ff:ff:ff:ff"
        # assert dhcpcap.server_ip == "255.255.255.255"
        # assert dhcpcap.server_port == 67
        # assert dhcpcap.lease is None
        # assert dhcpcap.event is None

    def test_gen_discover(self, dhcpcap):
        discover = dhcpcap.gen_discover()
        logger.debug(discover)
        logger.debug(dhcp_discover)
        assert discover == dhcp_discover

    def test_handle_offer(self, dhcpcap):
        dhcpcap.handle_offer(dhcp_offer)
        lease = dhcpcap.lease
        assert lease == LEASE_REQUEST

    def test_gen_request(self, dhcpcap):
        dhcpcap.lease = LEASE_REQUEST
        request = dhcpcap.gen_request()
        assert request == dhcp_request

    def test_handle_ack(self, dhcpcap):
        dhcpcap.lease = LEASE_REQUEST
        dhcpcap.handle_ack(dhcp_ack, datetime(2017, 6, 23))
        lease = dhcpcap.lease
        assert lease == LEASE_ACK
