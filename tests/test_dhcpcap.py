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
