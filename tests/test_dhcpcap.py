# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
""""""
import logging

from dhcpcap_pkts import dhcp_discover, dhcp_offer, dhcp_request, dhcp_ack
from dhcpcanon.dhcpcaplease import DHCPCAPLease

FORMAT = "%(levelname)s: %(filename)s:%(lineno)s - %(funcName)s - " + \
         "%(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
logger = logging.getLogger(__name__)

LEASE_REQUEST = DHCPCAPLease(interface='enp0s25', address='192.168.1.2',
                             server_id='192.168.1.1',
                             next_server='192.168.1.1',
                             router='192.168.1.1', subnet_mask='255.255.255.0',
                             broadcast_address='192.168.1.255',
                             domain='localdomain',
                             name_server='192.168.1.1', lease_time=129600,
                             renewal_time=604800, rebinding_time=1058400,
                             subnet_mask_cidr='', subnet='', expiry='',
                             renew='', rebind='')

LEASE_ACK = DHCPCAPLease(interface='enp0s25', address='192.168.1.2',
                         server_id='192.168.1.1', next_server='192.168.1.1',
                         router='192.168.1.1', subnet_mask='255.255.255.0',
                         broadcast_address='192.168.1.255',
                         domain='localdomain',
                         name_server='192.168.1.1', lease_time=129600,
                         renewal_time=604800, rebinding_time=1058400,
                         subnet_mask_cidr='24', subnet='192.168.1.0',
                         expiry='', renew='', rebind='')


class TestDHCPCAP:
    def test_intialize(self, dhcpcap):
        assert dhcpcap.client_mac == "00:0a:0b:0c:0d:0f"

    def test_gen_discover(self, dhcpcap, datadir):
        discover = dhcpcap.gen_discover()
        assert discover == dhcp_discover

    def test_handle_offer(self, dhcpcap, datadir):
        dhcpcap.handle_offer(dhcp_offer)
        lease = dhcpcap.lease
        logger.debug("lease %s", lease)
        assert lease == LEASE_REQUEST

    def test_gen_request(self, dhcpcap, datadir):
        dhcpcap.lease = LEASE_REQUEST
        request = dhcpcap.gen_request()
        assert request == dhcp_request

    def test_handle_ack(self, dhcpcap, datadir):
        dhcpcap.lease = LEASE_REQUEST
        dhcpcap.handle_ack(dhcp_ack)
        lease = dhcpcap.lease
        logger.debug("lease %s", lease)
        assert lease == LEASE_ACK
