# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
""""""
import logging
from scapy.all import Ether, IP, UDP, BOOTP, DHCP

FORMAT = "%(levelname)s: %(filename)s:%(lineno)s - %(funcName)s - " + \
         "%(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
logger = logging.getLogger(__name__)


class TestDHCPCAPFSM:

    def test_intialize(self, dhcpcanon):
        assert dhcpcanon.client_ip == '0.0.0.0'
        # TODO: assert more

    def test_gen_discover(self, dhcpcanon, datadir):
        dhcp_discover = (
            Ether(src="00:0a:0b:0c:0d:0f", dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=8001, dport=8000) /
            BOOTP(chaddr=['\x00\n\x0b\x0c\r\x0f'], options='c\x82Sc') /
            DHCP(options=[
                ('message-type', 'discover'),
                'end']
                )
        )
        discover = dhcpcanon.gen_discover()
        assert discover == dhcp_discover

    def test_parse_offer(self, dhcpcanon, datadir):
        dhcp_offer = (
            Ether(src="00:01:02:03:04:05", dst="00:0a:0b:0c:0d:0f") /
            IP(src="0.0.0.0", dst="127.0.0.1") /
            UDP(sport=8000, dport=8001) /
            BOOTP(op=2, yiaddr="127.0.0.1", siaddr="127.0.0.1",
                  giaddr='0.0.0.0', xid=1234) /
            DHCP(options=[
                ('message-type', 'offer'),
                ('subnet_mask', "255.0.0.0"),
                ('server_id', "127.0.0.1"),
                ('lease_time', 1800),
                ('domain', "localnet"),
                ('name_server', "127.0.0.1"),
                'end']
                )
        )
        dhcpcanon.parse_Offer(dhcp_offer)
        assert dhcpcanon.client_ip_offered == '127.0.0.1'
