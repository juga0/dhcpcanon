# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""Client class for the DHCP6 client implementation of the Anonymity Profile
([:rfc:`7844`])."""
from __future__ import absolute_import

# from __future__ import unicode_literals
import logging

import attr
import time
from netaddr import IPNetwork
from scapy.arch import get_if_raw_hwaddr
from scapy.config import conf
from scapy.layers.dhcp6 import (DHCP6_Solicit, DHCP6OptOptReq,
                                DHCP6OptClientId, DUID_LL, DHCP6OptIA_NA,
                                DHCP6OptRapidCommit, DHCP6OptElapsedTime)
from scapy.layers.inet6 import IPv6
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether
from scapy.utils import mac2str, str2mac

from .constants import (MULTICAST_ADDR6, BROADCAST_MAC6, CLIENT_PORT6, META_ADDR6,
                        SERVER_PORT6, PRL6)
from .dhcpcap import DHCPCAP
from .dhcpcaputils import gen_xid
from .dhcpcaplease import DHCPCAPLease

logger = logging.getLogger('dhcpcanon')


@attr.s
class DHCPCAP6(DHCPCAP):
    """."""
    iface = attr.ib(default=None)

    client_mac = attr.ib(default=None)
    client_ip = attr.ib(default=META_ADDR6)
    client_port = attr.ib(default=CLIENT_PORT6)

    server_mac = attr.ib(default=BROADCAST_MAC6)
    server_ip = attr.ib(default=MULTICAST_ADDR6)
    server_port = attr.ib(default=SERVER_PORT6)

    lease = attr.ib(default=attr.Factory(DHCPCAPLease))
    event = attr.ib(default=None)
    prl = attr.ib(default=None)
    xid = attr.ib(default=None)

    def __attrs_post_init__(self):
        """Initializes attributes after attrs __init__.

        These attributes do not change during the life of the object.

        """
        logger.debug('Creating new DHCPCAP obj.')
        if self.iface is None:
            self.iface = conf.iface
        if self.client_mac is None:
            _, client_mac = get_if_raw_hwaddr(self.iface)
            self.client_mac = str2mac(client_mac)
        if self.prl is None:
            self.prl = PRL6
        if self.xid is None:
            self.xid = gen_xid()
        logger.debug('Modifying Lease obj, setting iface.')
        self.lease.interface = self.iface

    def gen_ether_ip(self):
        """Generates link layer and IPv6 layer part of DHCP6 packet.

        For broadcast packets is:
            Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
            IPv6(src="0.0.0.0", dst="255.255.255.255") /

        """
        ether_ip = (Ether(src=self.client_mac, dst=BROADCAST_MAC6,
                          type="IPv6") /
                    IPv6(src=self.client_ip, dst=MULTICAST_ADDR6))

        return ether_ip

    def gen_udp(self):
        """Generates UDP layer part of DHCP6 packet.

        UDP layer is always:
            UDP(sport=546, dport=547) /

        """
        udp = (UDP(sport=self.client_port, dport=self.server_port))
        return udp


    def gen_discover(self):
        """
        Generate DHCP6 DISCOVER packet.

        [:rfc:`7844#section-3.1`] ::

            SHOULD randomize the ordering of options

            If this can not be implemented
            MAY order the options by option code number (lowest to highest).

        [:rfc:`7844#section-3.`] ::

            MAY contain the Parameter Request List option.

        """
        dhcp_discover = (
            self.gen_ether_ip() /
            self.gen_udp() /
            DHCP6_Solicit(trid=self.xid) /
            DHCP6OptClientId(duid=DUID_LL(lladdr=self.client_mac)) /
                            #  timeval=int(time.time())) /
            DHCP6OptIA_NA(iaid=0xf) /
            DHCP6OptRapidCommit() /
            # DHCP6OptElapsedTime() /
            # DHCP6OptOptReq(reqopts=b"\x17\x18")
            DHCP6OptOptReq(reqopts=[23, 24])
        )

        logger.debug('Generated discover %s.', dhcp_discover.summary())
        return dhcp_discover
