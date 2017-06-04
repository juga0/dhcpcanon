# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
""""""
import logging

import attr
from dhcpcanon.constants import (BROADCAST_ADDR, BROADCAST_MAC, CLIENT_PORT,
                                 DHCP_EVENTS, DHCP_OFFER_OPTIONS, META_ADDR,
                                 SERVER_PORT)
from dhcpcanon.dhcpcaplease import DHCPCAPLease
from scapy.arch import get_if_raw_hwaddr
from scapy.config import conf
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import mac2str, str2mac

logger = logging.getLogger('dhcpcanon')


@attr.s
class DHCPCAP(object):
    """."""
    iface = attr.ib(default=None)

    client_mac = attr.ib(default=None)
    client_ip = attr.ib(default=META_ADDR)
    client_port = attr.ib(default=CLIENT_PORT)

    server_mac = attr.ib(default=BROADCAST_MAC)
    server_ip = attr.ib(default=BROADCAST_ADDR)
    server_port = attr.ib(default=SERVER_PORT)

    lease = attr.ib(default=attr.Factory(DHCPCAPLease))
    event = attr.ib(default=None)

    def __attrs_post_init__(self):
        """."""
        if self.iface is None:
            self.iface = conf.iface
        if self.client_mac is None:
            _, client_mac = get_if_raw_hwaddr(self.iface)
            self.client_mac = str2mac(client_mac)
        self.lease.interface = self.iface

    def gen_ether_ip(self):
        """."""
        ether_ip = (Ether(src=self.client_mac, dst=self.server_mac) /
                    IP(src=self.client_ip, dst=self.server_ip))
        return ether_ip

    def gen_udp_bootp(self):
        """."""
        udp_bootp = (
            UDP(sport=self.client_port, dport=self.server_port) /
            # MAY
            # BOOTP(xid=self.client_xid) /
            # 3.4. The presence of  "Client hardware address" (chaddr)
            # is necessary for the proper operation of the DHCP service.
            BOOTP(chaddr=[mac2str(self.client_mac)], options='c\x82Sc')
        )
        return udp_bootp

    def gen_discover(self):
        """."""
        # FIXME: check if the follow also applies here:
        # 3.1. SHOULD randomize the ordering of options
        # conf.checkIPaddr = False
        dhcp_discover = (
            self.gen_ether_ip() /
            self.gen_udp_bootp() /
            DHCP(options=[
                ("message-type", "discover"),
                # MAY
                # ("param_req_list", PARAM_REQ_LIST),
                # client identifier
                "end"
            ])
        )
        logger.debug('Generated discover %s.', dhcp_discover.summary())
        return dhcp_discover

    def gen_request(self):
        """."""
        # conf.checkIPaddr = True
        dhcp_req = (
            self.gen_ether_ip() /
            self.gen_udp_bootp() /
            # DHCP(options=random.shuffle([
            DHCP(options=[
                ("message-type", "request"),
                # MAY
                # ("param_req_list", PARAM_REQ_LIST),
                # client identifier
                # If the message is in response
                # to a DHCPOFFER, it MUST contain the corresponding Server
                # Identifier option and the Requested IP address
                ("requested_addr", self.lease.address),
                ("server_id", self.lease.server_id),
                "end"])
        )
        logger.debug('Generated request %s.', dhcp_req.summary())
        return dhcp_req

    def gen_decline(self):
        """."""
        dhcp_decline = (
            self.gen_ether_ip() /
            self.gen_udp_bootp() /
            # FIXME: shuffle here?
            # DHCP(options=random.shuffle([
            DHCP(options=[
                ("message-type", "decline"),
                ("server_id", self.server_ip),
                ("requested_addr", self.client_ip),
                "end"])
        )
        logger.debug('Generated decline.')
        logger.debug(dhcp_decline.summary())
        return dhcp_decline

    def gen_release(self):
        """."""
        dhcp_release = (
            self.gen_ether_ip() /
            self.gen_udp_bootp() /
            DHCP(options=[
                ("message-type", "release"),
                ("server_id", self.server_ip),
                "end"])
        )
        logger.debug('Generated release.')
        logger.debug(dhcp_release.summary())
        return dhcp_release

    def gen_inform(self):
        """."""
        dhcp_inform = (
            self.gen_ether_ip() /
            self.gen_udp_bootp() /
            DHCP(options=[
                ("message-type", "inform"),
                # MAY
                # ("param_req_list", self.param_req_list)
                "end"])
        )
        logger.debug('Generated inform.')
        logger.debug(dhcp_inform.summary())
        return dhcp_inform

    def handle_offer_ack(self, pkt):
        """."""
        lease = DHCPCAPLease()
        lease.interface = self.iface
        lease.address = pkt[BOOTP].yiaddr
        lease.next_server = pkt[BOOTP].siaddr
        [setattr(lease, opt[0], opt[1]) for opt in pkt[DHCP].options
         if isinstance(opt, tuple) and opt[0] in DHCP_OFFER_OPTIONS]
        return lease

    def handle_offer(self, pkt):
        """."""
        logger.debug("Handling Offer.")
        lease = self.handle_offer_ack(pkt)
        self.lease = lease

    def handle_ack(self, pkt):
        """."""
        logger.debug("Handling ACK.")
        self.server_mac = pkt[Ether].src
        self.server_ip = pkt[IP].src
        self.server_port = pkt[UDP].sport
        event = DHCP_EVENTS['IP_ACQUIRE']
        # FIXME: check the fields match the previously offered ones?
        lease = self.handle_offer_ack(pkt)
        if self.lease is not None:
            if (self.lease.address != lease.address or
                    self.lease.subnet_mask != lease.subnet_mask or
                    self.lease.router != lease.router):
                event = DHCP_EVENTS['IP_CHANGE']
            else:
                event = DHCP_EVENTS['RENEW']
        self.lease = lease
        self.lease.sanitize_net_values()
        self.event = event
        return event
