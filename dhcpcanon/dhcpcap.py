# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""Client class for the DHCP client implementation of the Anonymity Profile
([:rfc:`7844`])."""
from __future__ import absolute_import

# from __future__ import unicode_literals
import logging

import attr
from netaddr import IPNetwork
from scapy.arch import get_if_raw_hwaddr
from scapy.config import conf
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import mac2str, str2mac

from .constants import (BROADCAST_ADDR, BROADCAST_MAC, CLIENT_PORT,
                        DHCP_EVENTS, DHCP_OFFER_OPTIONS, META_ADDR,
                        SERVER_PORT)
from .dhcpcaplease import DHCPCAPLease

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
        """Initializes attributes after attrs __init__.

        These attributes do not change during the life of the object.

        """
        if self.iface is None:
            self.iface = conf.iface
        if self.client_mac is None:
            _, client_mac = get_if_raw_hwaddr(self.iface)
            self.client_mac = str2mac(client_mac)
        logger.debug('Modifying Lease obj, setting iface.')
        self.lease.interface = self.iface

    def gen_ether_ip(self):
        """Generates link layer and IP layer part of DHCP packet.

        For broadcast packets is:
            Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /

        """
        ether_ip = (Ether(src=self.client_mac, dst=BROADCAST_MAC) /
                    IP(src=META_ADDR, dst=BROADCAST_ADDR))
        return ether_ip

    def gen_ether_ip_unicast(self):
        """Generates link layer and IP layer part of DHCP packet.

        For unicast packets is:
            Ether(src=client_mac, dst=server_mac) /
            IP(src=client_ip?, dst=server_ip) /

        """
        ether_ip = (Ether(src=self.client_mac, dst=self.server_mac) /
                    IP(src=self.client_ip, dst=self.server_ip))
        return ether_ip

    def gen_udp(self):
        """Generates UDP layer part of DHCP packet.

        UDP layer is always:
            UDP(sport=68, dport=67) /

        """
        udp = (UDP(sport=self.client_port, dport=self.server_port))
        return udp

    def gen_bootp(self):
        """Generates BOOTP layer part of DHCP packet.

        [ :rfc:`7844#section-3.4` ] ::

            The presence of this address is necessary for the proper operation
            of the DHCP service.

        [:rfc:`7844#section-3.`] ::
            MAY contain the Client Identifier option,

        """
        bootp = (
            BOOTP(chaddr=[mac2str(self.client_mac)])
            # , ciaddr=META_ADDR)
        )
        return bootp

    def gen_bootp_unicast(self):
        """Generates BOOTP layer part of unicast DHCP packet.

        Same comments as in gen_bootp

        """
        bootp = (
            BOOTP(chaddr=[mac2str(self.client_mac)])
            # , ciaddr=self.client_ip)
        )
        return bootp

    def gen_discover(self):
        """
        Generate DHCP DISCOVER packet.

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
            self.gen_bootp() /
            DHCP(options=[
                ("message-type", "discover"),
                "end"
            ])
        )
        logger.debug('Generated discover %s.', dhcp_discover.summary())
        return dhcp_discover

    def gen_request(self):
        """
        Generate DHCP REQUEST packet.

        [:rfc:`7844#section-3.1`] ::

            SHOULD randomize the ordering of options

            If this can not be implemented
            MAY order the options by option code number (lowest to highest).

        [:rfc:`7844#section-3.`] ::
            MAY contain the Parameter Request List option.

        If in response to a DHCPOFFER,::

            MUST contain the corresponding Server Identifier option
            MUST contain the Requested IP address option.

            If the message is not in response to a DHCPOFFER (BOUND, RENEW),::
            MAY contain a Requested IP address option

        """
        dhcp_req = (
            self.gen_ether_ip() /
            self.gen_udp() /
            self.gen_bootp() /
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", self.lease.address),
                ("server_id", self.lease.server_id),
                "end"])
        )
        logger.debug('Generated request %s.', dhcp_req.summary())
        return dhcp_req

    def gen_request_unicast(self):
        """
        Generate DHCP REQUEST unicast packet.

        Same comments as in gen_request apply.

        """
        dhcp_req = (
            self.gen_ether_ip_unicast() /
            self.gen_udp() /
            self.gen_bootp_unicast() /
            DHCP(options=[
                ("message-type", "request"),
                "end"])
        )
        logger.debug('Generated request %s.', dhcp_req.summary())
        return dhcp_req

    def gen_decline(self):
        """
        Generate DHCP decline packet (broadcast).

        [:rfc:`7844#section-3.`] ::

            MUST contain the Message Type option,
            MUST contain the Server Identifier option,
            MUST contain the Requested IP address option;

        .. note:: currently not being used.

        """
        dhcp_decline = (
            self.gen_ether_ip() /
            self.gen_udp() /
            self.gen_bootp() /
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
        """
        Generate DHCP release packet (broadcast?).

        [:rfc:`7844#section-3.`] ::

            MUST contain the Message Type option and
            MUST contain the Server Identifier option,

        .. note:: currently not being used.

        """
        dhcp_release = (
            self.gen_ether_ip() /
            self.gen_udp() /
            self.gen_bootp() /
            DHCP(options=[
                ("message-type", "release"),
                ("server_id", self.server_ip),
                "end"])
        )
        logger.debug('Generated release.')
        logger.debug(dhcp_release.summary())
        return dhcp_release

    def gen_inform(self):
        """
        Generate DHCP inform packet (unicast).

        [:rfc:`7844#section-3.`] ::

            MUST contain the Message Type option,

        .. note:: currently not being used.

        """
        dhcp_inform = (
            self.gen_ether_ip_unicast() /
            self.gen_udp() /
            self.gen_bootp_unicast() /
            DHCP(options=[
                ("message-type", "inform"),
                "end"])
        )
        logger.debug('Generated inform.')
        logger.debug(dhcp_inform.summary())
        return dhcp_inform

    def gen_check_lease_attrs(self, attrs_dict):
        """Generate network mask in CIDR format and subnet.

        Validate the given arguments. Otherwise AddrFormatError exception
        will be raised and catched in the FSM.

        """
        # without some minimal options given by the server, is not possible
        # to create new lease
        assert attrs_dict['subnet_mask']
        assert attrs_dict['address']
        # if address and/or network are not valid this will raise an exception
        # (AddrFormatError)
        ipn = IPNetwork(attrs_dict['address'] + '/' +
                        attrs_dict['subnet_mask'])
        # FIXME:70 should be this option required?
        # assert attrs_dict['server_id']
        if attrs_dict.get('server_id') is None:
            attrs_dict['server_id'] = self.server_ip
        # TODO: there should be more complex checking here about getting an
        # address in a subnet?
        # else:
        #     if IPAddress('server_id') not in ipn:
        #         raise ValueError("server_id is not in the same network as"
        #                          "the offered address.")
        if attrs_dict.get('router') is None:
            attrs_dict['router'] = attrs_dict['server_id']
        ripn = IPNetwork(attrs_dict['router'] + '/' +
                         attrs_dict['subnet_mask'])
        assert ripn.network == ipn.network
        # set the options that are not given by the server
        attrs_dict['subnet_mask_cidr'] = str(ipn.prefixlen)
        attrs_dict['subnet'] = str(ipn.network)
        # check other options that might not be given by the server
        if attrs_dict.get('broadcast_address') is None:
            attrs_dict['broadcast_address'] = str(ipn.broadcast)
        if attrs_dict.get('name_server') is None:
            attrs_dict['name_server'] = attrs_dict['server_id']
        if attrs_dict.get('next_server') is None:
            attrs_dict['next_server'] = attrs_dict['server_id']
        logger.debug('Net values are valid')
        return attrs_dict

    def handle_offer_ack(self, pkt, time_sent_request=None):
        """Create a lease object with the values in OFFER/ACK packet."""
        attrs_dict = dict([(opt[0], str(opt[1])) for opt in pkt[DHCP].options
                           if isinstance(opt, tuple)
                           and opt[0] in DHCP_OFFER_OPTIONS])
        attrs_dict.update({
            "interface": self.iface,
            "address": pkt[BOOTP].yiaddr,
            "next_server": pkt[BOOTP].siaddr,
        })
        # this function changes the dict
        self.gen_check_lease_attrs(attrs_dict)
        logger.debug('Creating Lease obj.')
        logger.debug('with attrs %s', attrs_dict)
        lease = DHCPCAPLease(**attrs_dict)
        return lease

    def handle_offer(self, pkt):
        """."""
        logger.debug("Handling Offer.")
        logger.debug('Modifying obj DHCPCAP, setting lease.')
        self.lease = self.handle_offer_ack(pkt)

    def handle_ack(self, pkt, time_sent_request):
        """."""
        logger.debug("Handling ACK.")
        logger.debug('Modifying obj DHCPCAP, setting server data.')
        self.server_mac = pkt[Ether].src
        self.server_ip = pkt[IP].src
        self.server_port = pkt[UDP].sport
        event = DHCP_EVENTS['IP_ACQUIRE']
        # FIXME:0 check the fields match the previously offered ones?
        # FIXME:50 create a new object also on renewing/rebinding
        # or only set_times?
        lease = self.handle_offer_ack(pkt, time_sent_request)
        lease.set_times(time_sent_request)
        if self.lease is not None:
            if (self.lease.address != lease.address or
                    self.lease.subnet_mask != lease.subnet_mask or
                    self.lease.router != lease.router):
                event = DHCP_EVENTS['IP_CHANGE']
            else:
                event = DHCP_EVENTS['RENEW']
        logger.debug('Modifying obj DHCPCAP, setting lease, client ip, event.')
        self.lease = lease
        self.client_ip = self.lease.address
        self.event = event
        return event
