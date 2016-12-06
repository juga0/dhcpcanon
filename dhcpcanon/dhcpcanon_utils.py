# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

# Copyright 2016 juga <juga@riseup.net>

# This file is part of dhcpcanon.
#
# dhcpcanon is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# dhcpcanon is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with dhcpcanon.  If not, see <http://www.gnu.org/licenses/>.

"""DCHP client implementation of the anonymity profile (RFC7844),
module functions."""

import logging
import random

from scapy.arch import get_if_raw_hwaddr
from scapy.layers.dhcp import DHCP, DHCPTypes, BOOTP, dhcpmagic
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether

logger = logging.getLogger(__name__)

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
META_MAC = '00:00:00:00:00:00'
BROADCAST_ADDR = '255.255.255.255'
META_ADDR = '0.0.0.0'

CLIENT_PORT = 68
SERVER_PORT = 67

# NOTE: 3.6. The choice of option numbers and the specific ordering of option
# numbers in the PRL can be used to fingerprint the client
# SHOULD only request a
# minimal number of options in the PRL and SHOULD also randomly shuffle
# the ordering of option codes in the PRL
# PARAM_REQ_LIST = '\x01\x03\x06\x0fw\xfc'# \x1c3
PARAM_REQ_LIST = '\x01\x1c\x02\x03\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a'

# TODO: set timeout with retransmission_delay function
MAX_DELAY_SELECTING = 10
TIMEOUT_DISCOVER = 10
MAX_DISCOVER_RETRIES = 2
MAX_OFFERS_COLLECTED = 1

RENEW_PERC = 0.5
REBIND_PERC = 0.875

XID_MIN = 1
XID_MAX = 900000000


def gen_xid():
    return random.randint(XID_MIN, XID_MAX)


def gen_delay_selecting():
    delay = random.randint(0, MAX_DELAY_SELECTING)
    logger.debug('Delay to enter in SELECTING %s.' % delay)
    return delay


def gen_renewing_time(lease_time, elapsed=0):
    # Times T1 and T2 SHOULD be chosen with some
    # random "fuzz" around a fixed value, to avoid synchronization of
    # client reacquisition.
    renewing_time = lease_time * RENEW_PERC - elapsed
    # FIXME: the random intervals here could deanonymize
    range_fuzz = lease_time * REBIND_PERC - renewing_time
    fuzz = random.uniform(-(range_fuzz),
                          +(range_fuzz))
    renewing_time += fuzz
    logger.debug('Renewing time %s.', renewing_time)
    return renewing_time


def gen_rebinding_time(lease_time, elapsed=0):
    rebinding_time = lease_time * REBIND_PERC - elapsed
    # FIXME: the random intervals here could deanonymize
    range_fuzz = lease_time - rebinding_time
    fuzz = random.uniform(-(range_fuzz),
                          +(range_fuzz))
    rebinding_time += fuzz
    logger.debug('Rebinding time %s.', rebinding_time)
    return rebinding_time


def now():
    from pytz import utc
    from datetime import datetime
    now = datetime.utcnow().replace(tzinfo=utc)
    logger.debug('Now %s.', now)
    return now


def is_Offer(packet):
    if DHCP in packet and DHCPTypes[packet[DHCP].options[0][1]] == 'offer':
        logger.debug('Packet is Offer.')
        return True
    return False


def is_NAK(packet):
    if DHCP in packet and DHCPTypes[packet[DHCP].options[0][1]] == 'nak':
        logger.debug('Packet is NAK.')
        return True
    return False


def is_ACK(packet):
    if DHCP in packet and DHCPTypes[packet[DHCP].options[0][1]] == 'ack':
        logger.debug('Packet is ACK.')
        return True
    return False


def parse_response(packet, debug=False):
    pkt_dict = {}
    pkt_dict['server_ip'] = packet[IP].src
    pkt_dict['server_mac'] = packet[Ether].src
    pkt_dict['client_ip_offered'] = packet[BOOTP].yiaddr
    logger.debug('offered ip %s', pkt_dict['client_ip_offered'])
    # pkt_dict['client_mac'] = str2mac(packet[BOOTP].chaddr)
    # pkt_dict['client_xid'] = packet[BOOTP].xid

    for option in packet[DHCP].options:
        if type(option) == tuple:
            if option[0] == 'server_id':
                pkt_dict['server_id'] = option[1]
            if option[0] == 'subnet_mask':
                pkt_dict['subnet_mask'] = option[1]
            if option[0] == 'broadcast_address':
                pkt_dict['broadcast_address'] = option[1]
            if option[0] == 'router':
                pkt_dict['router'] = option[1]
            if option[0] == 'domain':
                pkt_dict['domain'] = option[1]
            if option[0] == 'name_server':
                pkt_dict['name_server'] = option[1]
            if option[0] == 'lease_time':
                pkt_dict['lease_time'] = option[1]
            if option[0] == 'renewal_time':
                pkt_dict['renewal_time'] = option[1]
            if option[0] == 'rebinding_time':
                pkt_dict['rebinding_time'] = option[1]
    return pkt_dict


def discover_ifaces():
    import netifaces
    ifaces = netifaces.interfaces()
    ifaces.remove('lo')
    logger.debug('Disovered interfaces %s.', ifaces)
    return ifaces


def add_second(dt, secs):
    from datetime import timedelta
    return dt + timedelta(seconds=secs)


# TODO
def detect_speed_network():
    pass


# TODO
def retransmission_delay():
    pass


# TODO
def detect_initial_network():
    pass


# TODO
def send_ARP(client_ip,  server_ip):
    pass
