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
from scapy.layers.dhcp import DHCP, DHCPTypes

from constants import XID_MAX, XID_MIN

logger = logging.getLogger(__name__)


def gen_xid():
    return random.randint(XID_MIN, XID_MAX)


def isoffer(packet):
    if DHCP in packet and DHCPTypes[packet[DHCP].options[0][1]] == 'offer':
        logger.debug('Packet is Offer.')
        return True
    return False


def isnak(packet):
    if DHCP in packet and DHCPTypes[packet[DHCP].options[0][1]] == 'nak':
        logger.debug('Packet is NAK.')
        return True
    return False


def isack(packet):
    if DHCP in packet and DHCPTypes[packet[DHCP].options[0][1]] == 'ack':
        logger.debug('Packet is ACK.')
        return True
    return False


def discover_ifaces():
    import netifaces
    ifaces = netifaces.interfaces()
    ifaces.remove('lo')
    logger.debug('Disovered interfaces %s.', ifaces)
    return ifaces


# TODO
def detect_speed_network():
    # FIXME: only for linux
    # 100 Mbps = 100 Mb/s
    with open('/sys/class/net/eth0/speed') as fd:
        speed = fd.read()
    logger.debug('Net speed %s', speed)
    return speed


# TODO
def detect_initial_network():
    pass
