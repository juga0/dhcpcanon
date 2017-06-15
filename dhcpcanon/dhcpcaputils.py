# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""Util functions for the DHCP client implementation of the Anonymity Profile
([:rfc:`7844`])."""
from __future__ import absolute_import

import logging

from scapy.arch.linux import get_if_list
from scapy.layers.dhcp import DHCP, DHCPTypes

logger = logging.getLogger(__name__)


def isoffer(packet):
    """."""
    if DHCP in packet and (DHCPTypes.get(packet[DHCP].options[0][1]) == 'offer'
                           or packet[DHCP].options[0][1] == "offer"):
        logger.debug('Packet is Offer.')
        return True
    return False


def isnak(packet):
    """."""
    if DHCP in packet and (DHCPTypes.get(packet[DHCP].options[0][1]) == 'nak'
                           or packet[DHCP].options[0][1] == 'nak'):
        logger.debug('Packet is NAK.')
        return True
    return False


def isack(packet):
    """."""
    if DHCP in packet and (DHCPTypes.get(packet[DHCP].options[0][1]) == 'ack'
                           or packet[DHCP].options[0][1] == 'ack'):
        logger.debug('Packet is ACK.')
        return True
    return False


def discover_ifaces():
    ifaces = get_if_list()
    ifaces.remove('lo')
    logger.debug('Disovered interfaces %s.', ifaces)
    return ifaces


def detect_speed_network():
    # 100 Mbps = 100 Mb/s
    with open('/sys/class/net/eth0/speed') as fd:
        speed = fd.read()
    logger.debug('Net speed %s', speed)
    return speed


# TODO
def detect_initial_network():
    pass
