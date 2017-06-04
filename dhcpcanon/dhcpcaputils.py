# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""DCHP client implementation of the anonymity profile (RFC7844),
module functions."""

import logging
from scapy.layers.dhcp import DHCP, DHCPTypes

logger = logging.getLogger(__name__)


def isoffer(packet):
    """."""
    if DHCP in packet and DHCPTypes[packet[DHCP].options[0][1]] == 'offer':
        logger.debug('Packet is Offer.')
        return True
    return False


def isnak(packet):
    """."""
    if DHCP in packet and DHCPTypes[packet[DHCP].options[0][1]] == 'nak':
        logger.debug('Packet is NAK.')
        return True
    return False


def isack(packet):
    """."""
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
