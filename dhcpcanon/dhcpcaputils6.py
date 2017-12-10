# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""Util functions for the DHCP6 client implementation of the Anonymity Profile
([:rfc:`7844`])."""
from __future__ import absolute_import

import logging
import random

from scapy.arch.linux import get_if_list
from scapy.layers.dhcp6 import (DHCP6_Advertise, DHCP6OptOptReq,
                                DHCP6OptServerId)

from .constants import XID_MIN, XID_MAX

logger = logging.getLogger(__name__)


def isadvertise(packet):
    """."""
    if DHCP6_Advertise in packet and DHCP6OptIAAddress in packet \
        and DHCP6OptServerId in packet:
        logger.debug('Packet is Offer.')
        return True
    return False


def isnak(packet):
    """."""
    if DHCP6 in packet and (DHCPTypes.get(packet[DHCP6].options[0][1]) ==
                           'nak' or packet[DHCP6].options[0][1] == 'nak'):
        logger.debug('Packet is NAK.')
        return True
    return False


def isack(packet):
    """."""
    if DHCP6 in packet and (DHCPTypes.get(packet[DHCP6].options[0][1]) ==
                           'ack' or packet[DHCP6].options[0][1] == 'ack'):
        logger.debug('Packet is ACK.')
        return True
    return False
