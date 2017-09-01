# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""."""
import logging
import subprocess

from pyroute2 import IPRoute
from pyroute2.netlink import NetlinkError

from .constants import RESOLVCONF

logger = logging.getLogger(__name__)


def set_net(self, lease):
    ipr = IPRoute()
    index = ipr.link_lookup(ifname=lease.interface)[0]
    try:
        ipr.addr('add', index, address=lease.address,
                 mask=lease.subnet_mask_cidr)
    except NetlinkError as e:
        if ipr.get_addr(index=index)[0].\
                get_attrs('IFA_ADDRESS')[0] == lease.address:
            logger.debug('Interface %s is already set to IP %s' %
                         (lease.interface, lease.address))
        else:
            logger.error(e)
    else:
        logger.debug('Interface %s set to IP %s' %
                     (lease.interface, lease.address))
    try:
        ipr.route('add', dst='0.0.0.0', gateway=lease.router, oif=index)
    except NetlinkError as e:
        if ipr.get_routes(table=254)[0].\
                get_attrs('RTA_GATEWAY')[0] == lease.router:
            logger.debug('Default gateway is already set to %s' %
                         (lease.router))
        else:
            logger.error(e)
    else:
        logger.debug('Default gateway set to %s', lease.router)
    ipr.close()
    # TODO: resolvconf
