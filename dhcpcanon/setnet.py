# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""."""
import logging
import subprocess

from pyroute2 import IPRoute, IW
from pyroute2.netlink import NetlinkError

from .constants import RESOLVCONF

logger = logging.getLogger(__name__)


def get_iffs():
    iffs_ordered = []
    up_wifis = []
    down_wifis = []
    ipr = IPRoute()
    iw = IW()
    up = ipr.link_lookup(operstate='UP')
    down = ipr.link_lookup(operstate='DOWN')
    wifi_iffs = [i[0] for i in iw.get_interfaces_dict().values()]
    for i in wifi_iffs:
        if i in up:
            logger.debug('Wifi interface is up.')
            up_wifis.append(i)
            up.remove(i)
        else:
            logger.debug('Wifi interface is down.')
            down_wifis.append(i)
            down.remove(i)
    iffs_ordered = up + up_wifis + down + down_wifis
    iffs_ordered = [ipr.get_links(i)[0].get_attr('IFLA_IFNAME')
                    for i in iffs_ordered]
    logger.debug('Interfaces to listen %s', iffs_ordered)
    ipr.close()
    iw.close()
    return iffs_ordered


def set_iff_up(iff):
    ipr = IPRoute()
    index = ipr.link_lookup(ifname=iff)[0]
    try:
        ipr.link_up(index)
    except NetlinkError as e:
        if e.code == 19:
            logger.error("The device does not exist.")
            exit(1)
    ipr.close()


def set_net(lease):
    ipr = IPRoute()
    index = ipr.link_lookup(ifname=lease.interface)[0]
    try:
        ipr.addr('add', index, address=lease.address,
                 mask=int(lease.subnet_mask_cidr))
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
    cmd = [RESOLVCONF, '-a', lease.interface]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    stdin = '\n'.join(['nameserver ' + nm for nm in lease.name_server.split()])
    stdin = str.encode(stdin)
    try:
        (stdout, stderr) = proc.communicate(stdin)
    except TypeError as e:
        logger.error(e)
    logger.debug('result %s, stdout %s, stderr %s', proc.returncode, stdout,
                 stderr)
