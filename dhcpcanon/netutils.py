# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""Netowrk utils for the DHCP client implementation of the Anonymity Profile
([:rfc:`7844`])."""
import logging
import os.path
import subprocess

from dbus import SystemBus, Interface, DBusException
from pyroute2 import IPRoute
from pyroute2.netlink import NetlinkError

from .constants import RESOLVCONF, RESOLVCONF_ADMIN

logger = logging.getLogger(__name__)


def set_net(lease):
    ipr = IPRoute()
    try:
        index = ipr.link_lookup(ifname=lease.interface)[0]
    except IndexError as e:
        logger.error('Interface %s not found, can not set IP.',
                     lease.interface)
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
    set_dns(lease)


def set_dns(lease):
    if systemd_resolved_status() is True:
        set_dns_systemd_resolved(lease)
    elif os.path.exists(RESOLVCONF_ADMIN):
        set_dns_resolvconf_admin(lease)
    elif os.path.exists(RESOLVCONF):
        set_dns_resolvconf(lease)


def set_dns_resolvconf_admin(lease):
    cmd = [RESOLVCONF_ADMIN, 'add', lease.interface, lease.name_server]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    try:
        (stdout, stderr) = proc.communicate()
        return True
    except TypeError as e:
        logger.error(e)
    return False


def set_dns_resolvconf(lease):
    cmd = [RESOLVCONF, '-a', lease.interface]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdin = '\n'.join(['nameserver ' + nm for nm in
                       lease.name_server.split()])
    stdin = str.encode(stdin)
    try:
        (stdout, stderr) = proc.communicate(stdin)
        return True
    except TypeError as e:
        logger.error(e)
    return False


def set_dns_systemd_resolved(lease):
    # NOTE: if systemd-resolved is not already running, we might not want to
    # run it in case there's specific system configuration for other resolvers
    ipr = IPRoute()
    index = ipr.link_lookup(ifname=lease.interface)[0]
    # Construct the argument to pass to DBUS.
    # the equivalent argument for:
    # busctl call org.freedesktop.resolve1 /org/freedesktop/resolve1 \
    # org.freedesktop.resolve1.Manager SetLinkDNS 'ia(iay)' 2 1 2 4 1 2 3 4
    # is SetLinkDNS(2, [(2, [8, 8, 8, 8])]_
    iay = [(2, [int(b) for b in ns.split('.')])
           for ns in lease.name_server.split()]
    #        if '.' in ns
    #        else (10, [ord(x) for x in
    #            socket.inet_pton(socket.AF_INET6, ns)])
    bus = SystemBus()
    resolved = bus.get_object('org.freedesktop.resolve1',
                              '/org/freedesktop/resolve1')
    manager = Interface(resolved,
                        dbus_interface='org.freedesktop.resolve1.Manager')
    try:
        manager.SetLinkDNS(index, iay)
        return True
    except DBusException as e:
        logger.error(e)
        return False


def systemd_resolved_status():
    bus = SystemBus()
    systemd = bus.get_object('org.freedesktop.systemd1',
                             '/org/freedesktop/systemd1')
    manager = Interface(systemd,
                        dbus_interface='org.freedesktop.systemd1.Manager')
    unit = manager.LoadUnit('sytemd-resolved.service')
    proxy = bus.get_object('org.freedesktop.systemd1', str(unit))
    r = proxy.Get('org.freedesktop.systemd1.Unit',
                  'ActiveState',
                  dbus_interface='org.freedesktop.DBus.Properties')
    if str(r) == 'active':
        return True
    return False
