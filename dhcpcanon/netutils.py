# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""Netowrk utils for the DHCP client implementation of the Anonymity Profile
([:rfc:`7844`])."""
import logging
import os.path
import subprocess

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
        exit(1)
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
    if os.path.exists(RESOLVCONF_ADMIN):
        cmd = [RESOLVCONF_ADMIN, 'add', lease.interface, lease.name_server]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        try:
            (stdout, stderr) = proc.communicate()
        except TypeError as e:
            logger.error(e)
        return
    # TODO: check systemd-resolved
    if os.path.exists(RESOLVCONF):
        cmd = [RESOLVCONF, '-a', lease.interface]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                tdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdin = '\n'.join(['nameserver ' + nm for nm in
                           lease.name_server.split()])
        stdin = str.encode(stdin)
        try:
            (stdout, stderr) = proc.communicate(stdin)
        except TypeError as e:
            logger.error(e)
        logger.debug('result %s, stdout %s, stderr %s', proc.returncode,
                     stdout, stderr)


def systemd_resolved_status():
    # NOTE: not used currently
    from dbus import SystemBus, Interface
    bus = SystemBus()
    systemd = bus.get_object('org.freedesktop.systemd1',
                             '/org/freedesktop/systemd1')
    manager = Interface(systemd,
                        dbus_interface='org.freedesktop.systemd1.Manager')
    unit = manager.LoadUnit('sytemd-resolved.service')
    proxy = bus.get_object('org.freedesktop.systemd1', str(unit))
    # resolved = Interface(proxy,
    #                      dbus_interface='org.freedesktop.systemd1.Unit')
    r = proxy.Get('org.freedesktop.systemd1.Unit',
                  'ActiveState',
                  dbus_interface='org.freedesktop.DBus.Properties')
    if str(r) == 'active':
        return True
    return True


def pydbus_systemd_resolved_status():
    # NOTE: not used currently
    from pydbus import SystemBus
    bus = SystemBus()
    systemd = bus.get('org.freedesktop.systemd1')
    unit = systemd.LoadUnit('systemd-resolved.service')
    resolved = bus.get('.systemd1', unit[0])
    resolved.Get('org.freedesktop.systemd1.Unit', 'ActiveState')


def systemd_resolved_start():
    # NOTE: not used currently
    from pydbus import SystemBus
    bus = SystemBus()
    systemd = bus.get(".systemd1")
    try:
        systemd.StartUnit("systemd-resolved.service", "fail")
    except:
        # g-io-error-quark: GDBus.Error:org.freedesktop.systemd1.NoSuchUnit:
        # Unit foo.service not found. (36)
        logger.error("Could not start systemd-resolved")


def systemd_resolved_get_dns():
    # busctl introspect org.freedesktop.resolve1
    # /org/freedesktop/resolve1/link/_35 |grep DNS
    pass


def systemd_resolved_set_dns():
    # ip l
    # busctl call org.freedesktop.resolve1
    # /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager
    # SetLinkDNS 'ia(iay)' 5 1 2 4 8 8 8 8
    pass
