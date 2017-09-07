#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""DCHP client implementation of the anonymity profile (RFC7844)."""

import argparse
import logging
import logging.config

from scapy.config import conf

# in python3 this seems to be the only way to to disable:
# WARNING: Failed to execute tcpdump.
conf.logLevel = logging.ERROR

from . import __version__
from .conflog import LOGGING
from .constants import (CLIENT_PORT, SERVER_PORT, SCRIPT_PATH, LEASE_PATH,
                        CONF_PATH, PID_PATH)
from .dhcpcapfsm import DHCPCAPFSM

logging.config.dictConfig(LOGGING)
logger = logging.getLogger('dhcpcanon')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('interface', nargs='?',
                        help='interface to configure with DHCP')
    parser.add_argument('-v', '--verbose',
                        help='Set logging level to debug',
                        action='store_true')
    parser.add_argument('-l', '--lease', help='custom lease time',
                        default=None)
    parser.add_argument('--version', action='version',
                        help='version',
                        version='%(prog)s ' + __version__)
    parser.add_argument('-s', '--delay_selecting',
                        help='Selecting starts after a ramdon delay.',
                        action='store_true')
    # options to looks like dhclient
    parser.add_argument(
        '-sf', metavar='script-file', nargs='?',
        const=SCRIPT_PATH,
        help='Path to the network configuration script invoked by '
             'dhclient when it gets a lease. If unspecified, the '
             'default /sbin/dhcpcanon-script is used. See '
             'dhclient-script(8) for a description of this file.')
    parser.add_argument(
        '-pf', metavar='pid-file', nargs='?',
        const=PID_PATH,
        help='Path to the process ID file. If unspecified, the'
             'default /var/run/dhclient.pid is used')
    parser.add_argument(
        '-lf', metavar='lease-file', nargs='?',
        const=LEASE_PATH,
        help='Path to the lease database file. If unspecified, the'
             'default /var/lib/dhcp/dhclient.leases is used. See '
             'dhclient.leases(5) for a description of this file.')
    parser.add_argument(
        '-cf', metavar='config-file', nargs='?',
        const=CONF_PATH,
        help='Path to the client configuration file. If unspecified,'
             'the default /etc/dhcp/dhclient.conf is used. See '
             'dhclient.conf(5) for a description of this file.')
    parser.add_argument(
        '-d',
        action='store_true',
        help='Force dhclient to run as a foreground  process. '
             'Normally the DHCP  client will run in the foreground '
             'until is has configured an interface at which time it '
             'will revert to running in the background. This '
             'option is useful when running the client under a '
             'debugger, or when running it out of inittab on System V'
             ' systems.  This implies -v.')
    parser.add_argument('-q',
                        action='store_true',
                        help='Be quiet at startup, this is the default.')
    parser.add_argument('-N', action='store_true')
    parser.add_argument('-6', action='store_true')
    parser.add_argument('-4', action='store_true')
    args = parser.parse_args()
    logger.debug('args %s', args)

    # do not put interfaces in promiscuous mode
    conf.sniff_promisc = conf.promisc = 0
    conf.checkIPaddr = 1

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    logger.debug('args %s', args)
    if args.lease is not None:
        # TODO
        pass
    if args.interface:
        conf.iface = args.interface
    logger.debug('interface %s' % conf.iface)
    # FIXME: disabled for now
    # if args.pf is not None:
    #     import daemon
    #     from daemon import pidfile
    #     pf = pidfile.TimeoutPIDLockFile(args.pf)
    #     logger.debug('using pid file %s', pf)
    #     context = daemon.DaemonContext(pidfile=pf)
    #     # FIXME: it does not get daemonized
    dhcpcap = DHCPCAPFSM(iface=conf.iface,
                         server_port=SERVER_PORT,
                         client_port=CLIENT_PORT,
                         scriptfile=args.sf,
                         delay_selecting=args.delay_selecting)
    dhcpcap.run()


if __name__ == '__main__':
    main()
