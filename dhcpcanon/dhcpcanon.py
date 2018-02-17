#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""DCHP client implementation of the anonymity profile (RFC7844)."""

import argparse
import logging
import logging.config

from lockfile.pidlockfile import (PIDLockFile, AlreadyLocked,
                                  LockTimeout, LockFailed)
from scapy.config import conf

# in python3 this seems to be the only way to to disable:
# WARNING: Failed to execute tcpdump.
conf.logLevel = logging.ERROR

from . import __version__
from .conflog import LOGGING
from .constants import (CLIENT_PORT, SERVER_PORT, SCRIPT_PATH, PID_PATH)
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
             'dhcpcanon when it gets a lease. Without this option '
             'dhcpcanon will configure the network by itself.'
             'If unspecified, the '
             'default /sbin/dhcpcanon-script is used, which is a copy of'
             'dhclient-script(8) for a description of this file.'
             'If dhcpcanon is running with NetworkManager, it will'
             'be called with the script nm-dhcp-helper.')
    parser.add_argument(
        '-pf', metavar='pid-file', nargs='?',
        const=PID_PATH,
        help='Path to the process ID file. If unspecified, the'
             'default /var/run/dhcpcanon.pid is used. '
             'This option is used by NetworkManager to check whether '
             'dhcpcanon is already running.')
    args = parser.parse_args()
    logger.debug('args %s', args)

    # do not put interfaces in promiscuous mode
    conf.sniff_promisc = conf.promisc = 0
    conf.checkIPaddr = 1

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    logger.debug('args %s', args)
    if args.interface:
        conf.iface = args.interface
    logger.debug('interface %s' % conf.iface)
    if args.pf is not None:
        # This is only needed for nm
        pf = PIDLockFile(args.pf, timeout=5)
        try:
            pf.acquire()
            logger.debug('using pid file %s', pf)
        except AlreadyLocked as e:
            pf.break_lock()
            pf.acquire()
        except (LockTimeout, LockFailed) as e:
            logger.error(e)
    dhcpcap = DHCPCAPFSM(iface=conf.iface,
                         server_port=SERVER_PORT,
                         client_port=CLIENT_PORT,
                         scriptfile=args.sf,
                         delay_selecting=args.delay_selecting)
    dhcpcap.run()


if __name__ == '__main__':
    main()
