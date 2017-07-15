# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""Class to Initialize and call external script."""
from __future__ import absolute_import, unicode_literals

import logging
import os
import subprocess

import attr

from .constants import (LEASEATTRS2ENVKEYS, LEASEATTRS_SAMEAS_ENVKEYS,
                        SCRIPT_ENV_KEYS, STATES2REASONS)

logger = logging.getLogger('dhcpcanon')


@attr.s
class ClientScript(object):
    """Simulates the behaviour of the isc-dhcp client-script or nm-dhcp-helper.

    `client-script
    <https://anonscm.debian.org/cgit/pkg-dhcp/isc-dhcp.git/tree/client/scripts/linux>`_
    or `nm-dhcp-helper
    <https://github.com/NetworkManager/NetworkManager/tree/master/src/dhcp>`_.

    """

    scriptname = attr.ib(default=None)
    env = attr.ib(default=attr.Factory(dict))

    def __attrs_post_init__(self, env=None):
        """."""
        logger.debug('Modifying ClientScript obj after creating it.')
        if env is None:
            self.env = dict.fromkeys(SCRIPT_ENV_KEYS, str(''))
        else:
            self.env = env

    def script_init(self, lease, state, prefix='', medium=''):
        """Initialize environment to pass to the external script."""
        if self.scriptname is not None:
            logger.debug('Modifying ClientScript obj, setting env.')
            if isinstance(state, int):
                reason = STATES2REASONS[state]
            else:
                reason = state
            self.env['reason'] = str(reason)
            self.env['medium'] = str(medium)
            self.env['client'] = str('dhcpcanon')
            self.env['pid'] = str(os.getpid())

            for k in LEASEATTRS_SAMEAS_ENVKEYS:
                self.env[k] = str(lease.__getattribute__(k))

            for k, v in LEASEATTRS2ENVKEYS.items():
                self.env[k] = str(lease.__getattribute__(v))
        else:
            logger.debug('There is not script path.')

    def script_go(self, scriptname=None, env=None):
        """Run the external script."""
        scriptname = self.scriptname or scriptname
        if scriptname is not None:
            env = self.env or env
            logger.debug('Calling script %s', scriptname)
            logger.debug('with env %s', env)
            sp = None
            try:
                sp = subprocess.check_output([scriptname],
                                             stderr=subprocess.STDOUT, env=env)
            except subprocess.CalledProcessError as e:
                sp = e.output
                logger.debug('sp err %s', sp)
                return sp
        return None
