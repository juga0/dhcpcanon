# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""Class to Initialize and call external script."""
from __future__ import absolute_import, unicode_literals

import logging
import os
import subprocess

import attr

from .constants import (ENV_OPTIONS_REQ, LEASEATTRS2ENVKEYS,
                        LEASEATTRS_SAMEAS_ENVKEYS, SCRIPT_ENV_KEYS,
                        SCRIPT_PATH, STATES2REASONS)

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

    def __attrs_post_init__(self, scriptfile=None, env=None):
        """."""
        logger.debug('Modifying ClientScript obj after creating it.')
        self.scriptname = self.scriptname or scriptfile or SCRIPT_PATH
        if env is None:
            self.env = dict.fromkeys(SCRIPT_ENV_KEYS, str(''))
        else:
            self.env = env
        self.env['medium'] = str()
        self.env['pid'] = str(os.getpid())

    def script_init(self, lease, state, prefix='', medium=''):
        """Initialize environment to pass to the external script."""
        logger.debug('self.scriptname %s', self.scriptname)
        if self.scriptname is not None:
            logger.debug('Modifying ClientScript obj, setting env.')
            if isinstance(state, int):
                reason = STATES2REASONS[state]
            else:
                reason = state
            self.env['reason'] = str(reason)
            self.env['medium'] = self.env.get('medium') or str(medium)
            self.env['client'] = str('dhcpcanon')
            self.env['pid'] = str(os.getpid())
            for k in LEASEATTRS_SAMEAS_ENVKEYS:
                self.env[k] = str(lease.__getattribute__(k))
            for k, v in LEASEATTRS2ENVKEYS.items():
                self.env[v] = str(lease.__getattribute__(k))
            self.env.update(ENV_OPTIONS_REQ)
        else:
            logger.debug('There is not script path.')

    def script_go(self, scriptname=None, env=None):
        """Run the external script."""
        scriptname = self.scriptname or scriptname
        if scriptname is not None:
            env = self.env or env
            logger.info('Calling script %s', scriptname)
            logger.info('with env %s', env)
            proc = subprocess.Popen([scriptname], env=env,
                                    stderr=subprocess.STDOUT)
            try:
                (stdout, stderr) = proc.communicate()
                return True
            except TypeError as e:
                logger.error(e)
        return False
