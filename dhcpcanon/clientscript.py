#
""""""
from __future__ import unicode_literals
import os
import logging
import attr
import subprocess

from constants import STATES2REASONS

logger = logging.getLogger('dhcpcanon')


@attr.s
class ClientScript(object):
    """Simulates the behaviour of isc-dhcp client-script or
    Network Manager nm-dhcp-helper.

    """
    scriptname = attr.ib(default=None)
    env = attr.ib(default=attr.Factory(dict))

    def script_init(self, lease, state, prefix='',  medium=''):
        logger.debug('script init with state %s', state)
        if type(state) == int:
            reason = STATES2REASONS[state]
        else:
            reason = state
        self.env['reason'] = reason
        # FIXME: what is medium?
        self.env['medium'] = medium
        self.env['client'] = 'dhcpcanon'
        self.env['pid'] = str(os.getpid())
        self.env['interface'] = str(lease.interface)
        self.env['ip_address'] = str(lease.address)
        self.env['subnet_mask'] = lease.subnet_mask
        self.env['network_number'] = str(lease.network)
        self.env['broadcast_address'] = lease.broadcast_address
        self.env['domain_name_servers'] = lease.name_server
        self.env['routers'] = lease.router
        self.env['dhcp_server_identifier'] = str(lease.server_address)
        self.env['next_server'] = lease.next_server
        self.env['domain_name'] = lease.domain
        # FIXME: what is expiry?
        self.env['expiry'] = str(lease.lease_time)
        self.env['dhcp_lease_time'] = str(lease.lease_time)
        self.env['dhcp_renewal_time'] = str(lease.renewal_time)
        self.env['dhcp_rebinding_time'] = str(lease.rebinding_time)
        # logger.debug('env %s', self.env)

    def script_go(self, scriptname=None, env=None):
        scriptname = self.scriptname or scriptname
        env = self.env or env
        logger.debug('calling script %s', scriptname)
        #  with env %s', scriptname,
                    #  envstr)
        # os.execve(scriptname, [scriptname], clientenv)
        p = subprocess.Popen([scriptname], shell=False,
                             stdin=None, stdout=None, stderr=None,
                             close_fds=True, env=env)
        # FIXME: what to do with p?
        return p
