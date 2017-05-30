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
            if self.scriptname is not None:
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
            self.env['network_number'] = str(lease.subnet)
            self.env['broadcast_address'] = lease.broadcast_address
            self.env['domain_name_servers'] = lease.name_server
            self.env['routers'] = lease.router
            self.env['dhcp_server_identifier'] = str(lease.server_id)
            self.env['next_server'] = lease.next_server
            self.env['domain_name'] = lease.domain
            self.env['dhcp_lease_time'] = str(lease.lease_time)
            self.env['dhcp_renewal_time'] = str(lease.renewal_time)
            self.env['dhcp_rebinding_time'] = str(lease.rebinding_time)
            self.env['expire'] = lease.expiry
            self.env['renew'] = lease.renew
            self.env['rebind'] = lease.rebind
            # logger.debug('env %s', self.env)

    def script_go(self, scriptname=None, env=None):
        scriptname = self.scriptname or scriptname
        if scriptname is not None:
            env = self.env or env
            logger.debug('calling script %s with env %s', scriptname, env)
            sp = subprocess.Popen([scriptname], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, env=env,
                                  close_fds=True, shell=False)
            out, err = sp.communicate()
            if sp.returncode != 0:
                logger.debug('sp err %s', err)
            return sp.returncode
        return None

    def gen_lease_str(self):
        # FIXME: what are the numbers in renew, rebind, expire?
        text = """lease {
  interface "{interface}";
  fixed-address {ip_address};
  option subnet-mask {subnet_mask};
  option routers {routers};
  option dhcp-lease-time {dhcp_lease_time};
  option dhcp-message-type 5;
  option domain-name-servers {domain_name_servers};
  option dhcp-server-identifier {dhcp_server_identifier};
  option dhcp-renewal-time {dhcp_renewal_time};
  option broadcast-address {broadcast_address};
  option dhcp-rebinding-time {dhcp_rebinding_time};
  option host-name "";
  option domain-name "{domain_name_servers}";
  renew 3 {renew};
  rebind 1 2017/06/05 17:53:07;
  expire 3 2017/06/07 11:53:07;
}
""".format(self.env)
        return text
