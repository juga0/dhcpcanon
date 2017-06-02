# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2

# Copyright 2016 juga <juga@riseup.net>

# This file is part of dhcpcanon.
#
# dhcpcanon is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# dhcpcanon is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with dhcpcanon.  If not, see <http://www.gnu.org/licenses/>.

"""Lease class."""
import logging

import attr
from dhcpcanon.timers import (future_dt_str, gen_rebinding_time,
                              gen_renewing_time, nowutc)
from netaddr import AddrFormatError, IPAddress, IPNetwork

logger = logging.getLogger('dhcpcanon')


@attr.s
class DHCPCAPLease(object):
    """."""
    interface = attr.ib(default='')
    address = attr.ib(default='')
    server_id = attr.ib(default='')
    next_server = attr.ib(default='')
    router = attr.ib(default='')
    subnet_mask = attr.ib(default='')
    broadcast_address = attr.ib(default='')
    domain = attr.ib(default='')
    name_server = attr.ib(default='')
    lease_time = attr.ib(default='')
    renewal_time = attr.ib(default='')
    rebinding_time = attr.ib(default='')
    subnet_mask_cidr = attr.ib(default='')
    subnet = attr.ib(default='')
    expiry = attr.ib(default='')
    renew = attr.ib(default='')
    rebind = attr.ib(default='')

    def set_times(self, sent_dt):
        """."""
        # RFC2131 4.4.1 The client records the lease expiration time
        # as the sum of the time at which the original request was
        # sent and the duration of the lease from the DHCPACK message.
        elapsed = (nowutc() - sent_dt).seconds
        self.renewal_time = gen_renewing_time(self.lease_time,
                                              elapsed)
        self.rebinding_time = gen_rebinding_time(self.lease_time,
                                                 elapsed)
        self.expiry = future_dt_str(sent_dt, self.lease_time)
        self.renew = future_dt_str(sent_dt, self.renewal_time)
        self.rebind = future_dt_str(sent_dt, self.rebinding_time)
        logger.debug('lease time: %s, expires on %s', self.lease_time,
                     self.expiry)
        logger.debug('renewal_time: %s, expires on %s',
                     self.renewal_time, self.renew)
        logger.debug('rebinding time: %s, expires on %s',
                     self.rebinding_time, self.rebind)

    def sanitize_net_values(self):
        """."""
        try:
            ipn = IPNetwork(self.address + '/' + self.subnet_mask)
        except AddrFormatError as e:
            # FIXME: add other errors
            logger.error(e)
        logger.debug('The IP address and network mask are sanitized')
        self.subnet_mask_cidr = str(ipn.prefixlen)
        self.subnet = str(ipn.network)
        try:
            ipn = IPAddress(self.router)
        except AddrFormatError as err:
            # FIXME: add other errors
            logger.error(err)
        logger.debug('The gateway is sanitized')

    def info_lease(self):
        """Print lease information."""
        logger.info('address %s', self.address)
        logger.info('plen %s (%s)', self.subnet_mask_cidr, self.subnet_mask)
        logger.info('gateway %s', self.router)
        logger.info('server identifier %s', self.server_id)
        logger.info('nameserver %s', self.name_server)
        logger.info('domain name %s', self.domain)
        logger.info('lease time %s', self.lease_time)
