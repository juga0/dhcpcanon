# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""Lease class for the DHCP client implementation of the Anonymity Profile
([:rfc:`7844`]).."""
from __future__ import absolute_import

import logging

import attr
from attr.validators import instance_of

from .timers import (future_dt_str, gen_rebinding_time, gen_renewing_time,
                     nowutc)

logger = logging.getLogger('dhcpcanon')


@attr.s
class DHCPCAPLease(object):
    """."""
    address = attr.ib(default='', validator=instance_of(str))
    server_id = attr.ib(default='', validator=instance_of(str))
    next_server = attr.ib(default='', validator=instance_of(str))
    router = attr.ib(default='', validator=instance_of(str))
    subnet_mask = attr.ib(default='', validator=instance_of(str))
    broadcast_address = attr.ib(default='', validator=instance_of(str))
    domain = attr.ib(default='', validator=instance_of(str))
    name_server = attr.ib(default='', validator=instance_of(str))
    subnet = attr.ib(default='', validator=instance_of(str))
    lease_time = attr.ib(default='', validator=instance_of(str))
    renewal_time = attr.ib(default='', validator=instance_of(str))
    rebinding_time = attr.ib(default='', validator=instance_of(str))
    # not given by the server
    interface = attr.ib(default='', validator=instance_of(str))
    # not given by the server, calculated on previous
    subnet_mask_cidr = attr.ib(default='', validator=instance_of(str))
    network = attr.ib(default='', validator=instance_of(str))
    expiry = attr.ib(default='', validator=instance_of(str))
    renew = attr.ib(default='', validator=instance_of(str))
    rebind = attr.ib(default='', validator=instance_of(str))

    # def __attrs_post_init__(self, sent_dt):
    #     """Initializes attributes after attrs __init__."""
    #     self.set_times(sent_dt)

    def set_times(self, sent_dt):
        """
        Set timers for the lease given the time in which the request was sent.

        [:rfc:`2131#section-4.4.1`]::

            The client records the lease expiration time
            as the sum of the time at which the original request was
            sent and the duration of the lease from the DHCPACK message.

        """
        logger.debug('Modifying Lease obj, setting timers.')
        elapsed = (nowutc() - sent_dt).seconds
        if self.renewal_time == '':
            self.renewal_time = gen_renewing_time(self.lease_time, elapsed)
        if self.rebinding_time == '':
            self.rebinding_time = gen_rebinding_time(self.lease_time, elapsed)
        self.expiry = future_dt_str(sent_dt, self.lease_time)
        self.renew = future_dt_str(sent_dt, self.renewal_time)
        self.rebind = future_dt_str(sent_dt, self.rebinding_time)
        logger.debug('lease time: %s, expires on %s', self.lease_time,
                     self.expiry)
        logger.debug('renewal_time: %s, expires on %s',
                     self.renewal_time, self.renew)
        logger.debug('rebinding time: %s, expires on %s',
                     self.rebinding_time, self.rebind)

    def info_lease(self):
        """Print lease information."""
        logger.info('address %s', self.address)
        logger.info('plen %s (%s)', self.subnet_mask_cidr, self.subnet_mask)
        logger.info('gateway %s', self.router)
        logger.info('server identifier %s', self.server_id)
        logger.info('nameserver %s', self.name_server)
        logger.info('domain name %s', self.domain)
        logger.info('lease time %s', self.lease_time)
