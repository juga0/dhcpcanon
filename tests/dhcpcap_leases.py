# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""."""
from dhcpcanon.dhcpcaplease import DHCPCAPLease

LEASE_INIT = DHCPCAPLease(interface='enp0s25', address='', server_id='',
                          next_server='', router='', subnet_mask='',
                          broadcast_address='', domain='', name_server='',
                          lease_time='', renewal_time='', rebinding_time='',
                          subnet_mask_cidr='', subnet='', expiry='', renew='',
                          rebind='')


LEASE_REQUEST = DHCPCAPLease(interface='eth0', address='192.168.1.23',
                             server_id='192.168.1.1',
                             next_server='192.168.1.1',
                             router='192.168.1.1', subnet_mask='255.255.255.0',
                             broadcast_address='192.168.1.255',
                             domain='localdomain',
                             name_server='192.168.1.1', lease_time='43200',
                             renewal_time='21600', rebinding_time='37800',
                             subnet_mask_cidr='24', subnet='192.168.1.0',
                             expiry='', renew='', rebind='')


LEASE_ACK = DHCPCAPLease(interface='eth0', address='192.168.1.23',
                         server_id='192.168.1.1', next_server='192.168.1.1',
                         router='192.168.1.1', subnet_mask='255.255.255.0',
                         broadcast_address='192.168.1.255',
                         domain='localdomain',
                         name_server='192.168.1.1', lease_time='43200',
                         renewal_time='21600', rebinding_time='37800',
                         subnet_mask_cidr='24', subnet='192.168.1.0',
                         expiry='17-06-23 12:00:00', renew='17-06-23 06:00:00',
                         rebind='17-06-23 10:30:00')
