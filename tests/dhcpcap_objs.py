# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""."""
from dhcpcanon.dhcpcaplease import DHCPCAPLease
from dhcpcanon.dhcpcap import DHCPCAP

# init, before send discover

# init after sent discover
client_init = DHCPCAP(iface='enp0s25', client_mac='f0:de:f1:b8:9b:db',
                      client_ip='0.0.0.0', client_port=68,
                      server_mac='ff:ff:ff:ff:ff:ff',
                      server_ip='255.255.255.255', server_port=67,
                      lease=DHCPCAPLease(address='', server_id='',
                                         next_server='', router='',
                                         subnet_mask='', broadcast_address='',
                                         domain='', name_server='', subnet='',
                                         lease_time='', renewal_time='',
                                         rebinding_time='',
                                         interface='enp0s25',
                                         subnet_mask_cidr='', network='',
                                         expiry='', renew='', rebind=''),
                      event=None)
# selecting after received offer
client_select = DHCPCAP(iface='enp0s25', client_mac='f0:de:f1:b8:9b:db',
                        client_ip='0.0.0.0', client_port=68,
                        server_mac='ff:ff:ff:ff:ff:ff',
                        server_ip='255.255.255.255', server_port=67,
                        lease=DHCPCAPLease(address='192.168.2.113',
                                           server_id='192.168.2.1',
                                           next_server='192.168.2.1',
                                           router='192.168.2.1',
                                           subnet_mask='255.255.255.0',
                                           broadcast_address='192.168.2.255',
                                           domain='localdomain',
                                           name_server='192.168.2.1',
                                           subnet='192.168.2.0',
                                           lease_time='43200',
                                           renewal_time='21600',
                                           rebinding_time='37800',
                                           interface='enp0s25',
                                           subnet_mask_cidr='24',
                                           network='',
                                           expiry='', renew='', rebind=''),
                        event=None)


# in requesting state after received ack
client_request = DHCPCAP(iface='enp0s25', client_mac='f0:de:f1:b8:9b:db',
                         client_ip='0.0.0.0', client_port=68,
                         server_mac='1c:74:0d:b2:e5:10',
                         server_ip='192.168.2.1', server_port=67,
                         lease=DHCPCAPLease(address='192.168.2.113',
                                            server_id='192.168.2.1',
                                            next_server='192.168.2.1',
                                            router='192.168.2.1',
                                            subnet_mask='255.255.255.0',
                                            broadcast_address='192.168.2.255',
                                            domain='localdomain',
                                            name_server='192.168.2.1',
                                            subnet='192.168.2.0',
                                            lease_time='43200',
                                            renewal_time='21600',
                                            rebinding_time='37800',
                                            interface='enp0s25',
                                            subnet_mask_cidr='24',
                                            network='',
                                            expiry='17-06-15 23:00:32',
                                            renew='17-06-15 17:00:32',
                                            rebind='17-06-15 21:30:32'),
                         event=4)
