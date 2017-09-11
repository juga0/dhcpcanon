# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""Constants for the DHCP client implementation of the Anonymity Profile
([:rfc:`7844`])."""
import logging

logger = logging.getLogger(__name__)


DT_PRINT_FORMAT = '%y-%m-%d %H:%M:%S'

# client
##########
BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
META_MAC = '00:00:00:00:00:00'
BROADCAST_ADDR = '255.255.255.255'
META_ADDR = '0.0.0.0'
CLIENT_PORT = 68
SERVER_PORT = 67

# DHCP timers
##########
LEASE_TIME = 1209600  # 14 DAYS
RENEWING_TIME = 604800  # 7 DAYS
REBINDING_TIME = 1058400  # 12 DAYS
DELAY_SELECTING = 10
TIMEOUT_SELECTING = 60
TIMEOUT_REQUESTING = 60
TIMEOUT_REQUEST_RENEWING = 226800
TIMEOUT_REQUEST_REBINDING = 75600

MAX_DELAY_SELECTING = 10
RENEW_PERC = 0.5
REBIND_PERC = 0.875

# DHCP number packet retransmissions
MAX_ATTEMPTS_DISCOVER = 5
MAX_OFFERS_COLLECTED = 1
MAX_ATTEMPTS_REQUEST = 5

# DHCP packet
##############
DHCP_OFFER_OPTIONS = [
    'server_id', 'subnet_mask', 'broadcast_address',
    'router', 'domain', 'name_server', 'lease_time', 'renewal_time',
    'rebinding_time']

# DHCP FSM
#############
STATE_ERROR = -1
STATE_PREINIT = 0
STATE_INIT = 1
STATE_SELECTING = 2
STATE_REQUESTING = 3
STATE_BOUND = 4
STATE_RENEWING = 5
STATE_REBINDING = 6
STATE_END = 7

STATES2NAMES = {
    STATE_ERROR: 'ERROR',
    STATE_PREINIT: 'PREINIT',
    STATE_INIT: 'INIT',
    STATE_SELECTING: 'SELECTING',
    STATE_REQUESTING: 'REQUESTING',
    STATE_BOUND: 'BOUND',
    STATE_RENEWING: 'RENEWING',
    STATE_REBINDING: 'REBINDING',
    STATE_END: 'END',
}

# NM integration
#####################
REASONS_NM = ['bound', 'renew', 'rebind', 'expiry', 'fail', 'timeout',
              'nak', 'end', 'abend']

REASONS_CL = ['MEDIUM', 'PREINIT', 'BOUND', 'RENEW', 'REBIND', 'REBOOT',
              'EXPIRE', 'FAIL', 'STOP', 'RELEASE', 'NBI', 'TIMEOUT']

STATES2REASONS = {
    STATE_PREINIT: 'PREINIT',
    STATE_INIT: 'INIT',
    STATE_SELECTING: 'SELECTING',
    STATE_BOUND: 'BOUND',
    STATE_END: 'END',
    STATE_REBINDING: 'REBIND',
    STATE_RENEWING: 'RENEW',
    STATE_ERROR: "FAIL",
    # NOTE: there could be implemented a way toknow the reason for failure so
    # that it can be passed to NetworkManager, as dhclient does, ie:
    # "STOP", "EXPIRE"
}

# systemd events
DHCP_EVENTS = {
    'STOP': 0,
    'IP_ACQUIRE': 1,
    'IP_CHANGE': 2,
    'EXPIRED': 3,
    'RENEW': 4,
}

SCRIPT_ENV_KEYS = ['reason', 'medium', 'interface',
                   # 'client', 'pid',
                   'new_ip_address', 'new_subnet_mask', 'new_network_number',
                   'new_domain_name_servers', 'new_domain_name', 'new_routers',
                   'new_broadcast_address', 'new_next_server',
                   'new_dhcp_server_id']

LEASEATTRS_SAMEAS_ENVKEYS = ['interface', 'reason']
# 'client', 'pid',
# these are not set as environment but put in lease file
# , 'rebind', 'renew', 'expiry'

LEASEATTRS2ENVKEYS = {
    'address': 'new_ip_address',
    'subnet_mask': 'new_subnet_mask',
    'broadcast_address': 'new_broadcast_address',
    'next_server': 'new_next_server',
    'server_id': 'new_server_id',

    'network': 'new_network_number',
    'domain': 'new_domain_name',
    'name_server': 'new_domain_name_servers',
    'router': 'new_routers',
}

LEASE_ATTRS2LEASE_FILE = {
    'interface': 'interface',

    'address': 'fixed-address',

    'subnet_mask': 'option subnet-mask',
    'broadcast_address': 'option broadcast-address',

    'domain': 'option domain-name',
    'name_server': 'option domain-name-servers',
    'router': 'option routers',

    'lease_time': 'option dhcp-lease-time',
    'rebinding_time': 'option dhcp-rebinding-time',
    'renewal_time': 'option dhcp-renewal-time',
    'server_id': 'option dhcp-server-identifier',
    'renew': 'renew',
    'rebind': 'rebind',
    'expiry': 'expiry',
}

LEASE_ATTRS2LEASE_LOG = {
    'interface': 'interface',

    'subnet_mask': 'option subnet_mask',
    'broadcast_address': 'option broadcast_address',

    'address': 'ip_address',

    'router': 'option routers',
    'domain': 'option domain_name',
    'name_server': 'option domain_name_servers',

    'lease_time': 'option dhcp_lease_time',
    'renewal_time': 'option dhcp_renewal_time',
    'rebinding_time': 'option dhcp_rebinding_time',
    'server_id': 'option dhcp_server_identifier',
    'expiry': 'expiry',
}

ENV_OPTIONS_REQ = {
    'requested_subnet_mask': '1',
    'requested_router': '1',
    'requested_domain_name_server': '1',
    'requested_domain_name': '1',
    'requested_router_discovery': '1',
    'requested_static_route': '1',
    'requested_vendor_specific': '1',
    'requested_netbios_nameserver': '1',
    'requested_netbios_node_type': '1',
    'requested_netbios_scope': '1',
    'requested_classless_static_route_option': '1',
    'requested_private_classless_static_route': '1',
    'requested_private_proxy_autodiscovery': '1',
}

PRL = b"\x01\x03\x06\x0f\x1f\x21\x2b\x2c\x2e\x2f\x79\xf9\xfc"
"""
SD_DHCP_OPTION_SUBNET_MASK                     = 1
SD_DHCP_OPTION_ROUTER                          = 3
SD_DHCP_OPTION_DOMAIN_NAME_SERVER              = 6
SD_DHCP_OPTION_DOMAIN_NAME                     = 15
SD_DHCP_OPTION_ROUTER_DISCOVER                 = 31
SD_DHCP_OPTION_STATIC_ROUTE                    = 33
SD_DHCP_OPTION_VENDOR_SPECIFIC                 = 43
SD_DHCP_OPTION_NETBIOS_NAMESERVER              = 44
SD_DHCP_OPTION_NETBIOS_NODETYPE                = 46
SD_DHCP_OPTION_NETBIOS_SCOPE                   = 47
SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE          = 121
SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE  = 249
SD_DHCP_OPTION_PRIVATE_PROXY_AUTODISCOVERY     = 252
"""

FSM_ATTRS = ['request_attempts', 'discover_attempts', 'script',
             'time_sent_request', 'current_state', 'client']

XID_MIN = 1
XID_MAX = 900000000

SCRIPT_PATH = '/sbin/dhcpcanon-script'
PID_PATH = '/var/run/dhcpcanon.pid'
LEASE_PATH = '/var/lib/dhcp/dhcpcanon.leases'
CONF_PATH = '/etc/dhcp/dhcpcanon.conf'
RESOLVCONF = '/sbin/resolvconf'
