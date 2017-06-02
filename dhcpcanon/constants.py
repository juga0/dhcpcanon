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

"""."""
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

# NOTE: 3.6. The choice of option numbers and the specific ordering of option
# numbers in the PRL can be used to fingerprint the client
# SHOULD only request a
# minimal number of options in the PRL and SHOULD also randomly shuffle
# the ordering of option codes in the PRL
# PARAM_REQ_LIST = '\x01\x03\x06\x0fw\xfc'# \x1c3
PARAM_REQ_LIST = '\x01\x1c\x02\x03\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a'
XID_MIN = 1
XID_MAX = 900000000

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
REASONS_NM = [
    'bound', 'renew', 'rebind',
    'timeout',
    'nak', 'expire',
    'end',
    'fail',
    'abend'
]

STATES2REASONS = {
    STATE_PREINIT: 'PREINIT',
    STATE_INIT: 'INIT',
    STATE_BOUND: 'BOUND',
    STATE_END: 'END',
    STATE_REBINDING: 'REBIND',
    STATE_RENEWING: 'RENEW',
    # "EXPIRE"
    STATE_ERROR: "TIMEOUT",
    # "FAIL"
    # "STOP"
}

# similar to systemd
DHCP_EVENTS = {
    'STOP': 0,
    'IP_ACQUIRE': 1,
    'IP_CHANGE': 2,
    'EXPIRED': 3,
    'RENEW': 4,
}

SCRIPT_ENV_KEYS = ['reason', 'medium', 'client', 'pid', 'interface',
                   'ip_address', 'subnet_mask', 'network_number',
                   'broadcast_address', 'domain_name_servers', 'routers',
                   'dhcp_server_identifier', 'next_server', 'domain_name',
                   'dhcp_lease_time', 'dhcp_renewal_time',
                   'dhcp_rebinding_time', 'expire', 'renew', 'rebind']

LEASEATTRS_SAMEAS_ENVKEYS = [
    'interface', 'subnet_mask', 'broadcast_address', 'next_server', 'rebind',
    'renew']

LEASEATTRS2ENVKEYS = {
    'ip_address': 'address',
    'routers': 'router',
    'network_number': 'subnet',
    'domain_name': 'domain',
    'domain_name_servers': 'name_server',
    'dhcp_lease_time': 'lease_time',
    'dhcp_rebinding_time': 'rebinding_time',
    'dhcp_renewal_time': 'renewal_time',
    'expire': 'expiry',
    'dhcp_server_identifier': 'server_id',
}
