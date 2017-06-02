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

"""DCHP client implementation of the anonymity profile (RFC7844)."""
import logging

from dhcpcanon.clientscript import ClientScript
# These first constants are overwritten on run time,
# but ATMT.timeout is a class method and needs initial values
from dhcpcanon.constants import (
    LEASE_TIME, RENEWING_TIME, REBINDING_TIME,
    DELAY_SELECTING, TIMEOUT_SELECTING, TIMEOUT_REQUESTING,
    TIMEOUT_REQUEST_RENEWING, TIMEOUT_REQUEST_REBINDING)
from dhcpcanon.constants import (CLIENT_PORT,
                                 MAX_ATTEMPTS_DISCOVER, MAX_ATTEMPTS_REQUEST,
                                 MAX_OFFERS_COLLECTED, SERVER_PORT,
                                 STATE_BOUND, STATE_END, STATE_ERROR,
                                 STATE_INIT, STATE_PREINIT, STATE_REBINDING,
                                 STATE_RENEWING, STATE_REQUESTING,
                                 STATE_SELECTING, STATES2NAMES)
from dhcpcanon.dhcpcap import DHCPCAP
from dhcpcanon.dhcpcaputils import isack, isnak, isoffer
from dhcpcanon.timers import (gen_delay_selecting, gen_timeout_request_rebind,
                              gen_timeout_request_renew, gen_timeout_resend,
                              nowutc)
from scapy.arch import get_if_raw_hwaddr
from scapy.automaton import ATMT, Automaton
from scapy.config import conf
from scapy.sendrecv import sendp
from scapy.utils import str2mac

logger = logging.getLogger(__name__)


class DHCPCAPFSM(Automaton):
    """DHCP client FSM."""

    def reset(self, iface=None, client_mac=None, **kargs):
        """Reset object attributes when state is INIT."""
        logger.debug('Reseting attributes.')
        self.client = DHCPCAP(iface, client_mac)
        self.script = ClientScript()
        self.time_sent_request = None
        self.discover_attempts = 0
        self.request_attempts = 0
        self.current_state = STATE_PREINIT
        self.offers = list()

    def parse_args(self, iface=None, server_port=None,
                   client_port=None, client_mac=None,
                   scriptfile=None, **kargs):
        """Overwrite Automaton method."""
        # RFC7844: an external program should randomize MAC prior
        # running this.
        super(DHCPCAPFSM, self).parse_args()
        logger.debug('Automaton parsing args.')
        self.debug_level = 5
        # self.store_packets = 1

        self.reset()

        # base attrs
        self.client.iface = iface or conf.iface
        if client_mac is None:
            _, client_mac = get_if_raw_hwaddr(self.client.iface)
            self.client.client_mac = str2mac(client_mac)
        else:
            self.client.client_mac = client_mac
        self.client.server_port = server_port or SERVER_PORT
        self.client.client_port = client_port or CLIENT_PORT
        # capture filters
        self.socket_kargs = {
            'filter': 'udp and src port {0} and dst port {1}'
                      ' and ether dst {2}'.
                      format(self.client.server_port,
                             self.client.client_port,
                             self.client.client_mac)
            }
        self.script.scriptname = scriptfile
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()
        logger.debug('end automaton parsing args')

    def get_timeout(self, state, function):
        """ Workaround to change timeout in the ATMT.timeout class method.

        self.timeout format is:
        {'STATE': [
            (TIMEOUT0, <function foo>),
            (TIMEOUT1, <function bar>)),
            (None, None)
            ],
        }
        """
        state = STATES2NAMES[state]
        logger.debug('state %s, function %s', state, function)
        for timeout_fn_t in self.timeout[state]:
            # access the function name
            if timeout_fn_t[1] == function:
                logger.debug('timeout is %s', timeout_fn_t[0])
                return timeout_fn_t[0]

    def set_timeout(self, state, function, newtimeout):
        """ Workaround to change timeout values in the ATMT.timeout
        class method decorator.
        self.timeout format is:
        {'STATE': [
            (TIMEOUT0, <function foo>),
            (TIMEOUT1, <function bar>)),
            (None, None)
            ],
        }
        """

        state = STATES2NAMES[state]
        for timeout_fn_t in self.timeout[state]:
            # access the function name
            if timeout_fn_t[1] == function:
                # convert list to tuple to make it mutable
                timeout_l = list(timeout_fn_t)
                # modify the timeout
                timeout_l[0] = newtimeout
                # set the new timeoute to self.timeout
                i = self.timeout[state].index(timeout_fn_t)
                self.timeout[state][i] = tuple(timeout_l)
                logger.debug('Set state %s, function %s, to timeout %s',
                             state, function, newtimeout)

    def send_discover(self):
        """Send discover."""
        assert self.client
        assert self.current_state == STATE_INIT or \
            self.current_state == STATE_SELECTING
        pkt = self.client.gen_discover()
        sendp(pkt)
        # FIXME: check that this is correct,: all or only discover?
        if self.discover_attempts < MAX_ATTEMPTS_DISCOVER:
            self.discover_attempts += 1
        timeout = gen_timeout_resend(self.discover_attempts)
        self.set_timeout(self.current_state,
                         self.timeout_selecting,
                         timeout)
        # logger.info('DHCPDISCOVER on %s to %s port %s' %
        #             (self.client.iface, self.client.server_mac,
        #              self.client.server_port))

    def select_offer(self):
        """Select offer."""
        logger.debug('Selecting offer.')
        # TODO: algorithm to select offer
        pkt = self.offers[0]
        self.client.handle_offer(pkt)

    def send_request(self):
        """Send request."""
        assert self.client
        pkt = self.client.gen_request()
        sendp(pkt)
        self.time_sent_request = nowutc()
        logger.info('DHCPREQUEST of %s on %s to %s port %s',
                    self.client.iface, self.client.client_ip,
                    self.client.server_ip, self.client.server_port)

        # FIXME: check that this is correct,: all of only discover?
        # and if > MAX_DISCOVER_RETRIES?
        if self.request_attempts < MAX_ATTEMPTS_REQUEST:
            self.request_attempts *= 2
            logger.debug('Increased request attempts to %s',
                         self.request_attempts)
        if self.current_state == STATE_RENEWING:
            timeout_renewing = gen_timeout_request_renew(self.client.lease)
            self.set_timeout(self.current_state,
                             self.timeout_request_renewing,
                             timeout_renewing)
        elif self.current_state == STATE_REBINDING:
            timeout_rebinding = gen_timeout_request_rebind(self.client.lease)
            self.set_timeout(self.current_state,
                             self.timeout_request_rebinding,
                             timeout_rebinding)
        else:
            timeout_requesting = \
                gen_timeout_resend(self.request_attempts)
            self.set_timeout(self.current_state,
                             self.timeout_requesting,
                             timeout_requesting)

    def set_timers(self):
        """Set renewal, rebinding times."""
        logger.debug('setting timeouts')
        self.set_timeout(self.current_state,
                         self.renewing_time_expires,
                         self.client.lease.renewal_time)
        self.set_timeout(self.current_state,
                         self.rebinding_time_expires,
                         self.client.lease.rebinding_time)

    def process_received_ack(self, pkt):
        """Process a received ACK packet."""
        if isack(pkt):
            # FIXME: check the fields match the previously offered ones?
            self.event = self.client.handle_ack(pkt)
            self.client.lease.set_times(self.time_sent_request)
            # TODO: if error in parse, go back to SELECTING
            # TODO: if address is taken (PING?) go to INIT and send DHCPDELINE
            logger.info('DHCPACK of %s from %s' %
                        (self.client.client_ip, self.client.server_ip))
            return True
        return False

    def process_received_nak(self, pkt):
        """Process a received NAK packet."""
        if isnak(pkt):
            logger.info('DHCPNAK of %s from %s',
                        self.client.client_ip, self.client.server_ip)
            return True
        return False

    #################################################################
    # State machine
    #################################################################
    @ATMT.state(initial=1)
    def INIT(self):
        """INIT state."""
        # in case INIT is reached from other state, initialize attributes
        # reset all variables.
        if self.current_state != STATE_PREINIT:
            self.reset()
        self.current_state = STATE_INIT
        # NOTE: not in RFC7844 but RFC2131
        # The client SHOULD wait a random time between one and ten
        #  seconds to desynchronize the use of DHCP at startup
        delay_selecting = gen_delay_selecting()
        self.set_timeout(self.current_state,
                         self.timeout_delay_selecting,
                         delay_selecting)

    @ATMT.timeout(INIT, DELAY_SELECTING)
    def timeout_delay_selecting(self):
        """Timeout of delay selecting on INIT state."""
        raise self.SELECTING()

    @ATMT.action(timeout_delay_selecting)
    def on_timeout_delay_selecting(self):
        """Action on timeout of delay selecting on INIT state."""
        self.send_discover()

    @ATMT.state()
    def SELECTING(self):
        """SELECTING state."""
        self.current_state = STATE_SELECTING

    @ATMT.receive_condition(SELECTING)
    def receive_offer(self, pkt):
        "Receive offer on SELECTING state."
        if isoffer(pkt):
            self.offers.append(pkt)
            if len(self.offers) >= MAX_OFFERS_COLLECTED:
                self.select_offer()
                raise self.REQUESTING()
            else:
                # FIXME: neeeded?
                logger.debug('needed?')
                raise self.SELECTING()

    @ATMT.action(receive_offer)
    def on_select_offer(self):
        """Action on receive offer on SELECTING state."""
        self.send_request()

    @ATMT.timeout(SELECTING, TIMEOUT_SELECTING)
    def timeout_selecting(self):
        """Timeout of selecting on SELECTING state."""
        # FIXME: implementation details are not mentioned in RFC
        if self.discover_attempts >= MAX_ATTEMPTS_DISCOVER:
            logger.debug('Maximum number of discover retries is %s'
                         ' and already sent %s',
                         MAX_ATTEMPTS_DISCOVER, self.discover_attempts)
            if len(self.offers) < 1:
                logger.debug('No offer was received')
                raise self.ERROR()
            else:
                # FIXME: correct?
                logger.debug('needed? Use the offers received')
                raise self.REQUESTING()
        # else self.discover_attempts < MAX_ATTEMPTS_DISCOVER
        if len(self.offers) < MAX_OFFERS_COLLECTED:
            logger.debug('needed? Naximum number of offers not reached')
            raise self.SELECTING()

        logger.debug('Naximum number of offers reached')
        raise self.REQUESTING()

    @ATMT.action(timeout_selecting)
    def on_retransmit_discover(self):
        "Action on retransmit discover on SELECTING state."
        self.send_discover()

    @ATMT.state(error=1)
    def ERROR(self):
        """ERROR state."""
        self.current_state = STATE_ERROR
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()
        raise self.END()

    # @ATMT.action(timeout_selecting)
    # def on_ERROR(self):
    #  logger.debug("Action on ERROR.")

    @ATMT.state()
    def REQUESTING(self):
        """REQUESTING state."""
        self.current_state = STATE_REQUESTING

    @ATMT.receive_condition(REQUESTING)
    def receive_ack_requesting(self, pkt):
        "Receive ack on REQUESTING state."
        if self.process_received_ack(pkt):
            raise self.BOUND()

    @ATMT.receive_condition(REQUESTING)
    def receive_nak_requesting(self, pkt):
        "Receive nak on REQUESTING state."
        if self.process_received_nak(pkt):
            raise self.INIT()

    @ATMT.action(receive_ack_requesting)
    def on_ack_requesting(self):
        "Action on ack requesting on REQUESTING state."
        # NOTE RFC78444: not recording lease
        self.set_timers()

    @ATMT.timeout(REQUESTING, TIMEOUT_REQUESTING)
    def timeout_requesting(self):
        """Timeout of requesting on REQUESTING state."""
        # FIXME: implementation details are not mentioned in RFC
        if self.discover_requests >= MAX_ATTEMPTS_REQUEST:
            logger.debug('Maximum number of reuqest retries reached'
                         ' is %s and already sent %s',
                         MAX_ATTEMPTS_REQUEST, self.disover_requests)
            raise self.ERROR()
        raise self.REQUESTING()

    @ATMT.action(timeout_requesting)
    def on_retransmit_request(self):
        """Action on timeout of requesting on REQUESTING state."""
        self.send_request()

    @ATMT.state()
    def BOUND(self):
        """BOUND state."""
        logger.info('(%s) state changed %s -> bound' %
                    (self.client.iface,
                     STATES2NAMES[self.current_state]))
        self.current_state = STATE_BOUND
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()
        # TODO: go daemon?

    @ATMT.timeout(BOUND, RENEWING_TIME)
    def renewing_time_expires(self):
        """Timout of renewing time."""
        raise self.RENEWING()

    @ATMT.action(renewing_time_expires)
    def on_renewing_time_expires(self):
        """Action on renewing time expires on BOUND state."""
        # FIXME: udp
        self.send_request()

    @ATMT.state()
    def RENEWING(self):
        """RENEWING state."""
        self.current_state = STATE_RENEWING
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()

    @ATMT.receive_condition(RENEWING)
    def receive_ack_renewing(self, pkt):
        "Receive ack on RENEWING state."
        if self.process_received_ack(pkt):
            raise self.BOUND()

    @ATMT.receive_condition(RENEWING)
    def receive_nak_renewing(self, pkt):
        "Receive nak on RENEWING state."
        if self.process_received_nak(pkt):
            raise self.INIT()

    @ATMT.action(receive_ack_renewing)
    def on_renewing(self):
        """Action on renewing on RENEWING state."""
        # NOTE: not recording lease
        self.client.lease.sanitize_net_values()
        self.client.lease.set_times(self.time_sent_request)
        self.set_timers()
        # FIXME: restart lease

    @ATMT.timeout(RENEWING, TIMEOUT_REQUEST_RENEWING)
    def timeout_request_renewing(self):
        """Timeout of renewing on RENEWING state."""
        # FIXME: implementation details are not mentioned in RFC
        if self.request_attempts >= MAX_ATTEMPTS_REQUEST:
            logger.debug('Maximum number of request retries renewing is'
                         ' %s, already sent %s.',
                         MAX_ATTEMPTS_REQUEST, self.request_attempts)
            raise self.ERROR()
        raise self.RENEWING()

    @ATMT.action(timeout_request_renewing)
    def on_retransmit_request_renewing(self):
        """Action on timeout of request newing on RENEWING state."""
        self.send_request()

    @ATMT.timeout(RENEWING, REBINDING_TIME)
    def rebinding_time_expires(self):
        "Timeout of rebinding time on RENEWING state."
        raise self.REBINDING()

    @ATMT.action(rebinding_time_expires)
    def on_rebinding_time_expires(self):
        """Action on rebinding time expires on RENEWING state."""
        # broadcast
        self.send_request()

    @ATMT.state()
    def REBINDING(self):
        """REBINDING state."""
        self.current_state = STATE_REBINDING
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()

    @ATMT.timeout(REBINDING, LEASE_TIME)
    def lease_expires(self):
        "Timeoute of lease on REBINDING state."
        # NOTE: not sending DHCPRELEASE to minimaze deanonymization
        # RFC2131 4.4.6 Note that the correct operation
        # of DHCP does not depend on the transmission of DHCPRELEASE messages.
        raise self.STATE_INIT()

    @ATMT.receive_condition(REBINDING)
    def receive_ack_rebinding(self, pkt):
        "Receive ack on REBINDING state."
        if self.process_received_ack(pkt):
            raise self.BOUND()

    @ATMT.receive_condition(REBINDING)
    def receive_nak_rebinding(self, pkt):
        "Receive nak on REBINDING state."
        if self.process_received_nak(pkt):
            raise self.INIT()

    @ATMT.action(receive_ack_rebinding)
    def on_rebinding(self):
        """Action on receive ACK rebinding on REBINDING state."""
        # NOTE: not recording lease
        self.client.lease.sanitize_net_values()
        self.client.lease.set_times(self.time_sent_request)
        self.set_timers()
        # TODO: start new lease

    @ATMT.timeout(REBINDING, TIMEOUT_REQUEST_REBINDING)
    def timeout_request_rebinding(self):
        """Timeout of request rebinding on REBINDING state."""
        # FIXME: implementation details are not mentioned in RFC
        if self.request_attempts >= MAX_ATTEMPTS_REQUEST:
            logger.debug('Maximum number of request retries rebinding is'
                         ' %s, already sent %s.',
                         MAX_ATTEMPTS_REQUEST, self.request_attempts)
            raise self.ERROR()
        raise self.REBINDING()

    @ATMT.action(timeout_request_rebinding)
    def on_retransmit_request_rebinding(self):
        """Action on request rebinding on REBINDING state."""
        self.send_request()

    @ATMT.state(final=1)
    def END(self):
        """END state."""
        self.current_state = STATE_END
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()
        self.reset()
