# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""DCHP client implementation of the Anonymity Profiles [:rfc:`7844`]."""
from __future__ import absolute_import, unicode_literals

import logging

from netaddr import AddrFormatError
from scapy.arch import get_if_raw_hwaddr
from scapy.automaton import ATMT, Automaton
from scapy.config import conf
from scapy.sendrecv import sendp
from scapy.utils import str2mac

from .clientscript import ClientScript
from .constants import (CLIENT_PORT, DELAY_SELECTING, FSM_ATTRS, LEASE_TIME,
                        MAX_ATTEMPTS_DISCOVER, MAX_ATTEMPTS_REQUEST,
                        MAX_OFFERS_COLLECTED, REBINDING_TIME, RENEWING_TIME,
                        SERVER_PORT, STATE_BOUND, STATE_END, STATE_ERROR,
                        STATE_INIT, STATE_PREINIT, STATE_REBINDING,
                        STATE_RENEWING, STATE_REQUESTING, STATE_SELECTING,
                        STATES2NAMES, TIMEOUT_REQUEST_REBINDING,
                        TIMEOUT_REQUEST_RENEWING, TIMEOUT_REQUESTING,
                        TIMEOUT_SELECTING)
from .dhcpcap import DHCPCAP
from .dhcpcaputils import isack, isnak, isoffer
from .timers import (gen_delay_selecting, gen_timeout_request_rebind,
                     gen_timeout_request_renew, gen_timeout_resend, nowutc)

logger = logging.getLogger(__name__)


class DHCPCAPFSM(Automaton):
    """DHCP client Finite State Machine (FSM).

    ... todo::

        - Group methods that do the same.
        - Check other implementations for the functionality not specifiyed in
          the RFCs.

    """

    def dict_self(self):
        """Return the self object attributes not inherited as dict."""
        return {k: v for k, v in self.__dict__.items() if k in FSM_ATTRS}

    def __str__(self):
        return str(self.dict_self())

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def reset(self, iface=None, client_mac=None):
        """Reset object attributes when state is INIT."""
        logger.debug('Reseting attributes.')
        if iface is None:
            iface = conf.iface
        if client_mac is None:
            # scapy for python 3 returns byte, not tuple
            tempmac = get_if_raw_hwaddr(iface)
            if isinstance(tempmac, tuple) and len(tempmac) == 2:
                mac = tempmac[1]
            else:
                mac = tempmac
            client_mac = str2mac(mac)
        self.client = DHCPCAP(iface, client_mac)
        self.script = ClientScript()
        self.time_sent_request = None
        self.discover_attempts = 0
        self.request_attempts = 0
        self.current_state = STATE_PREINIT
        self.offers = list()

    def __init__(self, iface=None, server_port=None,
                 client_port=None, client_mac=None,
                 scriptfile=None, delay_selecting=None, timeout_select=None,
                 debug_level=5, *args, **kargs):
        """Overwrites Automaton __init__ method.

        [ :rfc:`7844#section-3.4` ] ::
            If the hardware address is reset to a new
            randomized value, the DHCP client SHOULD use the new randomized
            value in the DHCP messages

        """
        logger.debug('Inizializating FSM.')
        super(DHCPCAPFSM, self).__init__(*args, **kargs)
        self.debug_level = debug_level
        self.delay_selecting = delay_selecting
        self.timeout_select = timeout_select
        self.reset(iface, client_mac)
        self.client.server_port = server_port or SERVER_PORT
        self.client.client_port = client_port or CLIENT_PORT
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
        logger.debug('FSM thread id: %s.', self.threadid)

    def get_timeout(self, state, function):
        """Workaround to get timeout in the ATMT.timeout class method."""
        state = STATES2NAMES[state]
        for timeout_fn_t in self.timeout[state]:
            # access the function name
            if timeout_fn_t[1] is not None and \
               timeout_fn_t[1].atmt_condname == function.atmt_condname:
                logger.debug('Timeout for state %s, function %s, is %s',
                             state, function.atmt_condname, timeout_fn_t[0])
                return timeout_fn_t[0]
        return None

    def set_timeout(self, state, function, newtimeout):
        """
        Workaround to change timeout values in the ATMT.timeout class method.

        self.timeout format is::

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
            if timeout_fn_t[1] is not None and \
               timeout_fn_t[1].atmt_condname == function.atmt_condname:
                # convert list to tuple to make it mutable
                timeout_l = list(timeout_fn_t)
                # modify the timeout
                timeout_l[0] = newtimeout
                # set the new timeoute to self.timeout
                i = self.timeout[state].index(timeout_fn_t)
                self.timeout[state][i] = tuple(timeout_l)
                logger.debug('Set state %s, function %s, to timeout %s',
                             state, function.atmt_condname, newtimeout)

    def send_discover(self):
        """Send discover."""
        assert self.client
        assert self.current_state == STATE_INIT or \
            self.current_state == STATE_SELECTING
        pkt = self.client.gen_discover()
        sendp(pkt)
        # FIXME:20 check that this is correct,: all or only discover?
        if self.discover_attempts < MAX_ATTEMPTS_DISCOVER:
            self.discover_attempts += 1
        timeout = gen_timeout_resend(self.discover_attempts)
        self.set_timeout(self.current_state,
                         self.timeout_selecting,
                         timeout)
        # logger.info('DHCPDISCOVER on %s to %s port %s' %
        #             (self.client.iface, self.client.server_mac,
        #              self.client.server_port)))

    def select_offer(self):
        """Select an offer from the offers received.

        [:rfc:`2131#section-4.2`]::

            DHCP clients are free to use any strategy in selecting a DHCP
            server among those from which the client receives a DHCPOFFER.

        [:rfc:`2131#section-4.4.1`]::

            The time
            over which the client collects messages and the mechanism used to
            select one DHCPOFFER are implementation dependent.

        Nor [:rfc:`7844`] nor [:rfc:`2131`] specify the algorithm.
        Here, currently the first offer is selected.

        .. todo::
             * Check other implementations algorithm to select offer.
        """
        logger.debug('Selecting offer.')
        pkt = self.offers[0]
        self.client.handle_offer(pkt)

    def send_request(self):
        """Send request."""
        assert self.client
        if self.current_state == STATE_BOUND:
            pkt = self.client.gen_request_unicast()
        else:
            pkt = self.client.gen_request()
        sendp(pkt)
        logger.debug('Modifying FSM obj, setting time_sent_request.')
        self.time_sent_request = nowutc()
        logger.info('DHCPREQUEST of %s on %s to %s port %s',
                    self.client.iface, self.client.client_ip,
                    self.client.server_ip, self.client.server_port)

        # FIXME:10 check that this is correct,: all of only discover?
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
        """Process a received ACK packet.

        Not specifiyed in[:rfc:`7844`], [:rfc:`2131#section-2.2.`]::

            the allocating
            server SHOULD probe the reused address before allocating the
            address, e.g., with an ICMP echo request, and the client SHOULD
            probe the newly received address, e.g., with ARP.

        """
        if isack(pkt):
            # FIXME:30 check the fields match the previously offered ones?
            try:
                self.event = self.client.handle_ack(pkt,
                                                    self.time_sent_request)
            except AddrFormatError as err:
                logger.error(err)
                # the net values are not valid, go back to SELECTING state
                # (or just previous state?)
                raise self.SELECTING()
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
        logger.debug('INIT')
        if self.current_state is not STATE_PREINIT:
            self.reset()
        self.current_state = STATE_INIT
        # [:rfc:`2131#section-4.4.1`]::
        # The client SHOULD wait a random time between one and ten
        #  seconds to desynchronize the use of DHCP at startup
        if self.delay_selecting is None:
            delay_selecting = gen_delay_selecting()
        else:
            delay_selecting = self.delay_selecting
        self.set_timeout(self.current_state,
                         self.timeout_delay_selecting,
                         delay_selecting)
        if self.timeout_select is not None:
            self.set_timeout(STATE_SELECTING,
                             self.timeout_selecting,
                             self.timeout_select)

    @ATMT.timeout(INIT, DELAY_SELECTING)
    def timeout_delay_selecting(self):
        """Timeout of delay selecting on INIT state."""
        raise self.SELECTING()

    @ATMT.action(timeout_delay_selecting)
    def on_timeout_delay_selecting(self):
        """Action on timeout of delay selecting on INIT state."""
        self.send_discover()
        logger.debug('DISCOVER sent')

    @ATMT.state()
    def SELECTING(self):
        """SELECTING state."""
        logger.debug('SELECTING')
        self.current_state = STATE_SELECTING

    @ATMT.receive_condition(SELECTING)
    def receive_offer(self, pkt):
        """Receive offer on SELECTING state."""
        if isoffer(pkt):
            logger.debug('OFFER received')
            self.offers.append(pkt)
            if len(self.offers) >= MAX_OFFERS_COLLECTED:
                self.select_offer()
                raise self.REQUESTING()
            else:
                # FIXME:60 neeeded?
                raise self.SELECTING()

    @ATMT.action(receive_offer)
    def on_select_offer(self):
        """Action on receive offer on SELECTING state."""
        self.send_request()

    @ATMT.timeout(SELECTING, TIMEOUT_SELECTING)
    def timeout_selecting(self):
        """Timeout of selecting on SELECTING state.

        Not specifiyed in [:rfc:`7844#section-`].See comments in
        :func:`dhcpcapfsm.DHCPCAPFSM.timeout_request`.

        """
        if self.discover_attempts >= MAX_ATTEMPTS_DISCOVER:
            logger.debug('Maximum number of discover retries is %s'
                         ' and already sent %s',
                         MAX_ATTEMPTS_DISCOVER, self.discover_attempts)
            if len(self.offers) < 1:
                logger.debug('No offer was received')
                raise self.ERROR()
            else:
                # FIXME:40 correct?
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
        """Action on retransmit discover on SELECTING state."""
        self.send_discover()
        logger.debug('DISCOVER resent')

    @ATMT.state(error=1)
    def ERROR(self):
        """ERROR state."""
        logger.debug('ERROR')
        self.current_state = STATE_ERROR
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()
        raise self.END()

    @ATMT.state()
    def REQUESTING(self):
        """REQUESTING state."""
        logger.debug('REQUESTING')
        self.current_state = STATE_REQUESTING

    @ATMT.receive_condition(REQUESTING)
    def receive_ack_requesting(self, pkt):
        """Receive ack on REQUESTING state."""
        if self.process_received_ack(pkt):
            raise self.BOUND()

    @ATMT.receive_condition(REQUESTING)
    def receive_nak_requesting(self, pkt):
        """Receive nak on REQUESTING state."""
        if self.process_received_nak(pkt):
            raise self.INIT()

    @ATMT.action(receive_ack_requesting)
    def on_ack_requesting(self):
        """Action on ack requesting on REQUESTING state."""
        # [:rfc:`7844`]: not recording lease
        logger.debug('Setting timers.')
        self.set_timers()

    @ATMT.timeout(REQUESTING, TIMEOUT_REQUESTING)
    def timeout_requesting(self):
        """Timeout of requesting on REQUESTING state.

        Not specifiyed in [:rfc:`7844`]

        [:rfc:`2131#section-3.1`]::

            might retransmit the
            DHCPREQUEST message four times, for a total delay of 60 seconds

        """
        if self.discover_requests >= MAX_ATTEMPTS_REQUEST:
            logger.debug('Maximum number of reuqest retries reached'
                         ' is %s and already sent %s',
                         MAX_ATTEMPTS_REQUEST, self.disover_requests)
            raise self.ERROR()
        raise self.REQUESTING()

    @ATMT.action(timeout_requesting)
    def on_retransmit_request(self):
        """Action on timeout of requesting on REQUESTING state.

        Send REQUEST.

        """
        self.send_request()

    @ATMT.state()
    def BOUND(self):
        """BOUND state."""
        logger.debug('BOUND')
        logger.info('(%s) state changed %s -> bound', self.client.iface,
                    STATES2NAMES[self.current_state])
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
        # FIXME:100 udp
        self.send_request()

    @ATMT.state()
    def RENEWING(self):
        """RENEWING state."""
        self.current_state = STATE_RENEWING
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()

    @ATMT.receive_condition(RENEWING)
    def receive_ack_renewing(self, pkt):
        """Receive ack on RENEWING state."""
        if self.process_received_ack(pkt):
            raise self.BOUND()

    @ATMT.receive_condition(RENEWING)
    def receive_nak_renewing(self, pkt):
        """Receive nak on RENEWING state."""
        if self.process_received_nak(pkt):
            raise self.INIT()

    @ATMT.action(receive_ack_renewing)
    def on_renewing(self):
        """Action on renewing on RENEWING state.

        Not recording lease, but restarting timers.

        """
        self.client.lease.sanitize_net_values()
        self.client.lease.set_times(self.time_sent_request)
        self.set_timers()

    @ATMT.timeout(RENEWING, TIMEOUT_REQUEST_RENEWING)
    def timeout_request_renewing(self):
        """Timeout of renewing on RENEWING state.

        Same comments as in
        :func:`dhcpcapfsm.DHCPCAPFSM.timeout_requesting`.

        """
        if self.request_attempts >= MAX_ATTEMPTS_REQUEST:
            logger.debug('Maximum number of request retries renewing is'
                         ' %s, already sent %s.',
                         MAX_ATTEMPTS_REQUEST, self.request_attempts)
            raise self.ERROR()
        raise self.RENEWING()

    @ATMT.action(timeout_request_renewing)
    def on_retransmit_request_renewing(self):
        """Action on timeout of request newing on RENEWING state.

        Send REQUEST.

        """
        self.send_request()

    @ATMT.timeout(RENEWING, REBINDING_TIME)
    def rebinding_time_expires(self):
        """Timeout of rebinding time on RENEWING state."""
        raise self.REBINDING()

    @ATMT.action(rebinding_time_expires)
    def on_rebinding_time_expires(self):
        """Action on rebinding time expires on RENEWING state."""
        self.send_request()

    @ATMT.state()
    def REBINDING(self):
        """REBINDING state."""
        self.current_state = STATE_REBINDING
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()

    @ATMT.timeout(REBINDING, LEASE_TIME)
    def lease_expires(self):
        """Timeout of lease on REBINDING state.
        Not sending DHCPRELEASE to minimize deanonymization

        [:rfc:`2131#section-4.4.6`]::

            Note that the correct operation
            of DHCP does not depend on the transmission of DHCPRELEASE.

        """
        raise self.STATE_INIT()

    @ATMT.receive_condition(REBINDING)
    def receive_ack_rebinding(self, pkt):
        """Receive ack on REBINDING state."""
        if self.process_received_ack(pkt):
            raise self.BOUND()

    @ATMT.receive_condition(REBINDING)
    def receive_nak_rebinding(self, pkt):
        """Receive nak on REBINDING state."""
        if self.process_received_nak(pkt):
            raise self.INIT()

    @ATMT.action(receive_ack_rebinding)
    def on_rebinding(self):
        """Action on receive ACK rebinding on REBINDING state.

        Not recording lease, but start new lease

        """
        self.set_timers()

    @ATMT.timeout(REBINDING, TIMEOUT_REQUEST_REBINDING)
    def timeout_request_rebinding(self):
        """Timeout of request rebinding on REBINDING state.

        Same comments as in
        :func:`dhcpcapfsm.DHCPCAPFSM.timeout_requesting`.

        """
        if self.request_attempts >= MAX_ATTEMPTS_REQUEST:
            logger.debug('Maximum number of request retries rebinding is'
                         ' %s, already sent %s.',
                         MAX_ATTEMPTS_REQUEST, self.request_attempts)
            raise self.ERROR()
        raise self.REBINDING()

    @ATMT.action(timeout_request_rebinding)
    def on_retransmit_request_rebinding(self):
        """Action on request rebinding on REBINDING state.

        Send REQUEST.

        """
        self.send_request()

    @ATMT.state(final=1)
    def END(self):
        """END state."""
        logger.debug('END')
        self.current_state = STATE_END
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()
        self.reset()
