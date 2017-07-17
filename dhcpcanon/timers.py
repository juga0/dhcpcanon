# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""Timers for the DHCP client implementation of the Anonymity Profile
([:rfc:`7844`])."""
from __future__ import absolute_import

import logging
import random
from datetime import datetime, timedelta

from .constants import (DT_PRINT_FORMAT, MAX_DELAY_SELECTING, REBIND_PERC,
                        RENEW_PERC)

logger = logging.getLogger(__name__)


def future_dt_str(dt, td):
    """."""
    if isinstance(td, str):
        td = float(td)
    td = timedelta(seconds=td)
    future_dt = dt + td
    return future_dt.strftime(DT_PRINT_FORMAT)


def nowutc():
    """."""
    # now = datetime.utcnow().replace(tzinfo=utc)
    now = datetime.now()
    return now


def gen_delay_selecting():
    """Generate the delay in seconds in which the DISCOVER will be sent.

    [:rfc:`2131#section-4.4.1`]::

        The client SHOULD wait a random time between one and ten seconds to
        desynchronize the use of DHCP at startup.

    """
    delay = float(random.randint(0, MAX_DELAY_SELECTING))
    logger.debug('Delay to enter in SELECTING %s.', delay)
    logger.debug('SELECTING will happen on %s',
                 future_dt_str(nowutc(), delay))
    return delay


def gen_timeout_resend(attempts):
    """Generate the time in seconds in which DHCPDISCOVER wil be retransmited.

    [:rfc:`2131#section-3.1`]::

        might retransmit the
        DHCPREQUEST message four times, for a total delay of 60 seconds

    [:rfc:`2131#section-4.1`]::

        For example, in a 10Mb/sec Ethernet
        internetwork, the delay before the first retransmission SHOULD be 4
        seconds randomized by the value of a uniform random number chosen
        from the range -1 to +1.  Clients with clocks that provide resolution
        granularity of less than one second may choose a non-integer
        randomization value.  The delay before the next retransmission SHOULD
        be 8 seconds randomized by the value of a uniform number chosen from
        the range -1 to +1.  The retransmission delay SHOULD be doubled with
        subsequent retransmissions up to a maximum of 64 seconds.

    """
    timeout = 2 ** (attempts + 1) + random.uniform(-1, +1)
    logger.debug('next timeout resending will happen on %s',
                 future_dt_str(nowutc(), timeout))
    return timeout


def gen_timeout_request_renew(lease):
    """Generate time in seconds to retransmit DHCPREQUEST.

    [:rfc:`2131#section-4..4.5`]::

        In both RENEWING and REBINDING states,
        if the client receives no response to its DHCPREQUEST
        message, the client SHOULD wait one-half of the remaining
        time until T2 (in RENEWING state) and one-half of the
        remaining lease time (in REBINDING state), down to a
        minimum of 60 seconds, before retransmitting the
        DHCPREQUEST message.

    """
    time_left = (lease.rebinding_time - lease.renewing_time) * RENEW_PERC
    if time_left < 60:
        time_left = 60
    logger.debug('Next request in renew will happen on %s',
                 future_dt_str(nowutc(), time_left))
    return time_left


def gen_timeout_request_rebind(lease):
    """."""
    time_left = (lease.lease_time - lease.rebinding_time) * RENEW_PERC
    if time_left < 60:
        time_left = 60
    logger.debug('Next request on rebinding will happen on %s',
                 future_dt_str(nowutc(), time_left))
    return time_left


def gen_renewing_time(lease_time, elapsed=0):
    """Generate RENEWING time.

    [:rfc:`2131#section-4.4.5`]::

        T1
        defaults to (0.5 * duration_of_lease).  T2 defaults to (0.875 *
        duration_of_lease).  Times T1 and T2 SHOULD be chosen with some
        random "fuzz" around a fixed value, to avoid synchronization of
        client reacquisition.

    """
    renewing_time = int(lease_time) * RENEW_PERC - elapsed
    # FIXME:80 [:rfc:`2131#section-4.4.5`]: the chosen "fuzz" could fingerprint
    # the implementation
    # NOTE: here using same "fuzz" as systemd?
    range_fuzz = int(lease_time) * REBIND_PERC - renewing_time
    logger.debug('rebinding fuzz range %s', range_fuzz)
    fuzz = random.uniform(-(range_fuzz),
                          +(range_fuzz))
    renewing_time += fuzz
    logger.debug('Renewing time %s.', renewing_time)
    return renewing_time


def gen_rebinding_time(lease_time, elapsed=0):
    """."""
    rebinding_time = int(lease_time) * REBIND_PERC - elapsed
    # FIXME:90 [:rfc:`2131#section-4.4.5`]: the chosen "fuzz" could fingerprint
    # the implementation
    # NOTE: here using same "fuzz" as systemd?
    range_fuzz = int(lease_time) - rebinding_time
    logger.debug('rebinding fuzz range %s', range_fuzz)
    fuzz = random.uniform(-(range_fuzz),
                          +(range_fuzz))
    rebinding_time += fuzz
    logger.debug('Rebinding time %s.', rebinding_time)
    return rebinding_time
