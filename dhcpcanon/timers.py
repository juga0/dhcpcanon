# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""DCHP client implementation of the anonymity profile (RFC7844),
module functions."""

import logging
import random
from pytz import utc
from datetime import datetime, timedelta

from constants import MAX_DELAY_SELECTING, RENEW_PERC, REBIND_PERC
from constants import DT_PRINT_FORMAT

logger = logging.getLogger(__name__)


def future_dt_str(dt, td):
    """."""
    if isinstance(td, int) or isinstance(td, float):
        td = timedelta(seconds=td)
    future_dt = dt + td
    return future_dt.strftime(DT_PRINT_FORMAT)


def nowutc():
    """."""
    now = datetime.utcnow().replace(tzinfo=utc)
    return now


def gen_delay_selecting():
    """."""
    delay = float(random.randint(0, MAX_DELAY_SELECTING))
    logger.debug('Delay to enter in SELECTING %s.' % delay)
    logger.debug('SELECTING will happen on %s',
                 future_dt_str(nowutc(), delay))
    return delay


def gen_timeout_resend(attempts):
    """."""
    # RFC3121: For example, in a 10Mb/sec Ethernet
    # internetwork, the delay before the first retransmission SHOULD be 4
    # seconds randomized by the value of a uniform random number chosen
    # from the range -1 to +1.  Clients with clocks that provide resolution
    # granularity of less than one second may choose a non-integer
    # randomization value.  The delay before the next retransmission SHOULD
    # be 8 seconds randomized by the value of a uniform number chosen from
    # the range -1 to +1.  The retransmission delay SHOULD be doubled with
    # subsequent retransmissions up to a maximum of 64 seconds.  Th
    timeout = 2 ** (attempts + 1) + random.uniform(-1, +1)
    logger.debug('next timeout resending will happen on %s',
                 future_dt_str(nowutc(), timeout))
    return timeout


def gen_timeout_request_renew(lease):
    """."""
    # In both RENEWING and REBINDING states,
    # if the client receives no response to its DHCPREQUEST
    # message, the client SHOULD wait one-half of the remaining
    # time until T2 (in RENEWING state) and one-half of the
    # remaining lease time (in REBINDING state), down to a
    # minimum of 60 seconds, before retransmitting the
    # DHCPREQUEST message.
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
    """."""
    # Times T1 and T2 SHOULD be chosen with some
    # random "fuzz" around a fixed value, to avoid synchronization of
    # client reacquisition.
    renewing_time = lease_time * RENEW_PERC - elapsed
    # FIXME: the random intervals here could deanonymize
    range_fuzz = lease_time * REBIND_PERC - renewing_time
    fuzz = random.uniform(-(range_fuzz),
                          +(range_fuzz))
    renewing_time += fuzz
    logger.debug('Renewing time %s.', renewing_time)
    return renewing_time


def gen_rebinding_time(lease_time, elapsed=0):
    """."""
    rebinding_time = lease_time * REBIND_PERC - elapsed
    # FIXME: the random intervals here could deanonymize
    range_fuzz = lease_time - rebinding_time
    fuzz = random.uniform(-(range_fuzz),
                          +(range_fuzz))
    rebinding_time += fuzz
    logger.debug('Rebinding time %s.', rebinding_time)
    return rebinding_time
