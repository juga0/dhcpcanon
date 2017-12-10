# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""."""
import time

from scapy.all import (DHCP6_Solicit, DHCP6OptOptReq, DHCP6OptClientId,
                       DHCP6OptIA_NA, DHCP6OptRapidCommit, DHCP6OptElapsedTime,
                       DUID_LL, IPv6, UDP, Ether)

BROADCAST_MAC6 = "33:33:00:01:00:02"
BROADCAST_ADDR6 = "ff02::1:2"
META_ADDR6 = '0::0'
CLIENT_PORT6 = 546
SERVER_PORT6 = 547


# client packets
dhcp_discover = (
    Ether(src="00:01:02:03:04:05", dst="33:33:00:01:00:02") /
    IPv6(src="fe80::a00:27ff:fefe:8f95", dst="ff02::1:2") /
    UDP(sport=546, dport=547) /
    DHCP6_Solicit(trid=900000000) /
    DHCP6OptClientId(duid=DUID_LL(lladdr="00:01:02:03:04:05")) /
                    #  timeval=int(time.time())) /
    DHCP6OptIA_NA(iaid=0xf) /
    DHCP6OptRapidCommit() /
    # DHCP6OptElapsedTime() /
    # DHCP6OptOptReq(reqopts=b"\x17\x18")
    DHCP6OptOptReq(reqopts=[23, 24])
    )
