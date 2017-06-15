# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""."""
from scapy.all import BOOTP, DHCP, IP, UDP, Ether

# client packets

dhcp_discover = (
    Ether(src="00:01:02:03:04:05", dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=[b'\x00\x01\x02\x03\x04\x05']) /
    DHCP(options=[
        ('message-type', 'discover'),
        'end'])
)

dhcp_request = (
    Ether(src="00:01:02:03:04:05", dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=[b'\x00\x01\x02\x03\x04\x05']) /
    DHCP(options=[
        ('message-type', 'request'),
        ("requested_addr", "192.168.1.23"),
        ("server_id", "192.168.1.1"),
        'end'])
)

dhcp_request_unicast = (
    Ether(src="00:01:02:03:04:05", dst="00:0a:0b:0c:0d:0f") /
    IP(src="192.168.1.23", dst="192.168.1.1") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=[b'\x00\x01\x02\x03\x04\x05'], ciaddr="192.168.1.23") /
    DHCP(options=[
        ('message-type', 'request'),
        'end'])
)

dhcp_decline = (
    Ether(src="00:01:02:03:04:05", dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=['\x00\x01\x02\x03\x04\x05'], options='c\x82Sc') /
    DHCP(options=[
        ('message-type', 'decline'),
        ("requested_addr", "192.168.1.23"),
        ("server_id", "192.168.1.1"),
        'end'])
)

dhcp_request_unicast = (
    Ether(src="00:01:02:03:04:05", dst="ff:ff:ff:ff:ff:ff") /
    IP(src="192.168.1.23", dst="192.168.1.1") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=['\x00\x01\x02\x03\x04\x05'], options='c\x82Sc') /
    DHCP(options=[
        ('message-type', 'request'),
        ("server_id", "192.168.1.1"),
        'end'])
)

dhcp_inform = (
    Ether(src="00:01:02:03:04:05", dst="ff:ff:ff:ff:ff:ff") /
    IP(src="192.168.1.23", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=['\x00\x01\x02\x03\x04\x05'], ciaddr="192.168.1.23",
          options='c\x82Sc') /
    DHCP(options=[
        ('message-type', 'inform'),
        'end'])
)

# server packets
#################

dhcp_offer = (
    Ether(src="00:0a:0b:0c:0d:0f", dst="00:01:02:03:04:05") /
    IP(src="192.168.1.1", dst="192.168.1.23") /
    UDP(sport=67, dport=68) /
    BOOTP(op=2, yiaddr="192.168.1.23", siaddr="192.168.1.1",
          giaddr='0.0.0.0') /
    DHCP(options=[
        ('message-type', 'offer'),
        ('server_id', "192.168.1.1"),
        ('lease_time', 43200),
        ('renewal_time', 21600),
        ('rebinding_time', 37800),
        ('subnet_mask', "255.255.255.0"),
        ('broadcast_address', "192.168.1.255"),
        ('router', "192.168.1.1"),
        ('name_server', "192.168.1.1"),
        ('domain', "localdomain"),
        'end']
    )
)

dhcp_ack = (
    Ether(src="00:0a:0b:0c:0d:0f", dst="00:01:02:03:04:05") /
    IP(src="192.168.1.1", dst="192.168.1.23") /
    UDP(sport=67, dport=68) /
    BOOTP(op=2, yiaddr="192.168.1.23", siaddr="192.168.1.1",
          giaddr='0.0.0.0') /
    DHCP(options=[
        ('message-type', 'ack'),
        ('server_id', "192.168.1.1"),
        ('lease_time', 43200),
        ('renewal_time', 21600),
        ('rebinding_time', 37800),
        ('subnet_mask', "255.255.255.0"),
        ('broadcast_address', "192.168.1.255"),
        ('router', "192.168.1.1"),
        ('name_server', "192.168.1.1"),
        ('domain', "localdomain"),
        'end'])
)
