
from scapy.all import Ether, IP, UDP, BOOTP, DHCP

dhcp_discover = (
    Ether(src="00:0a:0b:0c:0d:0f", dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=['\x00\x0a\x0b\x0c\x0d\x0f'], options='c\x82Sc') /
    DHCP(options=[
      ('message-type', 'discover'),
      'end']
      )
)

dhcp_offer = (
    Ether(src="00:01:02:03:04:05", dst="00:0a:0b:0c:0d:0f") /
    IP(src="192.168.1.1", dst="192.168.1.2") /
    UDP(sport=67, dport=68) /
    BOOTP(op=2, yiaddr="192.168.1.2", siaddr="192.168.1.1",
          giaddr='0.0.0.0') /
    DHCP(options=[
        ('message-type', 'offer'),
        ('server_id', "192.168.1.1"),
        ('lease_time', 129600),
        ('renewal_time', 604800),
        ('rebinding_time', 1058400),
        ('subnet_mask', "255.255.255.0"),
        ('broadcast_address', "192.168.1.255"),
        ('router', "192.168.1.1"),
        ('name_server', "192.168.1.1"),
        ('domain', "localdomain"),
        'end']
        )
)

dhcp_request = (
    Ether(src="00:0a:0b:0c:0d:0f", dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=['\x00\x0a\x0b\x0c\x0d\x0f'], options='c\x82Sc') /
    DHCP(options=[
      ('message-type', 'request'),
      ("requested_addr", "192.168.1.2"),
      ("server_id", "192.168.1.1"),
      'end']
      )
)

dhcp_ack = (
    Ether(src="00:01:02:03:04:05", dst="00:0a:0b:0c:0d:0f") /
    IP(src="192.168.1.1", dst="192.168.1.2") /
    UDP(sport=67, dport=68) /
    BOOTP(op=2, yiaddr="192.168.1.2", siaddr="192.168.1.1",
          giaddr='0.0.0.0') /
    DHCP(options=[
        ('message-type', 'ack'),
        ('server_id', "192.168.1.1"),
        ('lease_time', 129600),
        ('renewal_time', 604800),
        ('rebinding_time', 1058400),
        ('subnet_mask', "255.255.255.0"),
        ('broadcast_address', "192.168.1.255"),
        ('router', "192.168.1.1"),
        ('name_server', "192.168.1.1"),
        ('domain', "localdomain"),
        'end']
        )
)
