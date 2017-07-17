.. _implementation:

Message types and options details in all layers
------------------------------------------------

DHCPDISCOVER
~~~~~~~~~~~~~

Always broadcast in AP::

    Ehter: src=client_mac, dst="ff:ff:ff:ff:ff:ff"
    IP: src="0.0.0.0", dst="255.255.255.255"
    UDP: sport=68, dport=67
    BOOTP: Client Hardware address (chaddr in scapy)
    DHCP: Message Type option (message-type in scapy)

DHCPREQUEST
~~~~~~~~~~~~~

In SELECTING state: Broadcast in AP::

    Ehter: src=client_mac, dst="ff:ff:ff:ff:ff:ff"
    IP: src="0.0.0.0", dst="255.255.255.255"
    UDP: sport=68, dport=67
    BOOTP: Client Hardware address (chaddr in scapy)
    DHCP: Message Type option (message-type in scapy)
    DHCP: Server Identifier option (server_id in scapy, siaddr in server BOOTP offer)
    DHCP: Requested IP option (requested_addr in scapy, yiaddr in server BOOTP offer)

In RENEWING state: Unicast to server id::

    Ehter: src=client_mac, dst=server_mac
    IP: src=client_ip, dst=server_ip
    UDP: sport=68, dport=67
    BOOTP: Client Hardware address (chaddr in scapy)
    DHCP: Message Type option (message-type in scapy)
    Client IP address (ciaddr=client_ip)?

In REBINDING state: broadcast::

    Ehter: src=client_mac, dst="ff:ff:ff:ff:ff:ff"
    IP: src="0.0.0.0", dst="255.255.255.255"
    UDP: sport=68, dport=67
    BOOTP: Client Hardware address (chaddr in scapy)
    DHCP: Message Type option (message-type in scapy)
    Client IP address (ciaddr=client_ip)?


DHCPDECLINE
~~~~~~~~~~~~~
Always broadcast?::

    Ehter: src=client_mac, dst="ff:ff:ff:ff:ff:ff"
    IP: src="0.0.0.0", dst="255.255.255.255"
    UDP: sport=68, dport=67
    BOOTP: Client Hardware address (chaddr in scapy)
    DHCP: Message Type option (message-type in scapy)
    DHCP: Server Identifier option (server_id in scapy, siaddr in server BOOTP offer)
    DHCP: Requested IP option (requested_addr in scapy, yiaddr in server BOOTP offer)

DHCPRELEASE
~~~~~~~~~~~~~

Always unicast, is not being used::

    Ehter: src=client_mac, dst=server_mac
    IP: src=client_ip, dst=server_ip
    UDP: sport=68, dport=67
    BOOTP: Client Hardware address (chaddr in scapy)
    DHCP: Message Type option (message-type in scapy)
    DHCP: Server Identifier option (server_id in scapy, siaddr in server BOOTP offer)

DHCPINFORM
~~~~~~~~~~~~~

Always broadcast in Anonymity Profile, is not being used::

    Ehter: src=client_mac, dst="ff:ff:ff:ff:ff:ff"
    IP: src=client_ip, dst="255.255.255.255"
    UDP: sport=68, dport=67
    BOOTP: Client Hardware address (chaddr in scapy)
    BOOTP: Client IP address (ciaddr=client_ip)
    DHCP: Message Type option (message-type in scapy)


