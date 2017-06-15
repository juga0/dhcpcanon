.. _implementation:

Comments about dhcpcanon implementation and the RFCs
==========================================================

See :ref:`RFC7844 comments <rfc7844comm>` for detailed comments about
[:rfc:`7844`]. This page is focused on the
options and functionality implemented by ``dhcpcanon``.

``dhcpcanon`` implements the options and functionality specified as ``MUST``
in [:rfc:`7844`], but does not the ones specified as ``SHOULD`` or ``MAY``.
It does not implement the ones as ``SHOULD NOT``, unless found cases where
they have to be implemented in order servers reply.


Packet formant
-----------------

DHCPDISCOVER (always broadcast in AP)::

    Ehter: src=client_mac, dst="ff:ff:ff:ff:ff:ff"
    IP: src="0.0.0.0", dst="255.255.255.255"
    UDP: sport=68, dport=67
    BOOTP: Client Hardware address (chaddr in scapy)
    DHCP: Message Type option (message-type in scapy)

DHCPREQUEST

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

In REBINDING state: Broadcast::

    Ehter: src=client_mac, dst="ff:ff:ff:ff:ff:ff"
    IP: src="0.0.0.0", dst="255.255.255.255"
    UDP: sport=68, dport=67
    BOOTP: Client Hardware address (chaddr in scapy)
    DHCP: Message Type option (message-type in scapy)
    Client IP address (ciaddr=client_ip)?


DHCPDECLINE (always broadcast?)::

    Ehter: src=client_mac, dst="ff:ff:ff:ff:ff:ff"
    IP: src="0.0.0.0", dst="255.255.255.255"
    UDP: sport=68, dport=67
    BOOTP: Client Hardware address (chaddr in scapy)
    DHCP: Message Type option (message-type in scapy)
    DHCP: Server Identifier option (server_id in scapy, siaddr in server BOOTP offer)
    DHCP: Requested IP option (requested_addr in scapy, yiaddr in server BOOTP offer)

DHCPRELEASE (always unicast)::

    Ehter: src=client_mac, dst=server_mac
    IP: src=client_ip, dst=server_ip
    UDP: sport=68, dport=67
    BOOTP: Client Hardware address (chaddr in scapy)
    DHCP: Message Type option (message-type in scapy)
    DHCP: Server Identifier option (server_id in scapy, siaddr in server BOOTP offer)

DHCPINFORM (always broadcast in AP)::

    Ehter: src=client_mac, dst="ff:ff:ff:ff:ff:ff"
    IP: src=client_ip, dst="255.255.255.255"
    UDP: sport=68, dport=67
    BOOTP: Client Hardware address (chaddr in scapy)
    BOOTP: Client IP address (ciaddr=client_ip)
    DHCP: Message Type option (message-type in scapy)

Operational considerations
---------------------------

Operational considerations
---------------------------

[:rfc:`7844#5.`] ::

   Implementers SHOULD provide a way for clients to control when the
   anonymity profiles are used and when standard behavior is preferred.

``dhcpcanon`` does not currently implement the standard behavior described in
 [:rfc:`2131`] in order to keep the implementation simple and
 because all existing implementations already implement it.

Leases
----------

For the sake of simplicity and privacy ``dhcpcanon`` does not currently
implement the INIT-REBOOT state nor reuse previously allocated addresses.

In future stages of ``dhcpcanon`` would be possible to reuse a previously
 allocated address.
In order to do not leak identifying information when doing so,
 it would be needed:

* to keep a database with previously allocated addresses associated to:

  * the link network where the address was obtained
    (without revealing the MAC being used).

  * the MAC address that was used in that network

It is possible also that ``dhcpcanon`` will include a MAC randomization module
 in the same distribution package or would require it in order to start.

Not mentioned in RFC7844, but RFC2131:
---------------------------------------------

Retransmission delays
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sending DHCPDISCOVER

* delay sending the first DHCPDISCOVER: float(random.randint(0, MAX_DELAY_SELECTING))?
* MAX_DELAY_SELECTING = 10
* maximum number of DHCPDISCOVER if no DHCPOFFER?

Receiving DHCPOFFER

* number of DHCPOFFERs to wait for?,
* timeout waiting for DHCPOFFERs?
* what's the algorithm to select the DHCPOFFER?

Timers
~~~~~~~

BOUND, setting renewing_time::

    renewing_time = lease_time * 0.5 - time_elapsed_after_request
    range_fuzz = lease_time * 0.875 - renewing_time
    renewing_time += random.uniform(-(range_fuzz), +(range_fuzz))

BOUND, setting rebinding_time::

    rebinding_time = lease_time * 0.875 - time_elapsed_after_request
    range_fuzz = lease_time - rebinding_time
    rebinding_time += random.uniform(-(range_fuzz), +(range_fuzz))

Client Identifier algorithm
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

See details in :ref:`RFC7844 comments, client identifier algorithm <rfc7844_comments:client-identifier-algorithm>`
