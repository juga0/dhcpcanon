.. _specification:

``dhcpcanon`` specification
=============================

This document details what and how is implemented in ``dhcpcanon``,
as stated in :ref:`implementation`, but as an RFC, what would be a more
restricted version of [:rfc:`7844`],
as commented in :ref:`RFC7844 comments <rfc7844comm>`


Mesagge types
-----------------

DHCP*
~~~~~~
::

    SHOULD randomize the ordering of options

If this can not be implemented MUST order the options by option code
number (lowest to highest).

DHCPDISCOVER
~~~~~~~~~~~~~
::

    MUST contain the Message Type option,

MUST NOT contain the Client Identifier option,

MUST NOT contain the Parameter Request List option.

MUST NOT contain any other option.


DHCPREQUEST
~~~~~~~~~~~~~
::

    MUST contain the Message Type option,


MUST NOT contain the Client Identifier option,

MUST NOT contain the Parameter Request List option.

MUST NOT contain any other option.::

    If in response to a DHCPOFFER,
    MUST contain the corresponding Server Identifier option
    MUST contain the Requested IP address option.

    If the message is not in response to a DHCPOFFER (BOUND, RENEW),:

MUST NOT contain a Requested IP address option

DHCPDECLINE
~~~~~~~~~~~~~
::

    MUST contain the Message Type option,
    MUST contain the Server Identifier option,
    MUST contain the Requested IP address option;

MUST NOT contain the Client Identifier option.


DHCPRELEASE
~~~~~~~~~~~~~

To do not leak when the client leaves the network, this message type
MUST NOT be implemented.

In this case, servers might run out of leases, but that is something
that servers should fix decreasing the lease time.


DHCPINFORM
~~~~~~~~~~~~~
::

    MUST contain the Message Type option,

MUST NOT contain the Client Identifier option,
MUST NOT contain the Parameter Request List option.

It MUST NOT contain any other option.


Message Options
-----------------

Client IP address (ciaddr)
~~~~~~~~~~~~~~~~~~~~~~~~~~
::

    MUST NOT include in the message a Client IP address that has been obtained
    with a different link-layer address.

Requested IP Address Option (code 50)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

MUST NOT use the Requested IP address option in DHCPDISCOVER messages.::

   MUST use the option when mandated (DHCPREQUEST)

    If in INIT-REBOOT:

MUST perform a complete four-way handshake, starting with a DHCPDISCOVER

This is like not having INIT-REBOOT state?::

    If the client can ascertain that this is exactly the same network to which it was previously connected, and if the link-layer address did not change,
    MAY issue a DHCPREQUEST to try to reclaim the current address.

This is like INIT-REBOOT state?

There is not a way to know ``if`` the link-layer address changed without leaking the link-layer?


Client Hardware Address Field
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
::

   If the hardware address is reset to a new randomized value,

the DHCP client MUST use the new randomized value in the DHCP messages

The client should be restarted when the hardware address changes and
use the current address instead of the permanent one.

Client Identifier Option (code 61)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

MUST NOT have this option


Parameter Request List Option (PRL) (code 55)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

MUST NOT have this option


Host Name option (code 12)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

MUST NOT send the Host Name option.


Client FQDN Option (code 81)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

MUST NOT include the Client FQDN option


UUID/GUID-Based Client Machine Identifier Option (code 97)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#3.9`]::

   Nodes visiting untrusted networks MUST NOT send or use the PXE options.

And in the hypotetical case that nodes are visiting a "trusted" network,
must this option be included for the PXE to work properly?


User and Vendor Class DHCP Options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#3.10`]

MUST NOT use the::

   Vendor-Specific Information option (code 43), the Vendor Class
   Identifier option (code 60), the V-I Vendor Class option (code 124),
   or the V-I Vendor-Specific Information option (code 125),


Operational considerations
---------------------------

Currently, the standard behaviour is not implemented.

Not detailed in RFC7844
---------------------------------------

Probe the offered IP
~~~~~~~~~~~~~~~~~~~~~

Currently, there is not any probe

Retransmission delays
~~~~~~~~~~~~~~~~~~~~~~~~~~~

DHCPDISCOVER is retransmitted 4 times for a total of 60 seconds

DHCPREQUEST is retransmitted 4 times for a total of 60 seconds

DHCPREQUEST in renewing and rebinding states is retransmitted according
to timers section

Selecting offer algorithm
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Currently, the first OFFER is chosen

Timers
~~~~~~~
[:rfc:`2131#4.4.5`]::

    T1
    defaults to (0.5 * duration_of_lease).  T2 defaults to (0.875 *
    duration_of_lease).  Times T1 and T2 SHOULD be chosen with some
    random "fuzz" around a fixed value, to avoid synchronization of
    client reacquisition.

Leases
~~~~~~~

Currently, there is not any lease reused.

Summary of questions
======================

Message Options
-----------------

Requested IP Address Option (code 50)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#3.3`]::

    If in INIT-REBOOT:
    SHOULD perform a complete four-way handshake, starting with a DHCPDISCOVER

- This is like not having INIT-REBOOT state?

..

    If the client can ascertain that this is exactly the same network to which it was previously connected, and if the link-layer address did not change,
    MAY issue a DHCPREQUEST to try to reclaim the current address.

- This is like INIT-REBOOT state?

- Is there a way to know ``if`` the link-layer address changed without leaking the link-layer?

Not detailed in RFC7844
--------------------------

Probe the offered IP
~~~~~~~~~~~~~~~~~~~~~
[:rfc:`2131#2.2`]::

   the allocating
   server SHOULD probe the reused address before allocating the address,
   e.g., with an ICMP echo request, and the client SHOULD probe the
   newly received address, e.g., with ARP.

   The client SHOULD broadcast an ARP
   reply to announce the client's new IP address and clear any outdated
   ARP cache entries in hosts on the client's subnet.

- does any implementation issue an ARP request to probe the offered address?
- is it issued after DHCPOFFER and before DHCPREQUEST, or after DHCPACK and before passing to BOUND state?

Retransmission delays
~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`2131#3.1`]::

    might retransmit the
    DHCPREQUEST message four times, for a total delay of 60 seconds

- MUST retransmit the DHCPREQUEST message four times, for a total delay of 60 seconds?

[:rfc:`2131#4.1`]::

    The delay before the next retransmission SHOULD
    be 8 seconds randomized by the value of a uniform number chosen from
    the range -1 to +1.

- the delay before the next retransmission MUST be 8 seconds randomized
  with [-1, +1]?::

    The retransmission delay SHOULD be doubled with
    subsequent retransmissions up to a maximum of 64 seconds.

- are these retransmission calculated for any type of packet or for the all the packet sent?
- how does other implementations do?

[:rfc:`2131#4..4.5`]::

    In both RENEWING and REBINDING states,
    if the client receives no response to its DHCPREQUEST
    message, the client SHOULD wait one-half of the remaining
    time until T2 (in RENEWING state) and one-half of the
    remaining lease time (in REBINDING state), down to a
    minimum of 60 seconds, before retransmitting the
    DHCPREQUEST message.

Selecting offer algorithm
~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`2131#4.2`]::

    DHCP clients are free to use any strategy in selecting a DHCP server
    among those from which the client receives a DHCPOFFER message.

    client may choose to collect several DHCPOFFER
    messages and select the "best" offer.

    If the client receives no acceptable offers, the client
    may choose to try another DHCPDISCOVER message.

- what is a no acceptable offer?
- which are the strategies to select OFFER implemented?

[:rfc:`2131#4.4.1`]::

    The client collects DHCPOFFER messages over a period of time, selects
    one DHCPOFFER message from the (possibly many) incoming DHCPOFFER
    messages

    The time
    over which the client collects messages and the mechanism used to
    select one DHCPOFFER are implementation dependent.

- Is it different the timeout waiting for offer or ack/nak?, in all states?

Timers
~~~~~~~
[:rfc:`2131#4.4.5`]::

    T1
    defaults to (0.5 * duration_of_lease).  T2 defaults to (0.875 *
    duration_of_lease).  Times T1 and T2 SHOULD be chosen with some
    random "fuzz" around a fixed value, to avoid synchronization of
    client reacquisition.

- what's the fixed value for the fuzz and how is it calculated?

Leases
~~~~~~~~

[:rfc:`7844#3.3`]::

    There are scenarios in which a client connecting to a network
    remembers a previously allocated address, i.e., when it is in the
    INIT-REBOOT state.  In that state, any client that is concerned with
    privacy SHOULD perform a complete four-way handshake, starting with a
    DHCPDISCOVER, to obtain a new address lease.  If the client can
    ascertain that this is exactly the same network to which it was
    previously connected, and if the link-layer address did not change,
    the client MAY issue a DHCPREQUEST to try to reclaim the current
    address.

See requesting IP address option
