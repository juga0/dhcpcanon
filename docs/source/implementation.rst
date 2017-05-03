.. _implementation:

Comments about dhcpcanon implementation and the RFCs
==========================================================

Please, see `RFC7844_comments https://rfc7844-comments.readthedocs.io`_ for comments about [:rfc:`7844`].

``dhcpcanon`` in general implements what MUST and SHOULD and does not
what SHOULD NOT or MAY, unless found cases where a MAY options
must be implemented in order servers reply.

[TBC]

Packet formant
-----------------

DHCPDISCOVER

    Message Type option
    BOOTP: Client Hardware address (chaddr)

DHCPREQUEST

In SELECTING state: Unicast to server id

    Message Type option
    Server Identifier option
    Requested IP option (yiaddr)
    Client IP address (ciaddr) as 0?

In RENEWING state: Unicast to server id

    Message Type option
    Client IP address (ciaddr)

In REBINDING state: Broadcast

    Message Type option
    Client IP address (ciaddr)


DHCPDECLINE
    Message Type option
    Server Identifier option
    Requested IP option

DHCPRELEASE

To don't implment

DHCPINFORM
    Message Type option

Operational considerations
---------------------------

``dhcpcanon`` will not implement for now the standard behavior as
it would require to implement more functionality and most of the current
tools implement already the standard.

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

[TBD]
