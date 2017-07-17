.. _specification:

RFC7844 DHCPv4 restricted version summary, questions and  ``dhcpcanon`` specification
======================================================================================

This document is a more restrictive version summary of [:rfc:`7844`],
where the keywords (``key words`` [:rfc:`2119`]) commented in
`RFC7844 comments <https://rfc7844-comments.readthedocs.io/en/latest/rfc7844comm.html#rfc7844comm>`_
are actually replaced. Use ``diff`` to see specific differences between these
two documents.

See :ref:`questions` for a summary of the questions stated here.

.. note::

    * Extracts from the [:rfc:`7844`] marked as
      `literal blocks <http://docutils.sourceforge.net/docs/ref/rst/restructuredtext.html#literal-blocks>`_.
    * Replacements are marked as
      `parsed literal <http://docutils.sourceforge.net/docs/ref/rst/directives.html#parsed-literal>`_
      with the keyword replaced in bold


Message types
-----------------

.. note::

    See :ref:`implementation` for a summary of the messages implementation

DHCP*
~~~~~~
[:rfc:`7844#section-3.1`]::

    SHOULD randomize the ordering of options

.. parsed-literal::

    If this can not be implemented
    **MUST** order the options by option code number (lowest to highest).


DHCPDISCOVER
~~~~~~~~~~~~~
[:rfc:`7844#section-3.`]::

    MUST contain the Message Type option,

.. parsed-literal::

    **MUST** NOT contain the Client Identifier option,

    **MUST** NOT contain the Parameter Request List option.

    **MUST** NOT contain any other option.


DHCPREQUEST
~~~~~~~~~~~~~
[:rfc:`7844#section-3.`]::

    MUST contain the Message Type option,

.. parsed-literal::

    **MUST** NOT contain the Client Identifier option,

    **MUST** NOT contain the Parameter Request List option.

    **MUST** NOT contain any other option.

::

    If in response to a DHCPOFFER,
    MUST contain the corresponding Server Identifier option
    MUST contain the Requested IP address option.

    If the message is not in response to a DHCPOFFER (BOUND, RENEW),:

.. parsed-literal::

    **MUST** NOT contain a Requested IP address option

DHCPDECLINE
~~~~~~~~~~~~~
[:rfc:`7844#section-3.`]::

    MUST contain the Message Type option,
    MUST contain the Server Identifier option,
    MUST contain the Requested IP address option;

.. parsed-literal::

    **MUST** NOT contain the Client Identifier option.

- is it always broadcast?

DHCPRELEASE
~~~~~~~~~~~~~
[:rfc:`7844#section-3.`]

To do not leak when the client leaves the network, this message type
**MUST** NOT be implemented.

In this case, servers might run out of leases, but that is something
that servers should fix decreasing the lease time.


DHCPINFORM
~~~~~~~~~~~~~
[:rfc:`7844#section-3.`]::

    MUST contain the Message Type option,

.. parsed-literal::

    **MUST** NOT contain the Client Identifier option,
    **MUST** NOT contain the Parameter Request List option.

    It **MUST** NOT contain any other option.


Message Options
-----------------

Client IP address (ciaddr)
~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#section-3.2`]::

    MUST NOT include in the message a Client IP address that has been obtained
    with a different link-layer address.

Requested IP Address Option (code 50)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#section-3.3`]

.. parsed-literal::

    **MUST** NOT use the Requested IP address option in DHCPDISCOVER messages.

::

    MUST use the option when mandated (DHCPREQUEST)

    If in INIT-REBOOT:

.. parsed-literal::

    **MUST** perform a complete four-way handshake, starting with a DHCPDISCOVER

- This is like not having INIT-REBOOT state?::

    If the client can ascertain that this is exactly the same network to which it was previously connected, and if the link-layer address did not change,
    MAY issue a DHCPREQUEST to try to reclaim the current address.

- This is like INIT-REBOOT state?
- Is there a way to know ``if`` the link-layer address changed without leaking the link-layer?


Client Hardware Address Field
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#section-3.4`]::

   If the hardware address is reset to a new randomized value,

.. parsed-literal::

   the DHCP client **MUST** use the new randomized value in the DHCP messages

The client should be restarted when the hardware address changes and
use the current address instead of the permanent one.

Client Identifier Option (code 61)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#section-3.5`]

.. parsed-literal::

    **MUST** NOT have this option

In the case that it would have this option because otherwise the server
does not answer to the requests,::

   DHCP
   clients MUST use client identifiers based solely on the link-layer
   address that will be used in the underlying connection.

Parameter Request List Option (PRL) (code 55)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#section-3.6`]

.. parsed-literal::

    **MUST** NOT have this option


Host Name option (code 12)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#section-3.7`]

.. parsed-literal::

    **MUST** NOT send the Host Name option.


Client FQDN Option (code 81)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#section-3.8`]

.. parsed-literal::

    **MUST** NOT include the Client FQDN option


UUID/GUID-Based Client Machine Identifier Option (code 97)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#section-3.9`]::

   Nodes visiting untrusted networks MUST NOT send or use the PXE options.

- And in the hypotetical case that nodes are visiting a "trusted" network,
  must this option be included for the PXE to work properly?


User and Vendor Class DHCP Options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#section-3.10`]

.. parsed-literal::

    **MUST** NOT use the

::

   Vendor-Specific Information option (code 43), the Vendor Class
   Identifier option (code 60), the V-I Vendor Class option (code 124),
   or the V-I Vendor-Specific Information option (code 125),

Operational considerations
---------------------------

[:rfc:`7844#section-5.`] ::

   Implementers SHOULD provide a way for clients to control when the
   anonymity profiles are used and when standard behavior is preferred.

``dhcpcanon`` does not currently implement the standard behavior described in
[:rfc:`2131`] in order to keep the implementation simple and
because all existing implementations already implement it


Not specified in RFC7844, but in RFC2131
-----------------------------------------

Probe the offered IP
~~~~~~~~~~~~~~~~~~~~~
[:rfc:`2131#section-2.2`]::

   the allocating
   server SHOULD probe the reused address before allocating the address,
   e.g., with an ICMP echo request, and the client SHOULD probe the
   newly received address, e.g., with ARP.

    The client SHOULD perform a
   check on the suggested address to ensure that the address is not
   already in use.  For example, if the client is on a network that
   supports ARP, the client may issue an ARP request for the suggested
   request.  When broadcasting an ARP request for the suggested address,
   the client must fill in its own hardware address as the sender's
   hardware address, and 0 as the sender's IP address, to avoid
   confusing ARP caches in other hosts on the same subnet.>>

   The client SHOULD broadcast an ARP
   reply to announce the client's new IP address and clear any outdated
   ARP cache entries in hosts on the client's subnet.

- does any implementation issue an ARP request to probe the offered address?
- is it issued after DHCPOFFER and before DHCPREQUEST,
  or after DHCPACK and before passing to BOUND state?

Currently, there is not any probe


Retransmission delays
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sending DHCPDISCOVER [:rfc:`2131#section-4.4.1`]::

    The client SHOULD wait a random time between one and ten seconds to
       desynchronize the use of DHCP at startup.

- is the DISCOVER retranmitted in the same way as the REQUEST?

[:rfc:`2131#section-3.1`]::

    a client retransmitting as described in section 4.1 might retransmit the
    DHCPREQUEST message four times, for a total delay of 60 seconds

[:rfc:`2131#section-4.4.5`]::

    In both RENEWING and REBINDING states,
    if the client receives no response to its DHCPREQUEST
    message, the client SHOULD wait one-half of the remaining
    time until T2 (in RENEWING state) and one-half of the
    remaining lease time (in REBINDING state), down to a
    minimum of 60 seconds, before retransmitting the
    DHCPREQUEST message.

[:rfc:`2131#section-4.1`]::

    For example, in a 10Mb/sec Ethernet
    internetwork, the delay before the first retransmission SHOULD be 4
    seconds randomized by the value of a uniform random number chosen
    from the range -1 to +1

    Clients with clocks that provide resolution
    granularity of less than one second may choose a non-integer
    randomization value.

    The delay before the next retransmission SHOULD
    be 8 seconds randomized by the value of a uniform number chosen from
    the range -1 to +1.

    The retransmission delay SHOULD be doubled with
    subsequent retransmissions up to a maximum of 64 seconds.

- the delay for the next retransmission is calculated with respect to the type
  of DHCP message or for the total of DHCP messages sent indendent of the type?
- without this algorithm being mandatory, **it'd be possible to fingerprint the
  the implementation depending on the delay of the retransmission**
- how does other implementations do?


Selecting offer algorithm
~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`2131#section-4.2`]::

    DHCP clients are free to use any strategy in selecting a DHCP server
    among those from which the client receives a DHCPOFFER message.

    client may choose to collect several DHCPOFFER
    messages and select the "best" offer.

    If the client receives no acceptable offers, the client
    may choose to try another DHCPDISCOVER message.

- what is a "no acceptable offer"?
- which are the "strategies" to select OFFER implemented?
- different algorithms to select an OFFER **could fingerprint the implementation**

[:rfc:`2131#section-4.4.1`]::

    The client collects DHCPOFFER messages over a period of time, selects
    one DHCPOFFER message from the (possibly many) incoming DHCPOFFER
    messages

    The time
    over which the client collects messages and the mechanism used to
    select one DHCPOFFER are implementation dependent.

- Is it different the retransmission delays waiting for offer or ack/nak?,
  in all states?

Currently, the first OFFER is chosen

Timers
~~~~~~~
[:rfc:`2131#section-4.4.5`]::

    Times T1 and T2 are configurable by the server through options.  T1
    defaults to (0.5 * duration_of_lease).  T2 defaults to (0.875 *
    duration_of_lease).  Times T1 and T2 SHOULD be chosen with some
    random "fuzz" around a fixed value, to avoid synchronization of
    client reacquisition.

T1 is then calculated as::

    renewing_time = lease_time * 0.5 - time_elapsed_after_request
    range_fuzz = lease_time * 0.875 - renewing_time
    renewing_time += random.uniform(-(range_fuzz), +(range_fuzz))

And T2::

    rebinding_time = lease_time * 0.875 - time_elapsed_after_request
    range_fuzz = lease_time - rebinding_time
    rebinding_time += random.uniform(-(range_fuzz), +(range_fuzz))

The range_fuzz is calculated in the same way that ``systemd`` implementation
does

- what's the fixed value for the fuzz and how is it calculated?
- The "fuzz" range is not specified, the fuzz chosen **could fingerprint** the
  implementation.


Leases
~~~~~~~

[:rfc:`7844#section-3.3`]::

    There are scenarios in which a client connecting to a network
    remembers a previously allocated address, i.e., when it is in the
    INIT-REBOOT state.  In that state, any client that is concerned with
    privacy SHOULD perform a complete four-way handshake, starting with a
    DHCPDISCOVER, to obtain a new address lease.  If the client can
    ascertain that this is exactly the same network to which it was
    previously connected, and if the link-layer address did not change,
    the client MAY issue a DHCPREQUEST to try to reclaim the current
    address.

- is there a way to know if the network the client is connected to is the same to which it was connected previously?

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
