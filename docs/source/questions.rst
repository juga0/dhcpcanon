.. _questions:

Summary of questions regarding the RFCs and the implementations
===============================================================

This is a summary of the questions stated in `RFC7844 DHCPv4 restricted version summary <https://dhcpcanon.readthedocs.io/en/latest/specification.html>`_

Message Options
-----------------

Requested IP Address Option (code 50)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#section-3.3`]

- Is there a way to know ``if`` the link-layer address changed without leaking the link-layer?


Not specified in RFC7844, but in RFC2131
-----------------------------------------

Probe the offered IP
~~~~~~~~~~~~~~~~~~~~~
[:rfc:`2131#section-2.2`]

- does any implementation issue an ARP request to probe the offered address?
- is it issued after DHCPOFFER and before DHCPREQUEST,
  or after DHCPACK and before passing to BOUND state?

Retransmission delays
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sending DHCPDISCOVER [:rfc:`2131#section-4.4.1`]

- is the DISCOVER retranmitted in the same way as the REQUEST

[:rfc:`2131#section-3.1`], [:rfc:`2131#section-4.4.5`], [:rfc:`2131#section-4.1`]

- the delay for the next retransmission is calculated with respect to the type
  of DHCP message or for the total of DHCP messages sent indendent of the type?
- without this algorithm being mandatory, **it'd be possible to fingerprint the
  the implementation depending on the delay of the retransmission**
- how does other implementations do?

Selecting offer algorithm
~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`2131#section-4.2`]

- what is a "no acceptable offer"?
- which are the "strategies" to select OFFER implemented?
- how many offers to wait for?
- different algorithms to select an OFFER **could fingerprint the implementation**

[:rfc:`2131#section-4.4.1`]

- Is it different the retransmission delays waiting for offer or ack/nak?,
  in all states?

Timers
~~~~~~~
[:rfc:`2131#section-4.4.5`]

- what's the fixed value for the fuzz and how is it calculated?
- The "fuzz" range is not specified, the fuzz chosen **could fingerprint** the
  implementation.


Leases
~~~~~~~

[:rfc:`7844#section-3.3`]

- is there a way to know if the network the client is connected to is the same to which it was connected previously?

Not specified in any RFC
-------------------------

- is it needed to check that the ACK options match with the OFFER ones?
- is it needed to check that all options make sense?, which ones?
