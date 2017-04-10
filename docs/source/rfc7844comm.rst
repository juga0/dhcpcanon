.. _rfc7844comm:


RFC7844 summary and comments
==============================

Notes: 

- Extracts from the RFC marked as `source code <http://docutils.sourceforge.net/docs/ref/rst/restructuredtext.html#literal-blocks>`_. 
- Unless otherwise explicited, this document refers to DHCP clients implementing Anonymity Profiles.

RFCs to the Comments to the RFC :)

Unfortunately, the deadline for the comments officially expired around Feb 2016 [cit needed].

An approved RFC can not be changed [cit need], 
**if** any of the following comments are "correct" [other more "correct" word than "correct" needed here], a new RFC should be proposed.

Most of the comments are regarding the verbs (``key words`` [:rfc:`2119`]) used, the author here does not have previous experience on proposing/commenting RFCs, so they might not be "correct".

Basically, in order to reveal less identifying information, the options in DHCP should be reduced in number and be more "homogenous" for all implementations what here is interpreted as in either this option MUST be included or MUST NOT, instead of MAY, SHOULD, etc. 
What is a similar way to express what is stated in :rfc:`7844#2.4`. ::

   The design of the anonymity profiles attempts to minimize the number
   of options and the choice of values, in order to reduce the
   possibilities of operating system fingerprinting.

Mesagge types
-----------------

DHCP* 
~~~~~~
[:rfc:`7844#3.1`] ::

    SHOULD randomize the ordering of options

Why not s/SHOULD/MUST?
::

    If this can not be implemented
    MAY order the options by option code number (lowest to highest).

Why not s/MAY/MUST?


DHCPDISCOVER
~~~~~~~~~~~~~
[:rfc:`7844#3.`] ::

    MUST contain the Message Type option,

::

    MAY contain the Client Identifier option,
    MAY contain the Parameter Request List option.

Why not s/MAY/MUST NOT?,

because servers will requests that do not contain those options? (found at least 1 case of server ignoring request without the Client Identifier option),

what RFC for DHCP server says about it?::

    SHOULD NOT contain any other option.

Why not s/SHOULD NOT/MUST NOT?

DHCPREQUEST
~~~~~~~~~~~~~
[:rfc:`7844#3.`] ::

    MUST contain the Message Type option,

::

    MAY contain the Client Identifier option,
    MAY contain the Parameter Request List option.
    SHOULD NOT contain any other option.

MAY, SHOULD NOT as in DHCPDISCOVER_::

    If in response to a DHCPOFFER,::
    MUST contain the corresponding Server Identifier option
    MUST contain the Requested IP address option.

::

    If the message is not in response to a DHCPOFFER (BOUND, RENEW),::
    MAY contain a Requested IP address option

Why not s/MAY/MUST?

DHCPDECLINE
~~~~~~~~~~~~~
[:rfc:`7844#3.`] ::

    MUST contain the Message Type option,
    MUST contain the Server Identifier option,
    MUST contain the Requested IP address option;

::

    MAY contain the Client Identifier option.

MAY as in DHCPDISCOVER_

Why here there is not SHOULD NOT as in DHCPDISCOVER_


DHCPRELEASE
~~~~~~~~~~~~~
[:rfc:`7844#3.`] ::

    MUST contain the Message Type option and
    MUST contain the Server Identifier option,

::

    MAY contain the Client Identifier option.

MAY as in DHCPDISCOVER_

To do not leak when the client leaves the network, this message type
should not be implemented.
In this case, servers might run out of leases, but that is something
that servers should fix decreasing the lease time.
Or all clients requesting a minor lease time?.

DHCPINFORM
~~~~~~~~~~~~~
[:rfc:`7844#3.`] ::

    MUST contain the Message Type option,

::

    MAY contain the Client Identifier option,
    MAY contain the Parameter Request List option.

::

    It SHOULD NOT contain any other option.


MAY, SHOULD NOT as in DHCPDISCOVER_

Message Options
-----------------

Client IP address (ciaddr)
~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#3.2`] ::

    MUST NOT include in the message a Client IP address that has been obtained with a different link-layer address.

Requested IP Address Option (code 50)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#3.3`] ::

   SHOULD NOT use the Requested IP address option in DHCPDISCOVER messages.
   MUST use the option when mandated (DHCPREQUEST)

::

    If in INIT-REBOOT:
    SHOULD perform a complete four-way handshake, starting with a DHCPDISCOVER

This is like not having INIT-REBOOT state?

::

    If the client can ascertain that this is exactly the same network to which it was previously connected, and if the link-layer address did not change,
    MAY issue a DHCPREQUEST to try to reclaim the current address.

This is like INIT-REBOOT state?

There is not a way to know ``if`` the link-layer address changed without leaking the link-layer?


Client Identifier Option (code 61)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[ :rfc:`7844#3.5` ] ::

   In contradiction to [RFC4361], when using the anonymity profile, DHCP
   clients MUST use client identifiers based solely on the link-layer
   address that will be used in the underlying connection.  This will
   ensure that the DHCP client identifier does not leak any information
   that is not already available to entities monitoring the network
   connection.  It will also ensure that a strategy of randomizing the
   link-layer address will not be nullified by the Client Identifier
   option.

As in DHCPDISCOVER_, it SHOULD NOT have this option

If it has it: what about having a common algorithm for all clients that is not based on "identifying" properties?::

   The algorithm for combining secrets and identifiers, as
   described in Section 5 of [RFC7217], solves a similar problem.  The
   criteria for the generation of random numbers are stated
   in [RFC4086].

Could be this the non "identifying" algorithm?

Parameter Request List Option (PRL) (code 55)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#3.6`] ::

   SHOULD only request a minimal number of options in the PRL and 
   SHOULD also randomly shuffle the ordering of option codes in the PRL.
   If this random ordering cannot be implemented, 
   MAY order the option codes in the PRL by option code number (lowest to highest).

As in DHCPDISCOVER_

Host Name option (code 12)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

[:rfc:`7844#3.7`] ::

   SHOULD NOT send the Host Name option.  
   If they choose to send the option [..]

As in DHCPDISCOVER_

Client FQDN Option (code 81)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#3.8`:] ::

    SHOULD NOT include the Client FQDN option

As in DHCPDISCOVER_
::

   MAY include a special-purpose FQDN using the same host name as in the
   Host Name option, with a suffix matching the connection-specific DNS
   suffix being advertised by that DHCP server.  
   

In this case there is an explicit reason why it MAY::
   
   Having a name in the
   DNS allows working with legacy systems that require one to be there

UUID/GUID-Based Client Machine Identifier Option (code 97)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#3.9`] ::

   This option is part of a set of options for the
   Intel Preboot eXecution Environment (PXE)

::

   Common sense seems to
   dictate that getting a new operating system from an unauthenticated
   server at an untrusted location is a really bad idea and that even if
   the option was available users would not activate it.

::

   Nodes visiting untrusted networks MUST NOT send or use the PXE options.

And in the hypotetical case that nodes are visiting a "trusted" network, 
must this option be included for the PXE to work properly?

Regarding english expression, should s/or/nor?,
and how to define "common sense"? :)

User and Vendor Class DHCP Options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[:rfc:`7844#3.10`] ::

   SHOULD NOT use the
   Vendor-Specific Information option (code 43), the Vendor Class
   Identifier option (code 60), the V-I Vendor Class option (code 124),
   or the V-I Vendor-Specific Information option (code 125),

Why not s/SHOULD NOT/MUST NOT?
