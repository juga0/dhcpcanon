.. _rfc7844comm:

RFC7844 summary
=================

Mesagge types
-----------------

https://github.com/juga0/privacy/blob/7844/rfc7844.txt#L542

DHCP*
~~~~~~~~
    SHOULD randomize the ordering of options
If this can not be implemented
    MAY order the options by option code number (lowest to highest).

https://github.com/juga0/privacy/blob/7844/rfc7844.txt#L482

DHCPDISCOVER
~~~~~~~~~~~~~

    MUST contain the Message Type option,
    MAY contain the Client Identifier option,
    MAY contain the Parameter Request List option.
    SHOULD NOT contain any other option.

DHCPREQUEST
~~~~~~~~~~~~~

    MUST contain the Message Type option,
    MAY contain the Client Identifier option,
    MAY contain the Parameter Request List option.
    SHOULD NOT contain any other option.

If in response to a DHCPOFFER,
    MUST contain the corresponding Server Identifier option
    MUST contain the Requested IP address option.

If the message is not in response to a DHCPOFFER (BOUND, RENEW),
    MAY contain a Requested IP address option

DHCPDECLINE
~~~~~~~~~~~~~

    MUST contain the Message Type option,
    MUST contain the Server Identifier option,
    MUST contain the Requested IP address option;
    MAY contain the Client Identifier option.

DHCPRELEASE
~~~~~~~~~~~~~

    MUST contain the Message Type option and
    MUST contain the Server Identifier option,
    MAY contain the Client Identifier option.

DHCPINFORM
~~~~~~~~~~~~~

    MUST contain the Message Type option,
    MAY contain the Client Identifier option,
    MAY contain the Parameter Request List option.
    It SHOULD NOT contain any other option.

Message Options
-----------------

#L551

Client IP address (ciaddr)
~~~~~~~~~~~~~~~~~~~~~~~~~~

    MUST NOT include in the message a Client IP address that has been obtained with a different link-layer address.


Requested IP Address Option (code 50)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

   SHOULD NOT use the Requested IP address option in DHCPDISCOVER messages.
   MUST use the option when mandated (DHCPREQUEST)

If in INIT-REBOOT
   SHOULD perform a complete four-way handshake, starting with a DHCPDISCOVER

If the client can ascertain that this is exactly the same network to which it was previously connected, and if the link-layer address did not change,
   MAY issue a DHCPREQUEST to try to reclaim the current address.

Client Identifier Option
~~~~~~~~~~~~~~~~~~~~~~~~~
