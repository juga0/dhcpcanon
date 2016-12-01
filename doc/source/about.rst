.. _about:

dhcpcanon - DHCP anonymity profile
==================================

DHCP client disclosing less identifying information.

Python implmentation of the DHCP Anonymity Profile
(`RFC7844 <https://tools.ietf.org/html/rfc7844>`__)
designed for users that wish to remain anonymous to the visited network
minimizing disclosure of identifying information.

Technologies
-------------

This implementation uses the Python `Scapy Automata <https://www.secdev.org/projects/scapy/doc/advanced_usage.html#automata>`__

What is the Anonymity Profile?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As the RFC7844 stats:

    Some DHCP options carry unique identifiers. These identifiers can
    enable device tracking even if the device administrator takes care of
    randomizing other potential identifications like link-layer addresses
    or IPv6 addresses. The anonymity profiles are designed for clients
    that wish to remain anonymous to the visited network. The profiles
    provide guidelines on the composition of DHCP or DHCPv6 messages,
    designed to minimize disclosure of identifying information.

What is DHCP?
~~~~~~~~~~~~~~

From `Wikipedia <https://en.wikipedia.org/wiki/DHCP>`__:
    The **Dynamic Host Configuration Protocol** (**DHCP**) is a standardized
    `network protocol <https://en.wikipedia.org/wiki/Network_protocol>`__
    used on `Internet
    Protocol <https://en.wikipedia.org/wiki/Internet_Protocol>`__ (IP)
    networks. The DHCP is controlled by a DHCP server that dynamically
    distributes network configuration parameters, such as `IP
    addresses <https://en.wikipedia.org/wiki/IP_address>`__, for interfaces
    and services. A
    `router <https://en.wikipedia.org/wiki/Router_%28computing%29>`__ or a
    `residential
    gateway <https://en.wikipedia.org/wiki/Residential_gateway>`__ can be
    enabled to act as a DHCP server. A DHCP server enables computers to
    request IP addresses and networking parameters automatically, reducing
    the need for a `network
    administrator <https://en.wikipedia.org/wiki/Network_administrator>`__
    or a user to configure these settings manually. In the absence of a DHCP
    server, each computer or other device (eg., a printer) on the network
    needs to be statically (ie., manually) assigned to an IP address.

DHCP Finite State Machine
""""""""""""""""""""""""""
State-transition diagram for DHCP clients:

.. image:: ./images/dhcpc_fsm.svg

Current status
--------------

WIP, still not recommended for end users.

See :ref:`todo`

Installation
------------

See :ref:`install`

Download
--------

You can download this project in either
`zip <http://github.com/juga0/dhcpcanon/zipball/master()>`__
or `tar <http://github.com/juga0/dhcpcanon/tarball/master>`__ formats.

You can also clone the project with Git by running:
    git clone git://github.com/juga0/dhcpcanon

Bugs and features
-----------------

If you wish to signal a bug or report a feature request, please fill-in
an issue on the `dhcpcanon issue tracker
<https://github.com/juga0/dhcpcanon/issues>`__.

License
-------

dhcpcanon is Copyright 2016 by juga ( juga at riseup dot net),
and is covered by the `GPLv3 <http://www.gnu.org/licenses/>`__ license.

Acknowledgments
---------------

To the persons that push me to implement yet another DHCP client
and to the person that told me about the anonymity profile.
