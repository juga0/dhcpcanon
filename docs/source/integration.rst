.. _integration:

``dhcpcanon`` integration with network managers
================================================

Integration with Gnome ``Network Manager``
-------------------------------------------

`Gnome Network Manager <https://wiki.gnome.org/Projects/NetworkManager/>`_
has several components.

In Debian the service ``NetworkManager`` by default
calls `dhclient <https://www.isc.org/>`_
which in turn calls ``nm-dhcp-helper``.
Depending on the configuration, dhclient is called with the parameters::

    /sbin/dhclient -d -q
    -sf /usr/lib/NetworkManager/nm-dhcp-helper
    -pf /var/run/dhclient-<interface>.pid
    -lf /var/lib/NetworkManager/dhclient-<?>-<interface>.lease
    -cf /var/lib/NetworkManager/dhclient-<interface>.conf
    <interface>

Dclient calls ``nm-dhcp-helper`` via the ``-sf`` parameter,
which seems to communicate back with ``NetworkManager`` via D-Bus.

``NetworkManager`` can be configured to use `dhcpcd <https://roy.marples.name/git/dhcpcd.git>`_
or ``internal``, as DHCP clients instead of ``dhclient``.

.. parsed-literal::

    FIXME: Configuring ``NetworkManager`` to use ``internal`` did not work
    (why?). Is it using systemd DHCP client code? (``libsystemd-network <https://github.com/NetworkManager/NetworkManager/tree/master/src/systemd/src/libsystemd-network`>`_
    is included in ``NetworkManager`` source code, which is in ``systemd``
    `code <https://github.com/systemd/systemd/tree/master/src/libsystemd-network>`_).

    It does not work either with ``dhcpcd``:
    NetworkManager[12712]: <warn>  [1493146345.7994] dhcp-init: DHCP client 'dhcpcd' not available


Environment variables that ``dhclient`` returns
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When ``dhclient`` call the script, by default ``/sbin/dhclient-script``,
or when called by ``NetworkManager``, ``nm-dhcp-helper``, it pass environment
variables.

.. parsed-literal::

   FIXME: Are these variables documented somewhere?.

In ``man  dhclient-script`` there is the list of values that the variable ``reason`` can take::

    The following reasons
       are currently defined: MEDIUM, PREINIT, BOUND, RENEW, REBIND,  REBOOT,
       EXPIRE, FAIL, STOP, RELEASE, NBI and TIMEOUT.

But there are more variables.
By setting ``RUN=yes`` in ``/etc/dhcp/debug``, these variables are found
in ``/tmp/dhclient-script.debug``::

    reason='PREINIT'
    interface=
    --------------------------
    reason='REBOOT'
    interface=
    new_ip_address=
    new_network_number=
    new_subnet_mask=
    new_broadcast_address=
    new_routers=
    new_domain_name=
    new_domain_name_servers=

Looking at the code `dhclient v4.3.5 <https://source.isc.org/cgi-bin/gitweb.cgi?p=dhcp.git;a=blob;f=client/dhclient.c;h=f7486c6a754f741fecb2a2999d78778ab79a5970;hb=846d0ecce7480257723c86c59f653687217181bc>`_
there seem to be more variables.

Environment variables that ``nm-dhcp-helper`` gets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

TBD

??

``dhcpcanon`` required modifications
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If ``dhcpcanon`` accepts the same arguments as ``dhclient`` and calls
the script ``nm-dhcp-helper`` with the same environment
variables as ``dhclient``, it should be integrated.

.. parsed-literal::

    FIXME: however for some reason this generates D-Bus errors.

``dhcpcanon`` could also implement the D-Bus input/output that
``NetworkManager`` needs.

There's a `NetworkManager D-Bus API <https://developer.gnome.org/NetworkManager/unstable/spec.html>`_
specification.

There's also a Python API, `python-networkmanager <https://pythonhosted.org/python-networkmanager/>`_,
so ``dhcpcanon`` could communicate directly with ``NetworkManager`` instead
communicating with  ``nm-dhcp-helper``.


nm notes
---------

Debugging:

    [logging]
    level=DEBUG


It is not possible to set ``dhcp-send-hostname``
(`Bug 768076 - No way to set dhcp-send-hostname globally  <https://bugzilla.gnome.org/show_bug.cgi?id=768076#c5>`_)
globally.

To modify ``dhcp-send-hostname`` per interface:

    nmcli connection modify "Wired connection" ipv4.dhcp-send-hostname no
    nmcli connection show "Wired connection"

Or the files:
    /etc/NetworkManager/system-connections/Wired\ connection

There is currently no way that when a new device is create it defaults to a configuration.


Integration with ``wicd``
---------------------------

TBD

`wicd <https://wicd.sourceforge.net/>`_

`wicd documentation <https://bazaar.launchpad.net/~wicd-devel/wicd/experimental/view/head:/README>`_
