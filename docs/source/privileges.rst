.. _privileges:

Minimising ``dhcpcanon`` privileges
====================================

Reasons why a DHCP client needs to run with root privileges:

* open sockets in privilege ports (68)
* open RAW sockets: to receive packets without having an IP set yet
* to set the IP offered

  .. note::

     ``dhcpcanon`` does not need privileges to set up the IP, as that is done
     by a separated script, as ``dhclient`` does.

Possible solutions to minimise privileges and their associated problems:

1. drop privileges after BOUND DHCP state (sockets binded):
 * problem: if the client stays connected until the renewing/rebinding time,
   privileges would be needed again and dropping privileges `temporally` it is
   not recommended [].
 * possible solutions: do not implement RENEWING/REBINDING states.

   * problem: this would not be compliant with RFC 2131 nor 7844.
   * pro: in "usual" networks, if the client stays enough time
     conected o the network, the lease would expire it could just restart in the
     INIT state.

     .. todo::

        which would be the associated problems to this solution?

2. wrapper with privileges to set linux network capabilities to the client,
   open sockets, then call the client inheriting the sockets:
  * problem: same as 1.

  .. note::

     it's not possible to set net capabilities directly to a python script,
     they would need to be set to the python binary, but that would give the
     capabilities to any python script.
     Python binary could also be copied, set the capabilies, and that script call
     the client, but would have the same problem as giving the capabilities to
     the original python binary

3. ``dhcpcanon`` could call a binary with privileges to create the sockets
   every time it needs to do so.
   It's needed to change several parts of the current implementation.

4. to have the process be granted just the capabilities it needs,
   by the system-level process manager.

   This is already implemented with ``systemd``

5. wrapper that does the same as in 4. without a system-level process
   manager. See section "wrapper to inherit capabilities"

6. wrapper with privileges to disable linux Remote Path (RP) filter,
   open sockets, then call the client:
  * problems:

    * it still needs root to change the default RP settings
    * it would only allow that the DHCP offers are received from other interfaces
      [], but still RAW sockets are needed to receive packets in the
      same interface that does not have an IP address yet
    * same as 1.

Wrapper to inherit capabilities
--------------------------------

With ``capsh``, ``dhcpcanon`` could be launched as another user and
inherit only the required capabilities, in a similar way as
``systemd.service`` does::

    capsh --caps=cap_net_raw,cap_net_bind_service,cap_net_admin+epi --keep=1 -- -c "mkdir -p /run/dhcpcanon && cd /run/dhcpcanon && su -c 'exec /sbin/dhcpcanon enp0s25' -s /bin/sh dhcpcanon"

``-s`` is needed cause dhcpcanon shell is ``/bin/false``

However this does not have capabilities to create the socket.

To show the capabilities that are actually inherited::

    capsh --keep=1 --secbits=0x1C --caps=cap_net_raw,cap_net_bind_service,cap_net_admin+epi  -- -c "mkdir -p /run/dhcpcanon && cd /run/dhcpcanon && su -c '/sbin/capsh --print' -s /bin/sh dhcpcanon"

In ``man capsh`` ``--securebits`` is not documented, ``securebits.h``
has some documentation, but it seems to be needed a newer version of
``libcap`` as commented in this `post <https://unix.stackexchange.com/questions/196483/how-do-i-use-capsh-i-am-trying-to-run-an-unprivileged-ping-with-minimal-capabi>`_
