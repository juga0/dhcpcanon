.. _running:

Running dhcpcanon
==================

If ``dhcpcanon`` is installed in the system (with the Debian package,
sudo pip install dhcpcanon or sudo python setup.py), run it just invoking::

    dhcpcanon

If it's not installed, but a virtualenv has been created,
it can still be run in a virtualenv with:

    source ~/.virtualenv/dhcpcanon/bin/activate
    pip install -e .
    sudo scripts/dhcpcanon

There is no need to pass any argument, most of the arguments are only used when
``dhcpcanon`` is called by other program (``systemd`` or
``gnome network manager``) and mimic the ``dhclient`` arguments.

An useful argument when reporting bugs is ``-v``.

In that case it will use the active interface.
If there're several active interfaces the behaviour right now
is not predictable.

An updated command line usage description can be always obtained with::
    scripts/dhcpcanon -h

At the time of writing this the usage documentation is::

    usage: dhcpcanon [-h] [-v] [-l LEASE] [--version] [-sf [script-file]]
                     [-pf [pid-file]] [-lf [lease-file]] [-cf [config-file]] [-d]
                     [-q] [-N] [-6] [-4]
                     [interface]

    positional arguments:
      interface             interface to configure with DHCP

    optional arguments:
      -h, --help            show this help message and exit
      -v, --verbose         Set logging level to debug
      -l LEASE, --lease LEASE
                            custom lease time
      --version             version
      -sf [script-file]     Path to the network configuration script invoked by
                            dhclient when it gets a lease. If unspecified, the
                            default /sbin/dhclient-script is used. See dhclient-
                            script(8) for a description of this file.
      -pf [pid-file]        Path to the process ID file. If unspecified,
                            thedefault /var/run/dhclient.pid is used
      -lf [lease-file]      Path to the lease database file. If unspecified,
                            thedefault /var/lib/dhcp/dhclient.leases is used. See
                            dhclient.leases(5) for a description of this file.
      -cf [config-file]     Path to the client configuration file. If
                            unspecified,the default /etc/dhcp/dhclient.conf is
                            used. See dhclient.conf(5) for a description of this
                            file.
      -d                    Force dhclient to run as a foreground process.
                            Normally the DHCP client will run in the foreground
                            until is has configured an interface at which time it
                            will revert to running in the background. This option
                            is useful when running the client under a debugger, or
                            when running it out of inittab on System V systems.
                            This implies -v.
      -q                    Be quiet at startup, this is the default.
      -N
      -6
      -4
