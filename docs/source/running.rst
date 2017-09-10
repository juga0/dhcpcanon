.. _running:

Running dhcpcanon
==================

If ``dhcpcanon`` has be installed with systemd, it can be started with::

    sudo systemctl start dhcpcanon

After installing, it can also be run manually::

    sudo dhcpcanon

There is no need to pass any argument, most of the arguments are only used when
``dhcpcanon`` is called by other program (``systemd`` or
``gnome network manager``) and mimic the ``dhclient`` arguments.

You can specify which network interface to use passing it as an argument.
Without specificying the network interface, it will use the active interface.

An useful argument when reporting bugs is ``-v``.

An updated command line usage description can be obtained with::

    dhcpcanon -h
