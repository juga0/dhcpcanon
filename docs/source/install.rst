.. _install:

Install dhcpcanon
=================

The recommended way to install ``dhcpcanon`` is with your package source
distribution, as it will also install other system files.

Currently is availabe for Debian unstable/testing.
It can be installed with a package manager or in command line::

    sudo apt install dhcpcanon

The main script will be installed in ``/sbin/dhcpcanon``, a systemd service
will be enabled and run by default, so there is no need to run anything manually.

**Important**: when running ``dhcpcanon`` the hardware address
(`MAC <https://en.wikipedia.org/wiki/MAC_address>`__) should be randomized.
You can use `macchanger <https://github.com/alobbs/macchanger>`__,
`macouflage <https://github.com/subgraph/macouflage>`__ or other.

Installation from source code
==============================

In case you would like to have a newer version or it is not packaged for your
distribution, you can install it from the source code.

Install system dependencies, in Debian/Ubuntu::

    sudo apt install python-dev

Obtain the source code::

    git clone https://github.com/juga0/dhcpcanon/

Install ``dhcpcanon`` and system files::

    sudo make install WITH_SYSTEMD=true

In Debian this will install all the required files under ``/usr/local``.
``WITH_SYSTEMD`` will install a systemd service and enable it, to run it::

    systemctl start dhcpcanon

for advanced users
--------------------

In the case that you would like to install without root privileges,
you can install it without the systemd service and you can specify
an alternative location, for instance::

    make --prefix=/home/user/.local install

Note however that without systemd ``dhcpcanon`` will need to be run with root
privileges, while the systemd service drop ``dhcpcanon`` root privileges and
only keeps the required network capabilities.

You would also need to install 
`resolvconf-admin <https://github.com/dkg/resolvoconf-admin'`_
to be able to run it as non root user and set up DNS servers provided by the DHCP server.
It will be possible to set up DNS servers with ``systemd`` too soon.

An alternative to do not run ``dhcpcanon`` with root privileges nor systemd,
is to use `ambient-rs wrapper <https://github.com/infinity0/ambient-rs>`
and run::

    RUST_BACKTRACE=1 ./target/debug/ambient -c NET_RAW,NET_ADMIN,NET_BIND_SERVICE /usr/bin/python3 -m dhcpcanon.dhcpcanon -v

Installation with pip
==========================

The pip package does not install either system files and it can be installed
without root, but it still needs to be run as root, as commented in the last
section.::

    pip install dhcpcanon

In Debian this will install the files in ``/home/youruser/.local``
Note also that if you install it in a virtualenv, when executing ``dhcpcanon``
with ``sudo``, won't use the virtualenv. To keep the virtualenv run it with::

    sudo /pathtovirtualenv/bin/dhcpcanon

Installation for developers
=============================

It is recommended to install ``dhcpcanon`` in a python virtual environment.

Check https://virtualenv.pypa.io/en/latest/installation.html. In Debian::

    sudo apt install python-virtualenv

Create a virtual environment::

    mkdir ~/.virtualenvs
    virtualenv ~/.virtualenvs/dhcpcanonenv
    source ~/.virtualenvs/dhcpcanonenv/bin/activate

Get the sources::
    git clone https://github.com/juga0/dhcpcanon

Install it::

    pip install -e .
