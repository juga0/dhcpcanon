.. _install:

Install dhcpcanon
=================

The recommended way to install ``dhcpcanon`` is with the Debian package manager,
as it will also install the ``systemd`` service.

The installation from source is recommended for developers or other Linux
distributions.

Installation in Debian testing
-------------------------------
::

    sudo apt install dhcpcanon

Installation in Debian/Ubuntu from source code
----------------------------------------------

Install system dependencies
~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    sudo apt install python-dev

Install dhcpcanon dependencies with virtualenv
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Obtain virtualenv
^^^^^^^^^^^^^^^^^

Check https://virtualenv.pypa.io/en/latest/installation.html or
if Debian equal/newer than Jessie (virtualenv version equal or greater
than 1.9), then::

    sudo apt install python-virtualenv

Create a virtual environment
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

    mkdir ~/.virtualenvs
    virtualenv ~/.virtualenvs/dhcpcanonenv
    source ~/.virtualenvs/dhcpcanonenv/bin/activate

Install dependencies in virtualenv
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    git clone https://github.com/juga0/dhcpcanon
    cd dhcpcanon
    pip install -r requirements.txt

or run::

    python setup.py install

or run::

    pip install dhcpcanon
