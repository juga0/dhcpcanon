Install dhcpcanon
=================

Installation in Debian/Ubuntu from source code
----------------------------------------------

### Install system dependencies

    sudo apt-get install python-dev

### Install dhcpcanon dependencies with virtualenv

#### Obtain virtualenv

Check <https://virtualenv.pypa.io/en/latest/installation.html> or if
Debian equal/newer than Jessie (virtualenv version equal or greater than
1.9), then:

    sudo apt-get install python-virtualenv

#### Create a virtual environment

    mkdir ~/.virtualenvs
    virtualenv ~/.virtualenvs/dhcpcanonenv source
    ~/.virtualenvs/dhcpcanonenv/bin/activate

#### Install dependencies in virtualenv

    git clone https://github.com/juga0/dhcpcanon
    cd dhcpcanon 
    pip install -r requirements.txt

or run:

    python setup.py install

or run:

    pip install dhcpcanon


