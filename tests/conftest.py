# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
"""."""
import pytest

from dhcpcanon.dhcpcap import DHCPCAP
from dhcpcanon.dhcpcapfsm import DHCPCAPFSM


@pytest.fixture
def dhcpcanon_maker(request):
    """Return a function which creates initialized dhcpcanon instances."""

    def maker():
        """."""
        dhcpcanon = DHCPCAPFSM(client_mac="00:0a:0b:0c:0d:0f")
        return dhcpcanon
    return maker


@pytest.fixture
def dhcpcanon(dhcpcanon_maker):
    """Return an initialized dhcpcanon instance."""
    return dhcpcanon_maker()


@pytest.fixture
def dhcpcap_maker(request):
    """Return a function which creates initialized dhcpcap instances."""
    def maker():
        """."""
        dhcpcap = DHCPCAP(client_mac="00:0a:0b:0c:0d:0f")
        return dhcpcap
    return maker


@pytest.fixture
def dhcpcap(dhcpcap_maker):
    """Return an initialized dhcpcap instance."""
    return dhcpcap_maker()


@pytest.fixture()
def datadir(request):
    """get, read, open test files from the "data" directory."""
    class D:
        def __init__(self, basepath):
            self.basepath = basepath

        def open(self, name, mode="r"):
            return self.basepath.join(name).open(mode)

        def join(self, name):
            return self.basepath.join(name).strpath

        def read_bytes(self, name):
            with self.open(name, "rb") as f:
                return f.read()

        def read(self, name):
            with self.open(name, "r") as f:
                return f.read()

    return D(request.fspath.dirpath("data"))
