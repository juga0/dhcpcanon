# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
""""""
import pytest

from dhcpcanon.dhcpcanon import DHCPCAnon


@pytest.fixture
def dhcpcanon_maker(request):
    """ return a function which creates initialized dhcpcanon instances. """

    def maker():
        dhcpcanon = DHCPCAnon("lo", "127.0.0.1", "127.0.0.1")
        dhcpcanon.parse_args(iface='lo',
                             server_port=8000, client_port=8001,
                             #  client_ip='127.0.0.1',
                             server_ip='127.0.0.1',
                             #  server_mac="00:01:02:03:04:05",
                             client_mac="00:0a:0b:0c:0d:0f")
        return dhcpcanon
    return maker


@pytest.fixture
def dhcpcanon(dhcpcanon_maker):
    """ return an initialized dhcpcanon instance. """
    return dhcpcanon_maker()


@pytest.fixture()
def datadir(request):
    """ get, read, open test files from the "data" directory. """
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
