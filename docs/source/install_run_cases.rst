.. _install_run_cases:

Installation and running cases
===================================

system files
-------------

sbin/dhcpcanon-script
systemd/dhcpcanon.service
tmpfiles.d/dhcpcanon.conf
systemd/network/90-dhcpcanon.link
console_scripts ->  /sbin/dhcpcanon

run cases
----------

1. standalone without systemd, using -sp sbin/dhcpcanon-script
2. standalone without systemd, using resolvconf
3. standalone without systemd, using resolvconf-admin
4. launched with a wrapper, using -sp sbin/dhcpcanon-script
5. launched with a wrapper, sing resolvconf
6. launched with a wrapper, using resolvconf-admin
7. launched as systemd service, using systemd-resolved

install from
-------------

* setup.py: dhcpcanon-scriptresolvconf, resolvconf-admin and/or systemd
  need to be installed manually
* pip: dhcpcanon-scriptresolvconf, resolvconf-admin and/or systemd
  need to be installed manually
* Makefile
* Debian
