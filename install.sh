#!/bin/bash

mkdir -p /sbin
for i in sbin/dhcpcanon-script; do install "$i" /sbin; done
mkdir -p /share/doc/dhcpcanon
for i in README.md LICENSE; do install -m 644 "$i" /share/doc/dhcpcanon; done
mkdir -p /share/man/man8
for i in man/dhcpcanon.8; do install -m 644 "$i" /share/man/man8; done
python3 setup.py install  --record installed.txt --install-scripts=/sbin
adduser --system dhcpcanon
mkdir -p /lib/systemd/system
cp systemd/dhcpcanon.service /lib/systemd/system/dhcpcanon.service
mkdir -p /lib/tmpfiles.d
for i in tmpfiles.d/dhcpcanon.conf; do install -m 644 "$i" /lib/tmpfiles.d; done
systemctl enable /lib/systemd/system/dhcpcanon.service
systemd-tmpfiles --create --root=/lib/tmpfiles.d/dhcpcanon.conf

mkdir -p /lib/systemd/network
for i in systemd/network/90-dhcpcanon.link; do install -m 644 "$i" /lib/systemd/network; done
mkdir -p /etc/apparmor.d
for i in apparmor.d/sbin.dhcpcanon; do install -m 644 "$i" /etc/apparmor.d; done
for i in apparmor.d/sbin.dhcpcanon; do aa-complain /etc/apparmor.d/"$i"; done
