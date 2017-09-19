# Makefile for a source distribution of dhcpcanon.
#
# This package is not self-contained and the build products may require other
# dependencies to function; it is given as a reference for distro packagers.

PACKAGE = dhcpcanon
VERSION = $(shell sh version.sh)
DESTDIR =

THISFILE = $(lastword $(MAKEFILE_LIST))
PYTHON = python

# GNU command variables
# see http://www.gnu.org/prep/standards/html_node/Command-Variables.html

INSTALL = install
INSTALL_DATA = $(INSTALL) -m 644
INSTALL_PROGRAM = $(INSTALL)
INSTALL_SCRIPT = $(INSTALL)

# GNU directory variables
# see http://www.gnu.org/prep/standards/html_node/Directory-Variables.html

prefix = /usr/local
exec_prefix = $(prefix)
sbindir = $(exec_prefix)/sbin

datarootdir = $(prefix)/share
datadir = $(datarootdir)
sysconfdir = $(prefix)/etc

docdir = $(datarootdir)/doc/$(PACKAGE)
mandir = $(datarootdir)/man
man8dir = $(mandir)/man8

# for systemd
tmpfilesdir=$(prefix)/lib/tmpfiles.d
systemunitdir=$(prefix)/lib/systemd/system
# for systemd udev
networkdir=$(prefix)/lib/systemd/network

# for apparmor
apparmordir=$(sysconfdir)/apparmor.d

srcdir = .

SRC_MAN8 = man/dhcpcanon.8
SRC_SCRIPT = sbin/dhcpcanon-script
SRC_DOC = README.md LICENSE
SRC_TMPFILES = tmpfiles.d/dhcpcanon.conf
SRC_UNITFILE = systemd/dhcpcanon.service
SRC_APPARMOR = apparmor.d/sbin.dhcpcanon
SRC_LINKFILE = systemd/network/90-dhcpcanon.link
SRC_ALL = $(SRC_SCRIPT) $(SRC_DOC) $(SRC_MAN8)

DST_MAN8 = $(SRC_MAN8)
DST_SCRIPT = $(SRC_SCRIPT)
DST_DOC = $(SRC_DOC)
DST_TMPFILES = $(SRC_TMPFILES)
DST_UNITFILE = $(SRC_UNITFILE)
DST_APPARMOR = $(SRC_APPARMOR)
DST_LINKFILE = $(SRC_LINKFILE)
DST_ALL = $(DST_SCRIPT) $(DST_DOC) $(DST_MAN8)

TEST_PY = dhcpcanon-test.py

all: $(DST_ALL) $(THISFILE)

install: all
	@echo $@

	mkdir -p $(DESTDIR)$(sbindir)
	for i in $(DST_SCRIPT); do $(INSTALL_SCRIPT) "$$i" $(DESTDIR)$(sbindir); done
	mkdir -p $(DESTDIR)$(docdir)
	for i in $(DST_DOC); do $(INSTALL_DATA) "$$i" $(DESTDIR)$(docdir); done
	mkdir -p $(DESTDIR)$(man8dir)
	for i in $(DST_MAN8); do $(INSTALL_DATA) "$$i" $(DESTDIR)$(man8dir); done

	$(PYTHON) setup.py install  --record installed.txt $(if $(DESTDIR),--root=$(DESTDIR),--install-scripts=$(DESTDIR)$(sbindir))

	if [ -z $(WITH_SYSTEMD)]; then \
		adduser --system dhcpcanon; \
		mkdir -p $(DESTDIR)$(systemunitdir); \
		for i in $(DST_UNITFILE); do $(INSTALL_DATA) "$$i" $(DESTDIR)$(systemunitdir); done; \
		mkdir -p $(DESTDIR)$(tmpfilesdir); \
		for i in $(DST_TMPFILES); do $(INSTALL_DATA) "$$i" $(DESTDIR)$(tmpfilesdir); done; \
		systemctl enable $(DESTDIR)$(systemunitdir)/dhcpcanon.service; \
		systemd-tmpfiles --create --root=$(DESTDIR)$(tmpfilesdir)/dhcpcanon.conf; \
	fi

	if [ -z $(WITH_SYSTEMD_UDEV)]; then \
		mkdir -p $(DESTDIR)$(networkdir); \
		for i in $(DST_LINKFILE); do $(INSTALL_DATA) "$$i" $(DESTDIR)$(networkdir); done; \
	fi

	if [ -z $(WITH_APPARMOR)]; then \
		mkdir -p $(DESTDIR)$(apparmordir); \
		for i in $(DST_APPARMOR); do $(INSTALL_DATA) "$$i" $(DESTDIR)$(apparmordir); done; \
		for i in $(DST_APPARMOR); do aa-complain $(DESTDIR)$(apparmordir)/"$$i"; done; \
	fi

uninstall:
	@echo $@
	for i in $(notdir $(DST_SCRIPT)); do rm $(DESTDIR)$(sbindir)/"$$i"; done
	for i in $(notdir $(DST_DOC)); do rm $(DESTDIR)$(docdir)/"$$i"; done
	for i in $(notdir $(DST_MAN8)); do rm $(DESTDIR)$(man8dir)/"$$i"; done
	# it will only work in the case that the file has not been removed
	cat installed.txt | xargs rm -rf
	# systemd files
	for i in $(notdir $(DST_UNITFILE)); do rm $(DESTDIR)$(systemunitdir)/"$$i"; done
	for i in $(notdir $(DST_TMPFILES)); do rm $(DESTDIR)$(tmpfilesdir)/"$$i"; done
	for i in $(notdir $(DST_APPARMOR)); do rm $(DESTDIR)$(apparmordir)/"$$i"; done
	for i in $(notdir $(DST_LINKFILE)); do rm $(DESTDIR)$(networkdir)/"$$i"; done

clean:
	python setup.py clean
	rm -rf *.pyc build dist dhcpcanon.egg-info

distclean: clean

maintainer-clean: distclean
	rm -f $(DST_MAN8)

pylint: $(SRC_SCRIPT)
	pylint -E $^

check: $(THISFILE)
	for i in $(TEST_PY); do $(PYTHON) "$$i"; done

.PHONY: all install uninstall clean distclean maintainer-clean check pylint
