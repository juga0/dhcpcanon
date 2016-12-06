#!/usr/bin/env python

#   This file is part of dhcpcanon, a set of scripts to
#   use different tor guards depending on the network we connect to.
#
#   Copyright (C) 2016 juga (juga at riseup dot net)
#
#   dhcpcanon is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License Version 3 of the
#   License, or (at your option) any later version.
#
#   dhcpcanon is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with dhcpcanon.  If not, see <http://www.gnu.org/licenses/>.
#

from setuptools import setup, find_packages
import dhcpcanon

setup(
    name='dhcpcanon',
    version=dhcpcanon.__version__,
    description=dhcpcanon.__description__,
    long_description=dhcpcanon.__long_description__,
    author=dhcpcanon.__author__,
    author_email=dhcpcanon.__author_mail__,
    license='GPLv3+',
    url=dhcpcanon.__website__,
    packages=find_packages(exclude=['contrib', 'docs', 'tests*']),
    dependency_links=[
        "https://pypi.python.org/simple/scapy==2.2.0-dev",
        "https://pypi.python.org/simple/netaddr==0.7.10",
        "https://pypi.python.org/simple/ipaddr==2.1.11",
        "https://pypi.python.org/simple/pytz==2016.6.1",
        "https://pypi.python.org/simple/pip==8.1.2",
        "https://pypi.python.org/simple/pyroute2==0.4.11"
    ],
    extras_require={
        'dev': ['ipython'],
        'test': ['coverage'],
    },
    # entry_points={
    #     'console_scripts': [
    #         'dhcpcanon = scripts.dhcpcanon:main',
    #     ]
    # },
    scripts=['scripts/dhcpcanon'],
    keywords='python scapy dhcp RFC7844 RFC2131 anonymity',
    classifiers=[
        'Development Status :: 3 - Alpha',
        "Environment :: Console",
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 ' +
        'or later (GPLv3+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
