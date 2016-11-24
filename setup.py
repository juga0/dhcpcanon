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

from setuptools import setup
# To use a consistent encoding
from os import path, listdir
from pip.req import parse_requirements
from dhcpcanon import __version__, __author__, __author_mail__

DOC_DIR = 'doc'
TEST_DIR = 'test'
BIN_DIR = 'bin'

here = path.abspath(path.dirname(__file__))
install_reqs = parse_requirements(path.join(here, 'requirements.txt'),
                                  session=False)
reqs = [str(ir.req) for ir in install_reqs]
sphinx_rst_files = [x for x in listdir(DOC_DIR) if x[-3:] == 'rst']
sphinx_docs = [path.join(DOC_DIR, x) for x in sphinx_rst_files]

setup(
    name='dhcpcanon',
    version=__version__,
    description='DCHP IPv4 anonymity profile implementation (RFC7844).',
    long_description="""DCHP client implementation of the anonymity profile (RFC7844)
     using Scapy Automaton.
     """,
    author=__author__,
    author_email=__author_mail__,
    license='GPLv3+',
    url='https://github.com/juga0/dhcpcanon',
    packages=['dhcpcanon'],
    install_requires=reqs,
    extras_require={
        'dev': ['ipython'],
        'test': ['coverage'],
    },
    scripts=['bin/dhcpca.py'],
    include_package_data=True,
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
