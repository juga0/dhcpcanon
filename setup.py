#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.

"""Setup."""
from setuptools import find_packages, setup

import dhcpcanon

setup(
    name='dhcpcanon',
    version=dhcpcanon.__version__,
    description=dhcpcanon.__description__,
    long_description=dhcpcanon.__long_description__,
    author=dhcpcanon.__author__,
    author_email=dhcpcanon.__author_mail__,
    license='MIT',
    url=dhcpcanon.__website__,
    packages=find_packages(exclude=['contrib', 'docs', 'tests*']),
    install_requires=[
        'scapy>=2.2";python_version<="2.7"',
        'scapy-python3>=0.21;python_version>="3.4"',
        "netaddr>=0.7",
        "pip>=8.1",
        "attrs>=16.3",
        # "daemon>=1.1"
    ],
    # leaved commented to have concrete dependencies
    # dependency_links=[
    #     "https://pypi.python.org/simple/scapy==2.2.0-dev",
    #     "https://pypi.python.org/simple/netaddr==0.7.10",
    #     "https://pypi.python.org/simple/ipaddr==2.1.11",
    #     "https://pypi.python.org/simple/pytz==2016.6.1",
    #     "https://pypi.python.org/simple/pip==8.1.2",
    #     "https://pypi.python.org/simple/pyroute2==0.4.11"
    #     "https://pypi.python.org/simple/attrs==16.3.0"
    # ],
    extras_require={
        'dev': ['ipython', 'pyflakes', 'pep8'],
        'test': ['coverage', 'coveralls', 'codecov', 'tox', 'pytest'],
        'doc': ['sphinx', 'pylint']
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
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        "Topic :: System :: Networking",
    ],
)
