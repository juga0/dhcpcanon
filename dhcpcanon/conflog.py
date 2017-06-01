#
""""""
import logging
import sys

LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'verbose': {
            'format': '%(asctime)s %(levelname)s'
                      ' %(filename)s:%(lineno)s -'
                      ' %(funcName)s - %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'
            },
        'simple': {
            'format': "%(message)s",
            },
        'sys': {
            'format': "%(module)s[%(process)s]: "
                      "%(message)s"
            }
        },
    'handlers': {
        'stdout': {
            'class': 'logging.StreamHandler',
            'stream': sys.stdout,
            'formatter': 'verbose',
            'level': 'DEBUG',
            },
        'stdoutscapy': {
            'class': 'logging.StreamHandler',
            'stream': sys.stdout,
            'formatter': 'simple',
            'level': 'DEBUG',
            },
        'syslog': {
            'class': 'logging.handlers.SysLogHandler',
            'address': '/dev/log',
            'formatter': 'sys',
            'level': 'INFO',
            },
        },
    'loggers': {
        'dhcpcanon': {
            'handlers': ['syslog', 'stdout'],
            'level': logging.INFO,
            'propagate': False
            },
        "scapy.interactive": {
            'handlers': ['stdoutscapy'],
            'level': logging.INFO,
            'propagate': False
            }
        }
    }
