
import logging
import sys

LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(module)s[%(process)d.%(thread)d]'\
                      ' %(filename)s:%(lineno)s -'\
                      ' %(funcName)s - %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'
            },
        'formsys': {
            'format': "%(asctime)s %(module)s[%(process)s.%(thread)s]: %(message)s",
            'datefmt': "%b %d %H:%M:%S"
            }
        },
    'handlers': {
        'stdout': {
            'class': 'logging.StreamHandler',
            'stream': sys.stdout,
            'formatter': 'verbose',
            'level': 'DEBUG',
            },
        'syslog': {
            'class': 'logging.handlers.SysLogHandler',
            'address': '/dev/log',
            'formatter': 'formsys',
            'level': 'INFO',
            },
        },
    'loggers': {
        'dhcpcanon': {
            'handlers': ['syslog', 'stdout'],
            'level': logging.INFO,
            'propagate': False
            },
        }
    }
