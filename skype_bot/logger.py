import logging
from logging import config


class Logger:
    config_dict = {
        'version': 1,
        'handlers':
        {
            'console':
                {
                    'class': 'logging.StreamHandler',
                    'formatter': 'default',
                    'level': 'DEBUG',

                },
            'file':
                {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'formatter': 'default',
                    'filename': '/tmp/logconfig.log',
                    'level': 'DEBUG',
                    'maxBytes': 102400,
                    'backupCount': 3
                }
        },
        'formatters':
        {
            'default':
            {
                'format': '%(asctime)s %(levelname)-8s %(name)-15s %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S'
            }
        },
        'loggers':
        {
                'debug':
                {
                    'handlers': ['console', 'file']
                }
        }
    }

    def __init__(self):
        logging.config.dictConfig(self.config_dict)

    def get_logger(self, name):
        return logging.getLogger(name)
