import re

class InterfacesTemplate(object):

    PARSERS = [
        {
            'name': 'interface',
            'getval': re.compile(r'''
              ^interface\s(?P<name>\S+)$''', re.VERBOSE),
            'setval': 'interface {name}',
            'result': {
                '{name}': {
                    'name': '{name}'
                    },
                },
            'shared': True
        },
        {
            'name': 'description',
            'getval': re.compile(r'''
              \s+description\s(?P<description>\S+)$''', re.VERBOSE),
            'setval': 'description {description}',
            'result': {
                '{name}': {
                    'description': '{description}'
                    },
                },
        },
        {
            'name': 'enable',
            'getval': re.compile(r'''^\s+(?P<shutdown>shutdown)$''', re.VERBOSE),
            'setval': 'shutdown',
            'result': {
                '{name}': {
                    'enable': '{shutdown}'
                    },
                },
            'cast': {
                'shutdown': 'false_or_none'
            }
        },
    ]
