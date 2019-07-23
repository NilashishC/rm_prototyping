import re


class InterfacesTemplate(object):

    PARSERS = [
        {
            'name':
            'interface',
            'getval':
            re.compile(r'''
              ^interface\s(?P<name>\S+)$''', re.VERBOSE),
            'setval':
            'interface {{ name }}',
            'result': {
                '{{ name }}': {
                    'name': '{{ name }}'
                },
            },
            'shared':
            True
        },
        {
            'name': 'description',
            'getval': re.compile(r'''
              \s+description\s(?P<description>\S+)$''', re.VERBOSE),
            'setval': 'description {{ description }}',
            'result': {
                '{{ name }}': {
                    'description': '{{ description }}'
                },
            },
        },
        {
            'name': 'duplex',
            'getval': re.compile(r'''
              \s+duplex\s(?P<duplex>\S+)$''', re.VERBOSE),
            'setval': 'duplex {{ duplex }}',
            'result': {
                '{{ name }}': {
                    'duplex': '{{ duplex }}'
                },
            },
        },
        {
            'name': 'mtu',
            'getval': re.compile(r'''
              \s+mtu\s(?P<mtu>\d+)$''', re.VERBOSE),
            'setval': 'mtu {{ mtu }}',
            'result': {
                '{{ name }}': {
                    'mtu': '{{ mtu|int }}'
                },
            },
        },
        {
            'name': 'speed',
            'getval': re.compile(r'''
              \s+speed\s(?P<speed>\S+)$''', re.VERBOSE),
            'setval': 'speed {{ speed }}',
            'result': {
                '{{ name }}': {
                    'speed': '{{ speed }}'
                },
            },
        },
        {
            'name': 'shutdown',
            'getval': re.compile(r'''^\s+(?P<shutdown>shutdown)$''',
                                 re.VERBOSE),
            'setval': 'shutdown',
            'result': {
                '{{ name }}': {
                    'enable': False
                },
            },
        },
    ]
