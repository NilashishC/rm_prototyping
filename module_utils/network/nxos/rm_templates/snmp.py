import re


def _tmplt_host(host):
    command = "snmp-server host {host}".format(**host)
    if 'message_type' in host:
        command += ' {message_type}'.format(**host)
    command += ' version {version}'.format(**host)
    if 'security_level' in host:
        command += ' {security_level}'.format(**host)
    command += ' {community}'.format(**host)
    return _tmplt_host_udp_port(command, host)


def _tmplt_host_source_interface(host):
    command = ("snmp-server host {host}"
               " source-interface {source_interface}").format(**host)
    return _tmplt_host_udp_port(command, host)


def _tmplt_host_udp_port(command, host):
    if 'udp_port' in host:
        command += " udp-port {udp_port}".format(**host)
    return command


def _tmplt_host_vrf_filter(host):
    command = ("snmp-server host {host}"
               " filter-vrf {filter}").format(**host)
    return _tmplt_host_udp_port(command, host)


def _tmplt_host_vrf_use(host):
    command = ("snmp-server host {host}"
               " use-vrf {vrf[use]}").format(**host)
    return _tmplt_host_udp_port(command, host)


def _tmplt_user(user):
    command = []
    command.append('snmp-server user')
    command.append(user['username'])
    if user.get('group'):
        command.append(user['group'])
    command.append('auth')
    command.append(user['algorithm'])
    command.append(user['password'])
    if user.get('privacy_password', False):
        command.append('priv')
        if user.get('aes_128', False):
            command.append('aes-128')
        command.append(user['privacy_password'])
    if user.get('localized_key', False):
        command.append('localizedKey')
    if user.get('engine_id', False):
        command.append('engineID')
        command.append(user['engine_id'])
    return " ".join(command)


class SnmpTemplate(object):

    PARSERS = [
        {
            'name': 'aaa_user.cache_timeout',
            'getval': re.compile(r'''
                ^snmp-server\saaa-user\s
                cache-timeout\s(?P<cache_val>\S+)$''', re.VERBOSE),
            'setval':
            'snmp-server aaa-user cache-timeout {{ aaa_user.cache_timeout }}',
            'result': {
                'aaa_user': {
                    'cache_timeout': '{{ cache_val|int }}'
                }
            }
        },
        {
            'name': 'communities',
            'getval': re.compile(r'''
                ^snmp-server\s
                community\s(?P<c_community>\S+)\s
                group\s(?P<group>\S+)$''', re.VERBOSE),
            'setval': 'snmp-server community {{ community }} group {{ group}}',
            'compval': 'group',
            'result': {
                'communities': {
                    '{{ c_community }}': {
                        'community': '{{ c_community }}',
                        'group': '{{ group }}'
                    }
                }
            }
        },
        {
            'name': 'communities.acl',
            'getval': re.compile(r'''
                ^snmp-server\s
                community\s(?P<c_community>\S+)\s
                use-acl\s(?P<acl>\S+)$''', re.VERBOSE),
            'setval': 'snmp-server community {{ community }} use-acl {{ acl}}',
            'compval': 'acl',
            'result': {
                'communities': {
                    '{{ c_community }}': {
                        'community': '{{ c_community }}',
                        'acl': '{{ acl }}'
                    }
                }
            }
        },
        {
            'name': 'communities.ipv4acl',
            'getval': re.compile(r'''
                ^snmp-server\s
                community\s(?P<c_community>\S+)\s
                use-ipv4acl\s(?P<ipv4acl>\S+)$''', re.VERBOSE),
            'setval': ('snmp-server community {{ community}}'
                       ' use-ipv4acl {{ ipv4acl }}'),
            'result': {
                'communities': {
                    '{{ c_community }}': {
                        'community': '{{ c_community }}',
                        'ipv4acl': '{{ ipv4acl }}'
                    }
                }
            }
        },
        {
            'name': 'communities.ipv6acl',
            'getval': re.compile(r'''
                ^snmp-server\s
                community\s(?P<c_community>\S+)\s
                use-ipv6acl\s(?P<ipv6acl>\S+)$''', re.VERBOSE),
            'setval': ('snmp-server community {{ community }}'
                       ' use-ipv6acl {{ ipv6acl }}'),
            'result': {
                'communities': {
                    '{{ c_community }}': {
                        'community': '{{ c_community }}',
                        'ipv6acl': '{{ ipv6acl }}'
                    }
                }
            }
        },
        {
            'name': 'communities.ipv4acl_ipv6acl',
            'getval': re.compile(r'''
              ^snmp-server\scommunity
              \s(?P<c_community>\S+)
              \suse-ipv4acl
              \s(?P<ipv4acl>\S+)
              \suse-ipv6acl
              \s(?P<ipv6acl>\S+)$''', re.VERBOSE),
            'setval': ('snmp-server community {{ community }}'
                       ' use-ipv4acl {{ ipv4acl }} use-ipv6acl {{ ipv6acl }}'),
            'result': {
                'communities': {
                    '{{ c_community }}': {
                        'community': '{{ c_community }}',
                        'ipv4acl': '{{ ipv4acl }}',
                        'ipv6acl': '{{ ipv6acl }}'
                    }
                }
            }
        },
        {
            'name': 'contact',
            'getval': r'^snmp-server contact (?P<contact>.*)$',
            'setval': 'snmp-server contact {{ contact }}',
            'result': {
                'contact': '{{ contact }}'
            }
        },
        {
            'name': 'engine_id.local',
            'getval': r'^snmp-server engineID local (?P<engine_id>\S+)$',
            'setval': 'snmp-server engineID local {{ engine_id.local }}',
            'result': {
                'engine_id': {
                    'local': '{{ engine_id }}'
                }
            }
        },
        {
            'name': 'enable',
            'getval': r'^((?P<no_enable>no)\s)?snmp-server protocol enable\s+$',
            'setval': 'snmp-server protocol enable',
            'result': {
                'enable': '{{ not no_enable is defined }}'
            },
        },
        {
            'name': 'global_enforce_priv',
            'getval': r'^((?P<no_gep>no)\s)?snmp-server globalEnforcePriv$',
            'setval': 'snmp-server globalEnforcePriv',
            'result': {
                'global_enforce_priv': '{{ not not_gep is defined }}'
            },
        },
        {
            'name': 'host',
            'getval': re.compile(r'''
                ^snmp-server\shost\s
                (?P<host>\S+)
                (\s(?P<message_type>\S+)?)
                \sversion\s
                (?P<version>\S+)\s
                ((?P<security_level>(auth|priv))\s)?
                (?P<h_community>\S+)
                (\sudp-port\s(?P<udp_port>\S+))?$
                ''', re.VERBOSE),
            'setval': _tmplt_host,
            'result': {
                'hosts': {
                    '{{ host }}_{{ udp_port|d() }}': {
                        'host': '{{ host }}',
                        'message_type': '{{ message_type }}',
                        'version': '{{ version }}',
                        'community': '{{ h_community }}',
                        'security_level': '{{ security_level }}',
                        'udp_port': '{{ udp_port|int }}'
                    }
                }
            },
            'shared': True,
        },
        {
            'name': 'host.vrf.filter',
            'getval': re.compile(r'''
               ^snmp-server\shost\s
               (?P<host>\S+)\s
               filter-vrf\s
               (?P<filter_vrf>\S+)
               (\sudp-port\s(?P<udp_port>\S+))?$
               ''', re.VERBOSE),
            'setval': _tmplt_host_vrf_filter,
            'compval': 'filter',
            'result': {
                'hosts': {
                    '{{ host }}_{{ udp_port|d() }}': {
                        'vrf': {
                            'filter': ['{{ filter_vrf }}']
                        }
                    }
                }
            }
        },
        {
            'name': 'host.vrf.use',
            'getval': re.compile(r'''
               ^snmp-server\shost\s
               (?P<host>\S+)\s
               use-vrf\s
               (?P<use_vrf>\S+)
               (\sudp-port\s(?P<udp_port>\S+))?$
               ''', re.VERBOSE),
            'setval': _tmplt_host_vrf_use,
            'compval': 'vrf.use',
            'result': {
                'hosts': {
                    '{{ host }}_{{ udp_port|d() }}': {
                        'vrf': {
                            'use': '{{ use_vrf }}'
                        }
                    }
                }
            }
        },
        {
            'name': 'host.source_interface',
            'getval': re.compile(r'''
                ^snmp-server\shost\s
                (?P<host>\S+)\s
                source-interface\s
                (?P<source_interface>\S+)$''', re.VERBOSE),
            'setval': _tmplt_host_source_interface,
            'compval': 'source_interface',
            'result': {
                'hosts': {
                    '{{ host }}_{{ udp_port|d() }}': {
                        'source_interface': '{{ source_interface }}'
                    }
                }
            }
        },
        {
            'name': 'location',
            'getval': r'^snmp-server location (?P<location>.*)$',
            'setval': 'snmp-server location {{ location }}',
            'remval': 'snmp-server location',
            'result': {
                'location': '{{ location }}'
            }
        },
        {
            'name': 'packetsize',
            'getval': r'^snmp-server packetsize (?P<packetsize>.*)$',
            'setval': 'snmp-server packetsize {{ packetsize }}',
            'result': {
                'packetsize': '{{ packetsize|int }}'
            },
        },
        {
            'name': 'source_interface.informs',
            'getval': r'^snmp-server source-interface informs (?P<int>\S+)$',
            'setval': ('snmp-server source-interface informs'
                       ' {{ source_interface.informs }}'),
            'result': {
                'source_interface': {
                    'informs': '{{ int }}'
                }
            }
        },
        {
            'name': 'source_interface.traps',
            'getval': r'^snmp-server source-interface traps (?P<int>\S+)$',
            'setval':
            'snmp-server source-interface traps {{ source_interface.traps }}',
            'result': {
                'source_interface': {
                    'traps': '{{ int }}'
                }
            },
        },
        {
            'name': 'traps',
            'getval': re.compile(r'''
                  ^((?P<no_trap>no)\s)?
                  snmp-server\senable\straps\s
                  (?P<type>\S+)\s
                  (?P<name>\S+)$''', re.VERBOSE),
            'setval': 'snmp-server enable traps {{ type }} {{ name}}',
            'compval': 'negate',
            'result': {
                'traps': {
                    '{{ type }}': {
                        'type': '{{ type }}',
                        'names': [{
                            'name': '{{ name }}',
                            'negate': '{{ no_trap is defined }}'
                        }]
                    }
                }
            }
        },
        {
            'name': 'users',
            'getval': re.compile(r'''
              ^snmp-server\suser\s
              (?P<username>\S+)
              (\s(?P<group>\S+))?
              \sauth
              \s(?P<algorithm>(md5|sha))
              \s(?P<password>\S+)
              (\spriv(\s(?P<aes_128>aes-128))?\s(?P<privacy_password>\S+))?
              (\s(?P<localized_key>localizedkey))?
              (\sengineID\s(?P<engine_id>\S+))?$''', re.VERBOSE),
            'setval': _tmplt_user,
            'result': {
                'users': {
                    '{{ username }}{{ engine_id|d() }}': {
                        'aes_128': '{{ not not aes_128 }}',
                        'algorithm': '{{ algorithm }}',
                        'engine_id': '{{ engine_id }}',
                        'groups': ['{{ group }}'],
                        'localized_key': '{{ not not localized_key }}',
                        'password': '{{ password }}',
                        'privacy_password': '{{ privacy_password }}',
                        'username': '{{ username }}'
                    }
                }
            },
        },
        {
            'name': 'users.enforce_priv',
            'getval': re.compile(r'''
              ^snmp-server\suser\s
              (?P<username>\S+)
              \s(?P<enforce_priv>enforcePriv)$''', re.VERBOSE),
            'setval': 'snmp-server user {{ username }} enforcePriv',
            'compval': 'enforce_priv',
            'result': {
                'users': {
                    '{{ username }}': {
                        'username': '{{ username }}',
                        'enforce_priv': True
                    }
                }
            },
        },
        {
            'name': 'users.group',
            'getval': re.compile(r'''
              ^snmp-server\suser\s
              (?P<username>\S+)
              \s(?!enforcePriv)(?P<group>\S+)$''', re.VERBOSE),
            'setval': 'snmp-server user {{ username }} {{ group }}',
            'result': {
                'users': {
                    '{{ username }}': {
                        'groups': ['{{ group }}'],
                        'username': '{{ username }}'
                    }
                }
            },
        },
        {
            'name': 'users.ipv4acl',
            'getval': re.compile(r'''
              ^snmp-server\suser\s
              (?P<username>\S+)
              \suse-ipv4acl
              \s(?P<ipv4acl>\S+)$''', re.VERBOSE),
            'setval': ('snmp-server user {{ username }}'
                       ' use-ipv4acl {{ ipv4acl }}'),
            'result': {
                'users': {
                    '{{ username }}': {
                        'username': '{{ username }}',
                        'ipv4acl': '{{ ipv4acl }}'
                    }
                }
            }
        },
        {
            'name': 'users.ipv6acl',
            'getval': re.compile(r'''
                  ^snmp-server\suser\s
                  (?P<username>\S+)
                  \suse-ipv6acl
                  \s(?P<ipv6acl>\S+)$''', re.VERBOSE),
            'setval': ('snmp-server user {{ username }}'
                       ' use-ipv6acl {{ ipv6acl }}'),
            'result': {
                'users': {
                    '{{ username }}': {
                        'username': '{{ username }}',
                        'ipv6acl': '{{ ipv6acl }}'
                    }
                }
            }
        },
        {
            'name': 'users.ipv4acl_ipv6acl',
            'getval': re.compile(r'''
              ^snmp-server\suser\s
              (?P<username>\S+)
              \suse-ipv4acl
              \s(?P<ipv4acl>\S+)
              \suse-ipv6acl
              \s(?P<ipv6acl>\S+)$''', re.VERBOSE),
            'setval': ('snmp-server user {{ username }}'
                       ' use-ipv4acl {{ ipv4acl }} use-ipv6acl {{ ipv6acl }}'),
            'result': {
                'users': {
                    '{{ username }}': {
                        'username': '{{ username }}',
                        'ipv4acl': '{{ ipv4acl }}',
                        'ipv6acl': '{{ ipv6acl }}'
                    }
                }
            }
        }
    ]
