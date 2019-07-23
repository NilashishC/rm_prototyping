import re


def _tmplt_process_id(process):
    command = "router ospf {id}".format(**process)
    if 'vrf' in process:
        command += ' vrf {vrf}'.format(**process)
    return command


def _tmplt_area_default_information(area):
    command = "area {area} {type}".format(**area)
    command += " default-information-originate"
    if 'metric' in area['default_information']:
        command += ' metric {default_information[metric]}'.format(**area)
    if 'metric_type' in area['default_information']:
        command += ' metric-type'
        command += ' {default_information[metric_type]}'.format(**area)
    if area['default_information'].get('nssa_only', False):
        command += ' nssa-only'
    return command


def _tmplt_area_range(arange):
    command = "area {area} range {range}".format(**arange)
    if arange.get('not_advertise') is True:
        command += ' not-advertise'
    if 'cost' in arange:
        command += ' cost {cost}'.format(**arange)
    return command


def _tmplt_default_information(proc):
    command = "default-information originate"
    if 'always' in proc['default_information'] and \
            proc['default_information']['always']:
        command += ' always'
    if 'metric' in proc['default_information']:
        command += ' metric'
        command += ' {default_information[metric]}'.format(**proc)
    if 'metric_type' in proc['default_information']:
        command += ' metric-type'
        command += ' {default_information[metric_type]}'.format(**proc)
    if 'route_map' in proc['default_information']:
        command += ' route-map'
        command += ' {default_information[route_map]}'.format(**proc)
    return command


def _tmplt_graceful_restart(proc):
    command = "graceful-restart"
    if 'grace_period' in proc['graceful_restart']:
        command += ' grace-period'
        command += ' {graceful_restart[grace_period]}'.format(**proc)
    return command

class OspfTemplate(object):

    PARSERS = [
        {
            'name': 'process_id',
            'getval': re.compile(r'''
                ^router\sospf\s
                (?P<process_id>\S+)
                (\svrf\s(?P<vrf>\S+))?$''', re.VERBOSE),
            'setval': _tmplt_process_id,
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'id': '{{ process_id|int }}',
                        'vrf': '{{ vrf }}'
                    }
                }
            },
            'shared': True
        },
        {
            'name': 'adjacency.exchange_start.threshold',
            'getval': re.compile(r'''
                \s+adjacency\sexchange-start\sthreshold\s
                (?P<aest>\d+)$''', re.VERBOSE),
            'setval': ('adjacency exchange-start threshold'
                       ' {adjacency[exchange_start][threshold]}'),
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'adjacency': {
                            'exchange_start': {
                                'threshold': '{{ aest|int }}'
                            }
                        }
                    }
                }
            }
        },
        {
            'name': 'auto_cost.reference_bandwidth',
            'getval': re.compile(r'''
                \s+auto-cost\sreference-bandwidth\s
                (?P<acrb>\d+)$''', re.VERBOSE),
            'setval':
            'auto-cost reference-bandwidth {auto_cost[reference_bandwidth]}',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'auto_cost': {
                            'reference_bandwidth': '{{ acrb }}'
                        }
                    }
                }
            },
            'cast': {
                'acrb': 'to_int',
            },
        },
        {
            'name': 'area',
            'getval': re.compile(r'''
                \s+area\s(?P<area>\S+)\s
                (?P<area_type>nssa|stub)$''', re.VERBOSE),
            'setval': 'area {area} {type}',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'areas': {
                            '{{ area }}': {
                                'area': '{{ area }}',
                                'type': '{{ area_type }}'
                            }
                        }
                    }
                }
            }
        },
        {
            'name': 'area.default_cost',
            'getval': re.compile(r'''
                \s+area\s(?P<area>\S+)\s
                default-cost\s(?P<default_cost>\S+)$''', re.VERBOSE),
            'setval': 'area {area} default-cost {default_cost}',
            'compval': 'default_cost',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'areas': {
                            '{{ area }}': {
                                'area': '{{ area }}',
                                'default_cost': '{{ default_cost|int }}'
                            }
                        }
                    }
                }
            }
        },
        {
            'name': 'area.filter',
            'getval': re.compile(r'''
                \s+area\s(?P<area>\S+)\s
                filter\s(?P<filter>\S+)$''', re.VERBOSE),
            'setval': 'area {area} filter {filter}',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'areas': {
                            '{{ area }}': {
                                'area': '{{ area }}',
                                'filters': ['{{ filter }}']
                            }
                        }
                    }
                }
            }
        },
        {
            'name': 'area.default_information',
            'getval': re.compile(r'''
                \s+area\s(?P<area>\S+)\s
                (?P<area_type>nssa|stub)\s
                (?P<dio>default-information-originate)
                (\smetric\s(?P<adi_metric>\d+))?
                (\smetric-type\s(?P<adi_metric_type>\d))?
                (\s(?P<d_nssa_only>nssa-only))?$''', re.VERBOSE),
            'setval': _tmplt_area_default_information,
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'areas': {
                            '{{ area }}': {
                                'area': '{{ area }}',
                                'type': '{{ area_type }}',
                                'default_information': {
                                    'metric': ('{{ adi_metric|int'
                                               ' if adi_metric != None'
                                               ' else None }}'),
                                    'metric_type': ('{{ adi_metric_type|int'
                                                    ' if adi_metric_type'
                                                    ' != None else None }}'),
                                    'nssa_only': ('{{ True if d_nssa_only'
                                                  ' else None }}'),
                                    'originate': True
                                }
                            }
                        }
                    }
                }
            }
        },
        {
            'name': 'area.no_summary',
            'getval': re.compile(r'''
                \s+area\s(?P<area>\S+)\s
                (?P<area_type>nssa|stub)\s
                (?P<no_summary>no-summary)''', re.VERBOSE),
            'setval': 'area {area} {type} no-summary',
            'compval': 'no_summary',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'areas': {
                            '{{ area }}': {
                                'area': '{{ area }}',
                                'no_summary': True,
                                'type': '{{ area_type }}'
                            }
                        }
                    }
                }
            }
        },
        {
            'name': 'area.nssa_only',
            'getval': re.compile(r'''
                \s+area\s(?P<area>\S+)\s
                (?P<area_type>nssa|stub)
                (\s(?P<a_nssa_only>nssa-only))?$''', re.VERBOSE),
            'setval': 'area {area} {type} nssa-only',
            'compval': 'nssa_only',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'areas': {
                            '{{ area }}': {
                                'area': '{{ area }}',
                                'nssa_only': ('{{ True if a_nssa_only'
                                              ' else None }}'),
                                'type': '{{ area_type }}'
                            }
                        }
                    }
                }
            }
        },
        {
            'name': 'area.range',
            'getval': re.compile(r'''
                \s+area\s(?P<area>\S+)\s
                range\s(?P<range>\S+)
                (\s(?P<not_advertise>not-advertise))?
                (\scost\s(?P<cost>\d+))?$''', re.VERBOSE),
            'setval': _tmplt_area_range,
            'remval': 'area {area} range {range}',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'areas': {
                            '{{ area }}': {
                                'area': '{{ area }}',
                                'ranges': [{
                                    'cost': ('{{ cost|int if cost != None'
                                             ' else None }}'),
                                    'not_advertise': ('{{ True'
                                                      ' if not_advertise'
                                                      ' else None }}'),
                                    'range': '{{ range }}'
                                    }]
                            }
                        }
                    }
                }
            }
        },
        {
            'name': 'bfd.all_interfaces',
            'getval': re.compile(r'''
                \s+bfd\s
                (?P<all_interfaces>all-interfaces)$''', re.VERBOSE),
            'setval': 'bfd all-interfaces',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'bfd': {
                            'all_interfaces': ('{{ True if all_interfaces'
                                               ' else None}}')
                        }
                    }
                }
            }
        },
        {
            'name': 'compatible.rfc1583',
            'getval': re.compile(r'''
                \s+compatible\s
                (?P<rfc1583>rfc1583)$''', re.VERBOSE),
            'setval': 'compatible rfc1583',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'compatible': {
                            'rfc1583': '{{ True if rfc1583 else None }}'
                        }
                    }
                }
            }
        },
        {
            'name': 'default_information',
            'getval': re.compile(r'''
                (\s+(?P<no_dio>no))?
                \s+default-information\soriginate
                (\s(?P<always>always))?
                (\smetric\s(?P<di_metric>\d+))?
                (\smetric-type\s(?P<di_metric_type>\d))?
                (\sroute-map\s(?P<route_map>\S+))?$''', re.VERBOSE),
            'setval': _tmplt_default_information,
            'remval': 'default-information originate',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'default_information': {
                            'always': '{{ True if always else None }}',
                            'metric': ('{{di_metric|int '
                                       'if di_metric != None else None }}'),
                            'metric_type': ('{{ di_metric_type|int'
                                            ' if di_metric_type != None'
                                            ' else None }}'),
                            'originate': '{{ False if no_dio else True }}',
                            'route_map': '{{ route_map }}'
                        }
                    }
                }
            }
        },
        {
            'name': 'distance.external',
            'getval': re.compile(r'''
                \s+distance\sospf\sexternal\s
                (?P<distance_external>\d+)$''', re.VERBOSE),
            'setval': 'distance ospf external {distance[external]}',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'distance': {
                            'external': '{{ distance_external|int }}'
                        }
                    }
                }
            }
        },
        {
            'name': 'distance.intra_area',
            'getval': re.compile(r'''
                \s+distance\sospf\sintra-area\s
                (?P<distance_intra_area>\d+)$''', re.VERBOSE),
            'setval': 'distance ospf intra-area {distance[intra_area]}',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'distance': {
                            'intra_area': '{{ distance_intra_area|int }}'
                        }
                    }
                }
            }
        },
        {
            'name': 'distance.inter_area',
            'getval': re.compile(r'''
                \s+distance\sospf\sinter-area\s
                (?P<distance_inter_area>\d+)$''', re.VERBOSE),
            'setval': 'distance ospf inter-area {distance[inter_area]}',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'distance': {
                            'inter_area': '{{ distance_inter_area|int }}'
                        }
                    }
                }
            }
        },
        {
            'name': 'distribute_list',
            'getval': re.compile(r'''
                \s+distribute-list\s
                (?P<dl_type>\S+)\s
                (?P<dl_name>\S+)\sin$''', re.VERBOSE),
            'setval': ('distribute-list {distribute_list[type]}'
                       ' {distribute_list[name]} in'),
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'distribute_list': {
                            'name': '{{ dl_name }}',
                            'type': '{{ dl_type }}'
                        }
                    }
                }
            }
        },
        {
            'name': 'dn_bit_ignore',
            'getval': re.compile(r'''\s+dn-bit-ignore$''', re.VERBOSE),
            'setval': 'dn-bit-ignore',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'dn_bit_ignore': True
                    }
                }
            }
        },
        {
            'name': 'graceful_restart',
            'getval': re.compile(r'''
                \s+graceful-restart
                (\sgrace-period\s(?P<grace_period>\d+))?
                $''', re.VERBOSE),
            'setval': _tmplt_graceful_restart,
            'remval': 'graceful-restart',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'graceful_restart': {
                            'enable': True,
                            'grace_period': ('{{ grace_period|int'
                                             ' if grace_period != None'
                                             ' else None }}')
                        }
                    }
                }
            }
        },
        {
            'name': 'graceful_restart.helper',
            'getval': re.compile(r'''
                \s+(?P<graceful_restart_helper>no\sgraceful-restart-helper)
                $''', re.VERBOSE),
            'setval': 'graceful-restart-helper',
            'compval': 'graceful_restart.helper',
            'result': {
                'processes': {
                    '{{ process_id }}_{{ vrf }}': {
                        'graceful_restart': {
                            'helper': False,
                        }
                    }
                }
            }
        }
    ]
