from ansible.module_utils.network.common.templator import Templator
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
    command = "area {area} range {range[range]}".format(**arange)
    if arange['range'].get('not_advertise') is True:
        command += ' not-advertise'
    if 'cost' in arange['range']:
        command += ' cost {range[cost]}'.format(**arange)
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


class OspfTemplate(Templator):

    PARSERS = {
        'process_id': {
            'getval': re.compile(r'''
                ^router\sospf\s
                (?P<process_id>\S+)
                (\svrf\s(?P<vrf>\S+))?$''', re.VERBOSE),
            'setval': _tmplt_process_id,
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'id': '{process_id}',
                        'vrf': '{vrf}'
                    },
                },
            },
            'cast': {
                'process_id': 'to_int',
            },
            'shared': True
        },
        'adjacency.exchange_start.threshold': {
            'getval': re.compile(r'''
                \s+adjacency\sexchange-start\sthreshold\s
                (?P<aest>\d+)$''', re.VERBOSE),
            'setval': 'adjacency exchange-start threshold {adjacency[exchange_start][threshold]}',
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'adjacency': {
                            'exchange_start': {
                                'threshold': '{aest}'
                            }
                        }
                    },
                },
            },
            'cast': {
                'aest': 'to_int',
            },
        },
        'auto_cost.reference_bandwidth': {
            'getval': re.compile(r'''
                \s+auto-cost\sreference-bandwidth\s
                (?P<acrb>\d+)$''', re.VERBOSE),
            'setval':
            'auto-cost reference-bandwidth {auto_cost[reference_bandwidth]}',
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'auto_cost': {
                            'reference_bandwidth': '{acrb}'
                        }
                    },
                },
            },
            'cast': {
                'acrb': 'to_int',
            },
        },
        'area': {
            'getval': re.compile(r'''
                \s+area\s(?P<area>\S+)\s
                (?P<area_type>nssa|stub)$''', re.VERBOSE),
            'setval': 'area {area[area]} {area[type]}',
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'areas': {
                            '{area}': {
                                'area': '{area}',
                                'type': '{area_type}'
                            }
                        }
                    },
                },
            },
        },
        'area.default_cost': {
            'getval': re.compile(r'''
                \s+area\s(?P<area>\S+)\s
                default-cost\s(?P<default_cost>\S+)$''', re.VERBOSE),
            'setval': 'area {area[area]} default-cost {area[default_cost]}',
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'areas': {
                            '{area}': {
                                'area': '{area}',
                                'default_cost': '{default_cost}'
                            }
                        }
                    },
                },
            },
            'cast': {
                'default_cost': 'to_int',
            },
        },
        'area.filter': {
            'getval': re.compile(r'''
                \s+area\s(?P<area>\S+)\s
                filter\s(?P<filter>\S+)$''', re.VERBOSE),
            'setval': 'area {area} filter {filter}',
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'areas': {
                            '{area}': {
                                'area': '{area}',
                                'filters': ['{filter}']
                            }
                        }
                    },
                },
            },
        },
        'area.default_information': {
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
                    '{process_id}_{vrf}': {
                        'areas': {
                            '{area}': {
                                'area': '{area}',
                                'type': '{area_type}',
                                'default_information': {
                                    'metric': '{adi_metric}',
                                    'metric_type': '{adi_metric_type}',
                                    'nssa_only': '{d_nssa_only}',
                                    'originate': True
                                }
                            }
                        }
                    },
                },
            },
            'cast': {
                'dio': 'to_bool',
                'adi_metric': 'to_int',
                'adi_metric_type': 'to_int',
                'd_nssa_only': 'true_or_none'
            }
        },
        'area.no_summary': {
            'getval': re.compile(r'''
                \s+area\s(?P<area>\S+)\s
                (?P<area_type>nssa|stub)\s
                (?P<no_summary>no-summary)''', re.VERBOSE),
            'setval': 'area {area[area]} {area[type]} no-summary',
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'areas': {
                            '{area}': {
                                'area': '{area}',
                                'no_summary': '{no_summary}',
                                'type': '{area_type}'
                            }
                        }
                    },
                },
            },
            'cast': {
                'no_summary': 'to_bool'
            }
        },
        'area.nssa_only': {
            'getval': re.compile(r'''
                \s+area\s(?P<area>\S+)\s
                (?P<area_type>nssa|stub)
                (\s(?P<a_nssa_only>nssa-only))?$''', re.VERBOSE),
            'setval': 'area {area[area]} {area[type]} nssa-only',
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'areas': {
                            '{area}': {
                                'area': '{area}',
                                'nssa_only': '{a_nssa_only}',
                                'type': '{area_type}'
                            }
                        }
                    },
                },
            },
            'cast': {
                'a_nssa_only': 'true_or_none',
            },
        },
        'area.range': {
            'getval': re.compile(r'''
                \s+area\s(?P<area>\S+)\s
                range\s(?P<range>\S+)
                (\s(?P<not_advertise>not-advertise))?
                (\scost\s(?P<cost>\d+))?$''', re.VERBOSE),
            'setval': _tmplt_area_range,
            'remval': 'no area {area} range {range}',
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'areas': {
                            '{area}': {
                                'area': '{area}',
                                'ranges': [{
                                    'cost': '{cost}',
                                    'not_advertise': '{not_advertise}',
                                    'range': '{range}'
                                    }]
                            }
                        }
                    },
                },
            },
            'cast': {
                'cost': 'to_int',
                'not_advertise': 'true_or_none'
            }
        },
        'bfd.all_interfaces': {
            'getval': re.compile(r'''
                \s+bfd\s
                (?P<all_interfaces>all-interfaces)$''', re.VERBOSE),
            'setval': 'bfd all-interfaces',
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'bfd': {
                            'all_interfaces': '{all_interfaces}'
                        }
                    },
                },
            },
            'cast': {
                'all_interfaces': 'true_or_none',
            },
        },
        'compatible.rfc1583': {
            'getval': re.compile(r'''
                \s+compatible\s
                (?P<rfc1583>rfc1583)$''', re.VERBOSE),
            'setval': 'compatible rfc1583',
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'compatible': {
                            'rfc1583': '{rfc1583}'
                        }
                    },
                },
            },
            'cast': {
                'rfc1583': 'true_or_none',
            },
        },
        'default_information': {
            'getval': re.compile(r'''
                (\s+(?P<no_dio>no))?
                \s+default-information\soriginate
                (\s(?P<always>always))?
                (\smetric\s(?P<di_metric>\d+))?
                (\smetric-type\s(?P<di_metric_type>\d))?
                (\sroute-map\s(?P<route_map>\S+))?$''', re.VERBOSE),
            'setval': _tmplt_default_information,
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'default_information': {
                            'always': '{always}',
                            'metric': '{di_metric}',
                            'metric_type': '{di_metric_type}',
                            'originate': '{no_dio}',
                            'route_map': '{route_map}'
                        }
                    },
                },
            },
            'cast': {
                'always': 'true_or_none',
                'di_metric': 'to_int',
                'di_metric_type': 'to_int',
                'no_dio': 'no_means_false',
            },
        },
        'distance.external': {
            'getval': re.compile(r'''
                \s+distance\sospf\sexternal\s
                (?P<distance_external>\d+)$''', re.VERBOSE),
            'setval': 'distance ospf external {distance[external]}',
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'distance': {
                            'external': '{distance_external}'
                        }
                    },
                },
            },
            'cast': {
                'distance_external': 'to_int',
            },
        },
        'distance.intra_area': {
            'getval': re.compile(r'''
                \s+distance\sospf\sintra-area\s
                (?P<distance_intra_area>\d+)$''', re.VERBOSE),
            'setval': 'distance ospf intra-area {distance[intra_area]}',
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'distance': {
                            'intra_area': '{distance_intra_area}'
                        }
                    },
                },
            },
            'cast': {
                'distance_intra_area': 'to_int',
            },
        },
        'distance.inter_area': {
            'getval': re.compile(r'''
                \s+distance\sospf\sinter-area\s
                (?P<distance_inter_area>\d+)$''', re.VERBOSE),
            'setval': 'distance ospf inter-area {distance[inter_area]}',
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'distance': {
                            'inter_area': '{distance_inter_area}'
                        }
                    },
                },
            },
            'cast': {
                'distance_inter_area': 'to_int',
            },
        },
        'distribute_list': {
            'getval': re.compile(r'''
                \s+distribute-list\s
                (?P<dl_type>\S+)\s
                (?P<dl_name>\S+)\sin$''', re.VERBOSE),
            'setval': 'distribute-list {distribute_list[type]} {distribute_list[name]} in',
            'result': {
                'processes': {
                    '{process_id}_{vrf}': {
                        'distribute_list': {
                            'name': '{dl_name}',
                            'type': '{dl_type}'
                        }
                    },
                },
            },
        },
    }
