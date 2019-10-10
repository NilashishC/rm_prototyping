""" Note the quotes around password and privacy_password
to prevent Template from converting it to an int
"""

import re


def _tmplt_address(side):
    command = []
    if side.get('any'):
        command.append('any')
    elif 'prefix' in side:
        command.append(side['prefix'])
    elif 'address' in side:
        command.append(side['address'])
        command.append(side['wildcard_bits'])
    elif 'addrgroup' in side:
        command.append('addrgroup')
        command.append(side['addrgroup'])
    return command


def _tmplt_intr(entry):
    command = []
    for qualifier in ['eq', 'gt', 'lt', 'neq']:
        if qualifier in entry:
            command.append(qualifier)
            command.append(entry[qualifier])
    if 'range' in entry:
        command.append('range')
        command.append(entry['range']['start'])
        command.append(entry['range']['end'])
    return command


def _tmplt_portgroup(entry):
    command = []
    if 'portgroup' in entry:
        command.append('portgroup')
        command.append(entry['portgroup'])
    return command


def _tmplt_entry(entry):
    command = []
    command.append(entry['sequence'])
    command.append(entry['action'])
    command.append(entry['protocol'])
    for srcdst in entry['source'], entry['destination']:
        command.extend(_tmplt_address(srcdst))
        command.extend(_tmplt_intr(srcdst.get('port_protocol', {})))
        command.extend(_tmplt_portgroup(srcdst.get('port_protocol', {})))
    if 'match' in entry:
        for boolval in ['ack', 'established', 'fin',
                        'psh', 'rst', 'syn', 'urg']:
            if entry['match'].get(boolval):
                command.append(boolval)
        for oval in ['dscp', 'http_method', 'precedence', 'ttl', 'vlan']:
            if oval in entry['match']:
                command.append(oval.replace('_', '-'))
                command.append(entry['match'][oval])
        if 'packet_length' in entry['match']:
            command.append('packet-length')
            command.extend(_tmplt_intr(entry['match']['packet_length']))
        if 'udf' in entry['match']:
            command.append('udf')
            for _name, udf in entry['match']['udf'].items():
                command.append(udf['name'])
                command.append(udf['value'])
                command.append(udf['mask'])
    if 'additional_parameters' in entry:
        command.append(entry['additional_parameters'])
    if entry.get('log'):
        command.append('log')
    return ' '.join([str(part) for part in command])


class ACLsTemplate(object):

    PARSERS = [
        {
            "name": "name",
            "getval": re.compile(
                r"""
                ^ip\saccess-list\s(?P<name>\S+)$""",
                re.VERBOSE,
            ),
            "setval": "ip access-list {{ name }}",
            "result": {"{{ name }}": {"name": "{{ name }}"}},
            'shared': True
        },
        {
            "name": "entry",
            "getval": re.compile(
                r"""
                ^\s+(?P<sequence>\d+)
                \s(?P<action>(permit|deny))
                \s(?P<protocol>\S+)
                (\s(?P<source_any>any))?
                (\s(?P<source_network_prefix>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}))?
                (\s(?P<source_network_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(?P<source_wildcard>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?
                (\saddrgroup\s(?P<source_addrgroup>\S+))?
                (\seq\s(?P<src_port_eq>\S+))?
                (\sgt\s(?P<src_port_gt>\S+))?
                (\slt\s(?P<src_port_lt>\S+))?
                (\sneq\s(?P<src_port_neq>\S+))?
                (\sportgroup\s(?P<src_port_portgroup>\S+))?
                (\srange\s(?P<src_range_start>\S+)\s(?P<src_range_end>\S+))?
                (\s(?P<dest_any>any))?
                (\s(?P<dest_network_prefix>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}))?
                (\s(?P<dest_network_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(?P<dest_wildcard>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?
                (\saddrgroup\s(?P<dest_addrgroup>\S+))?
                (\seq\s(?P<dest_port_eq>\S+))?
                (\sgt\s(?P<dest_port_gt>\S+))?
                (\slt\s(?P<dest_port_lt>\S+))?
                (\sneq\s(?P<dest_port_neq>\S+))?
                (\sportgroup\s(?P<dest_port_portgroup>\S+))?
                (\srange\s(?P<dest_range_start>\S+)\s(?P<dest_range_end>\S+))?
                (\s(?P<m_ack>ack))?
                (\sdscp\s(<?P<m_dscp>\S+))?
                (\s(?P<m_established>established))?
                (\s(?P<m_fin>fin))?
                (\shttp-method\s(?P<m_http_method>\S+))?
                (\spacket-length\seq\s(?P<m_pl_eq>\d+))?
                (\spacket-length\sgt\s(?P<m_pl_gt>\d+))?
                (\spacket-length\slt\s(?P<m_pl_lt>\d+))?
                (\spacket-length\sneq\s(?P<m_pl_neq>\d+))?
                (\spacket-length\srange\s(?P<m_pl_rstart>\d+)\s(?P<m_pl_rend>\d+))?
                (\sprecedence\s(?P<m_precedence>\S+))?
                (\s(?P<m_urg>urg))?
                (\s(?P<m_psh>psh))?
                (\s(?P<m_rst>rst))?
                (\s(?P<m_syn>syn))?
                (\sttl\s(?P<m_ttl>\d+))?
                (\sudf(?P<m_udf_str>(\s+\S+\s0x\S+\s0x\S+)+))?
                (\svlan\s(?P<m_vlan>\d+))?
                (\s(?P<log>log))?
                (\s)?
                (?P<additional_parameters>.*?)?
                $""",
                re.VERBOSE,
            ),
            'setval': _tmplt_entry,
            "result": {
                "{{ name }}": {
                    'entries': {
                        "{{ sequence }}": {
                            'sequence': "{{ sequence }}",
                            'additional_parameters': "{{ additional_parameters.strip() }}",
                            'action': "{{ action }}",
                            'log': "{{ not not log }}",
                            'protocol': "{{ protocol }}",
                            'source': {
                                'address': "{{ source_network_address }}",
                                'addrgroup': "{{ source_addrgroup }}",
                                'any': "{{ not not source_any }}",
                                'port_protocol': {
                                    'eq': "{{ src_port_eq }}",
                                    'gt': "{{ src_port_gt }}",
                                    'lt': "{{ src_port_lt }}",
                                    'neq': "{{ src_port_neq }}",
                                    'portgroup': "{{ src_port_portgroup }}",
                                    'range': {
                                        'start': "{{ src_range_start }}",
                                        'end': "{{ src_range_end }}"
                                    },
                                },
                                'prefix': "{{ source_network_prefix }}",
                                'wildcard_bits': "{{ source_wildcard }}"
                            },
                            'destination': {
                                'addrgroup': "{{ dest_addrgroup }}",
                                'address': "{{ dest_network_address }}",
                                'any': "{{ not not dest_any }}",
                                'bits': "{{ dest_bits }}",
                                'port_protocol': {
                                    'eq': "{{ dest_port_eq }}",
                                    'gt': "{{ dest_port_gt }}",
                                    'lt': "{{ dest_port_lt }}",
                                    'neq': "{{ dest_port_neq }}",
                                    'portgroup': "{{ dest_port_portgroup }}",
                                    'range': {
                                        'start': "{{ dest_range_start }}",
                                        'end': "{{ dest_range_end }}"
                                    },
                                },
                                'prefix': "{{ dest_network_prefix }}",
                                'wildcard_bits': "{{ dest_wildcard }}"
                            },
                            'match': {
                                'ack': "{{ not not m_ack }}",
                                'dscp': "{{ m_dscp }}",
                                'established': "{{ m_established }}",
                                'fin': "{{ m_fin }}",
                                'http_method': "{{ m_http_method }}",
                                'packet_length': {
                                    'eq': "{{ m_pl_eq|int }}",
                                    'gt': "{{ m_pl_gt|int }}",
                                    'lt': "{{ m_pl_lt|int }}",
                                    'range': {
                                        'start': "{{ m_pl_rstart|int }}",
                                        'end': "{{ m_pl_rend|int }}"
                                    },
                                },
                                'precedence': "{{ m_precedence }}",
                                'psh': "{{ not not m_psh }}",
                                'rst': "{{ not not m_rst }}",
                                'syn': "{{ not not m_syn }}",
                                'ttl': "{{ m_ttl|int }}",
                                'udf': "{{ m_udf_str }}",
                                'urg': "{{ not not m_urg }}",
                                'vlan': "{{ m_vlan|int }}"
                            }
                        }
                    }
                },
            }
        },
        {
            "name": "remark",
            "getval": re.compile(
                r"""
                ^\s+(?P<sequence>\d+)\s
                (remark\s(?P<remark>.*))
                $""",
                re.VERBOSE
            ),
            "setval": "{{ sequence }} remark {{ remark }}",
            "result": {
                "{{ name }}": {
                    'entries': {
                        "{{ sequence }}": {
                            'sequence': "{{ sequence }}",
                            'remark': "{{ remark }}"
                        }
                    }
                }
            }
        },
    ]
