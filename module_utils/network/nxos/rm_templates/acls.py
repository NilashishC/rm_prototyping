import re
import q

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
        if entry['match'].get('fragments'):
            command.append('fragments')
        if 'tcp' in entry['match'] and 'flags' in entry['match']['tcp']:
            for tcp_flag, value in entry['match']['tcp']['flags'].items():
                if value:
                    command.append(tcp_flag)
        if 'icmp' in entry['match'] and 'types' in entry['match']['icmp']:
            unnamed = ['message_type', 'message_code']
            for icmp_type, value in entry['match']['icmp']['types'].items():
                if icmp_type not in unnamed:
                    command.append(icmp_type.replace('_', '-'))
            for msg in unnamed:
                if entry['match']['icmp']['types'].get(msg):
                    command.append(entry['match']['icmp']['types'].get(msg))
        for oval in ['precedence', 'vlan', 'dscp', 'http_method', 'ttl']:
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


def re_acl_start(proto):
    regex = re.compile(
        r"""
        ^\s+(?P<sequence>\d+)
        \s(?P<action>(permit|deny))
        \s(?P<protocol>PROTO)
        """, re.VERBOSE)
    return regex.pattern.replace('PROTO', proto)


def re_address(val):
    regex = re.compile(
        r"""
        ((\s(?P<VAL_any>any))|
        (\s(?P<VAL_network_prefix>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}))|
        (\s(?P<VAL_network_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(?P<VAL_wildcard>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))|
        (\saddrgroup\s(?P<VAL_addrgroup>\S+)))
        """, re.VERBOSE)
    return regex.pattern.replace('VAL', val)


def re_port(val):
    regex = re.compile(
        r"""
        (\seq\s(?P<VAL_port_eq>\S+))?
        (\sgt\s(?P<VAL_port_gt>\S+))?
        (\slt\s(?P<VAL_port_lt>\S+))?
        (\sneq\s(?P<VAL_port_neq>\S+))?
        (\sportgroup\s(?P<VAL_port_portgroup>\S+))?
        (\srange\s(?P<VAL_range_start>\S+)\s(?P<VAL_range_end>\S+))?
        """, re.VERBOSE)
    return regex.pattern.replace('VAL', val)


def re_tcp_flags():
    regex = re.compile(
        r"""
        (\s(?P<m_urg>urg))?
        (\s(?P<m_ack>ack))?
        (\s(?P<m_psh>psh))?
        (\s(?P<m_rst>rst))?
        (\s(?P<m_syn>syn))?
        (\s(?P<m_fin>fin))?
        (\s(?P<m_established>established))?
        """, re.VERBOSE)
    return regex.pattern


def re_packet_def():
    regex = re.compile(
        r"""
        (\sprecedence\s(?P<m_precedence>\S+))?
        (\sdscp\s(?P<m_dscp>\S+))?
        (\s(?P<m_fragments>fragments))?
        (\spacket-length\seq\s(?P<m_pl_eq>\d+))?
        (\spacket-length\sgt\s(?P<m_pl_gt>\d+))?
        (\spacket-length\slt\s(?P<m_pl_lt>\d+))?
        (\spacket-length\sneq\s(?P<m_pl_neq>\d+))?
        (\spacket-length\srange\s(?P<m_pl_rstart>\d+)\s(?P<m_pl_rend>\d+))?
        (\sttl\s(?P<m_ttl>\d+))?
        (\svlan\s(?P<m_vlan>\d+))?
        (\shttp-method\s(?P<m_http_method>\S+))?
        (\sudf(?P<m_udf_str>(\s+\S+\s0x\S+\s0x\S+)+))?
        (\s(?P<log>log))?
        """, re.VERBOSE)
    return regex.pattern


def re_unparsed():
    regex = re.compile(
        r"""
        (\s)?
        (?P<additional_parameters>.*)?
        """, re.VERBOSE)
    return regex.pattern


def re_icmp_types():
    regex = re.compile(
        r"""
        (\s(?P<icmp_message_type>\d+))?
        (\s(?P<icmp_message_code>\d+))?
        (\s(?P<icmp_administratively_prohibited>administratively-prohibited))?
        (\s(?P<icmp_alternate_address>alternate-address))?
        (\s(?P<icmp_conversion_error>conversion-error))?
        (\s(?P<icmp_dod_host_prohibited>dod-host-prohibited))?
        (\s(?P<icmp_dod_net_prohibited>dod-net-prohibited))?
        (\s(?P<icmp_echo_reply>echo-reply))?
        (\s(?P<icmp_echo>echo))?
        (\s(?P<icmp_general_parameter_problem>general-parameter-problem))?
        (\s(?P<icmp_host_isolated>host-isolated))?
        (\s(?P<icmp_host_precedence_unreachable>host-precedence-unreachable))?
        (\s(?P<icmp_host_redirect>host-redirect))?
        (\s(?P<icmp_host_tos_redirect>host-tos-redirect))?
        (\s(?P<icmp_host_tos_unreachable>host-tos-unreachable))?
        (\s(?P<icmp_host_unknown>host-unknown))?
        (\s(?P<icmp_host_unreachable>host-unreachable))?
        (\s(?P<icmp_information_reply>information-reply))?
        (\s(?P<icmp_information_request>information-request))?
        (\s(?P<icmp_mask_reply>mask-reply))?
        (\s(?P<icmp_mask_request>mask-request))?
        (\s(?P<icmp_mobile_redirect>mobile-redirect))?
        (\s(?P<icmp_net_redirect>net-redirect))?
        (\s(?P<icmp_net_tos_redirect>net-tos-redirect))?
        (\s(?P<icmp_net_tos_unreachable>net-tos-unreachable))?
        (\s(?P<icmp_net_unreachable>net-unreachable))?
        (\s(?P<icmp_network_unknown>network-unknown))?
        (\s(?P<icmp_no_room_for_option>no-room-for-option))?
        (\s(?P<icmp_option_missing>option-missing))?
        (\s(?P<icmp_packet_too_big>packet-too-big))?
        (\s(?P<icmp_parameter_problem>parameter-problem))?
        (\s(?P<icmp_port_unreachable>port-unreachable))?
        (\s(?P<icmp_precedence_unreachable>precedence-unreachable))?
        (\s(?P<icmp_protocol_unreachable>protocol-unreachable))?
        (\s(?P<icmp_reassembly_timeout>reassembly-timeout))?
        (\s(?P<icmp_redirect>redirect))?
        (\s(?P<icmp_router_advertisement>router-advertisement))?
        (\s(?P<icmp_router_solicitation>router-solicitation))?
        (\s(?P<icmp_source_quench>source-quench))?
        (\s(?P<icmp_source_route_failed>source-route-failed))?
        (\s(?P<icmp_time_exceeded>time-exceeded))?
        (\s(?P<icmp_time_range>time-range))?
        (\s(?P<icmp_timestamp_reply>timestamp-reply))?
        (\s(?P<icmp_timestamp_request>timestamp-request))?
        (\s(?P<icmp_traceroute>traceroute))?
        (\s(?P<icmp_ttl_exceeded>ttl-exceeded))?
        (\s(?P<icmp_unreachable>unreachable))?
        """, re.VERBOSE)
    return regex.pattern


class ACLsTemplate(object):

    ICMP_TYPES = {
        "administratively_prohibited": "{{ not not icmp_administratively_prohibited }}",
        "alternate_address": "{{ not not icmp_alternate_address }}",
        "conversion_error": "{{ not not icmp_conversion_error }}",
        "dod_host_prohibited": "{{ not not icmp_dod_host_prohibited }}",
        "dod_net_prohibited": "{{ not not icmp_dod_net_prohibited }}",
        "echo": "{{ not not icmp_echo }}",
        "echo_reply": "{{ not not icmp_echo_reply }}",
        "general_parameter_problem": "{{ not not icmp_general_parameter_problem }}",
        "host_isolated": "{{ not not icmp_host_isolated }}",
        "host_precedence_unreachable": "{{ not not icmp_host_precedence_unreachable }}",
        "host_redirect": "{{ not not icmp_host_redirect }}",
        "host_tos_redirect": "{{ not not icmp_host_tos_redirect }}",
        "host_tos_unreachable": "{{ not not icmp_host_tos_unreachable }}",
        "host_unknown": "{{ not not icmp_host_unknown }}",
        "host_unreachable": "{{ not not icmp_host_unreachable }}",
        "information_reply": "{{ not not icmp_information_reply }}",
        "information_request": "{{ not not icmp_information_request }}",
        "mask_reply": "{{ not not icmp_mask_reply }}",
        "mask_request": "{{ not not icmp_mask_request }}",
        "message_code": "{{ icmp_message_code }}",
        "message_type": "{{ icmp_message_type }}",
        "mobile_redirect": "{{ not not icmp_mobile_redirect }}",
        "net_redirect": "{{ not not icmp_net_redirect }}",
        "net_tos_redirect": "{{ not not icmp_net_tos_redirect }}",
        "net_tos_unreachable": "{{ not not icmp_net_tos_unreachable }}",
        "net_unreachable": "{{ not not icmp_net_unreachable }}",
        "network_unknown": "{{ not not icmp_network_unknown }}",
        "no_room_for_option": "{{ not not icmp_no_room_for_option }}",
        "option_missing": "{{ not not icmp_option_missing }}",
        "packet_too_big": "{{ not not icmp_packet_too_big }}",
        "parameter_problem": "{{ not not icmp_parameter_problem }}",
        "port_unreachable": "{{ not not icmp_port_unreachable }}",
        "precedence_unreachable": "{{ not not icmp_precedence_unreachable }}",
        "protocol_unreachable": "{{ not not icmp_protocol_unreachable }}",
        "reassembly_timeout": "{{ not not icmp_reassembly_timeout }}",
        "redirect": "{{ not not icmp_redirect }}",
        "router_advertisement": "{{ not not icmp_router_advertisement }}",
        "router_solicitation": "{{ not not icmp_router_solicitation }}",
        "source_quench": "{{ not not icmp_source_quench }}",
        "source_route_failed": "{{ not not icmp_source_route_failed }}",
        "time_exceeded": "{{ not not icmp_time_exceeded }}",
        "timestamp_reply": "{{ not not icmp_timestamp_reply }}",
        "timestamp_request": "{{ not not icmp_timestamp_request }}",
        "traceroute": "{{ not not icmp_traceroute }}",
        "ttl_exceeded": "{{ not not icmp_ttl_exceeded }}",
        "unreachable": "{{ not not icmp_unreachable }}"
    }

    RESULT = {
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
                        'dscp': "{{ m_dscp }}",
                        'fragments': "{{ not not m_fragments }}",
                        'http_method': "{{ m_http_method }}",
                        'icmp': {
                            'types': ICMP_TYPES
                        },
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
                        'tcp': {
                            'flags': {
                                'ack': "{{ not not m_ack }}",
                                'established': "{{ not not m_established }}",
                                'fin': "{{ not not m_fin }}",
                                'psh': "{{ not not m_psh }}",
                                'rst': "{{ not not m_rst }}",
                                'syn': "{{ not not m_syn }}",
                                'urg': "{{ not not m_urg }}",
                            }
                        },
                        'ttl': "{{ m_ttl|int }}",
                        'udf': "{{ m_udf_str }}",
                        'vlan': "{{ m_vlan|int }}"
                    }
                }
            }
        }
    }

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
                re_acl_start(proto="tcp") +
                re_address('source') +
                re_port('src') +
                re_address('dest') +
                re_port('dest') +
                re_tcp_flags() +
                re_packet_def() +
                re_unparsed()
                , re.VERBOSE),
            'setval': _tmplt_entry,
            "result": RESULT
        },
        {
            "name": "entry",
            "getval": re.compile(
                re_acl_start(proto="udp") +
                re_address('source') +
                re_port('src') +
                re_address('dest') +
                re_port('dest') +
                re_packet_def() +
                re_unparsed()
                , re.VERBOSE),
            'setval': _tmplt_entry,
            "result": RESULT
        },
        {
            "name": "entry",
            "getval": re.compile(
                re_acl_start(proto="icmp") +
                re_address('source') +
                re_address('dest') +
                re_icmp_types() +
                re_packet_def() +
                re_unparsed()
                , re.VERBOSE),
            'setval': _tmplt_entry,
            "result": RESULT
        },
        {
            "name": "entry",
            "getval": re.compile(
                re_acl_start(proto="\\S+") +
                re_address('source') +
                re_address('dest') +
                re_packet_def() +
                re_unparsed()
                , re.VERBOSE),
            'setval': _tmplt_entry,
            "result": RESULT
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
