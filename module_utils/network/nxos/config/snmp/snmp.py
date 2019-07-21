#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The nxos_snmp class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""


from copy import deepcopy
from ansible.module_utils.network.nxos.rm_templates.snmp import SnmpTemplate
from ansible.module_utils.network.common.utils import dict_merge
from ansible.module_utils.network.nxos.facts.facts import Facts
from ansible.module_utils.network.common.rm_module import RmModule
from ansible.module_utils.network.common.rm_utils \
    import get_from_dict, compare_partial_dict

class Snmp(RmModule):
    """
    The nxos_snmp class
    """
    def __init__(self, module):
        super(Snmp, self).__init__(empty_fact_val={},
                                   facts_module=Facts(module),
                                   module=module, resource='snmp',
                                   tmplt=SnmpTemplate())
        self.want = self.want

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        self.xform()
        self.gen_config()
        self.run_commands()
        return self.result

    def xform(self):
        """ xform
        """
        # convert lists of dicts into dicts, keyed on the uid of the obj
        for thing in self.want, self.have:
            thing['communities'] = {entry['community']: entry
                                    for entry in thing.get('communities', [])}
            thing['hosts'] = {(entry['host'], entry.get('udp_port')): entry
                              for entry in thing.get('hosts', [])}
            thing['traps'] = {(trap['type'], name['name']):
                              {'name': name['name'],
                               'negate': not name['negate'],
                               'type': trap['type']}
                              for trap in thing.get('traps', [])
                              for name in trap['names']}
            thing['users'] = {(entry['username'], entry.get('engine_id')):
                              entry for entry in thing.get('users', [])}

        # if state is merged, merge want onto have
        if self.state == 'merged':
            self.want = dict_merge(self.have, self.want)

    def gen_config(self):
        """ gen config
        """
        entries = ['aaa_user.cache_timeout', 'contact', 'enable',
                   'global_enforce_priv', 'location', 'packetsize',
                   'source_interface.informs', 'source_interface.traps']
        self.compare(entries)
        self._communities_compare()
        self._hosts_compare()
        self._traps_compare()
        if self.state == 'deleted':
            self._users_compare()
            self.compare(['engine_id.local'])
        else:
            self._engine_id_users()
            self.compare(['engine_id.local'])
            self._users_compare()

    def _engine_id_users(self):
        inw = get_from_dict(self.want, 'engine_id.local')
        inh = get_from_dict(self.have, 'engine_id.local')
        if inw and (inw != inh):
            actual_wanted_users = self.want['users']
            self.want['users'] = {}
            self._users_compare()
            self.warnings.append('Existing SNMP users removed and readded'
                                 ' as needed due to change in'
                                 ' engine_id local.')
            self.want['users'] = actual_wanted_users
            self.have['users'] = {}

    def _communities_compare(self):
        want = self.want['communities']
        have = self.have['communities']
        for name, entry in want.items():
            self._community_compare(entry, have.pop(name, {}))
        for name, entry in have.items():
            self._community_delete(entry)

    def _community_compare(self, want, have):
        parsers = ['communities', 'communities.acl']
        self.compare(parsers, want, have)
        match_keys = ['ipv4acl', 'ipv6acl']
        if not compare_partial_dict(want, have, match_keys):
            if any([want.get(match_key) is not None
                    for match_key in match_keys]):
                self._community_acls(want, False)
            else:
                self._community_acls(have, True)

    def _community_delete(self, community):
        self._community_acls(community, True)
        self.addcmd(community, 'communities.acl', True)
        self.addcmd(community, 'communities', True)

    def _community_acls(self, community, negate):
        parsers = ['communities.ipv4acl_ipv6acl', 'communities.ipv4acl',
                   'communities.ipv6acl']
        self.addcmd_first_found(community, parsers, negate)

    def _hosts_compare(self):
        want = self.want['hosts']
        have = self.have['hosts']
        for name, entry in want.items():
            self._host_compare(entry, have.pop(name, {}))
        for name, entry in have.items():
            self._host_delete(entry)

    def _host_compare(self, want, have):
        match_keys = ['!source_interface', '!vrf']
        if not compare_partial_dict(want, have, match_keys):
            self.addcmd(want, 'host', False)

        parsers = ['host.source_interface', 'host.vrf.use']
        self.compare(parsers, want, have)

        wantd = {filter: {"filter": filter}
                 for filter in get_from_dict(want, 'vrf.filter') or []}
        haved = {filter: {"filter": filter}
                 for filter in get_from_dict(have, 'vrf.filter') or []}
        for name, entry in wantd.items():
            if entry != haved.pop(name, {}):
                entry.update(want)
                self.addcmd(entry, 'host.vrf.filter', False)
        for name, entry in haved.items():
            entry.update(have)
            self.addcmd(entry, 'host.vrf.filter', True)

    def _host_delete(self, host):
        self.addcmd(host, 'host.source_interface', True)
        for vrf in get_from_dict(host, 'vrf.filter') or []:
            host['vrf']['filter'] = vrf
            self.addcmd(host, 'host.vrf.filter', True)
        self.addcmd(host, 'host.vrf.use', True)
        self.addcmd(host, 'host', True)

    def _traps_compare(self):
        want = self.want['traps']
        have = self.have['traps']
        for name, entry in want.items():
            self.compare('traps', want=entry, have=have.pop(name, {}))
        for name, entry in have.items():
            self.compare('traps', want={}, have=entry)

    def _users_compare(self):
        want = self.want['users']
        have = self.have['users']
        for name, entry in want.items():
            self._user_compare(entry, have.pop(name, {}))
        for name, entry in have.items():
            self._user_delete(entry)

    def _user_compare(self, want, have):
        match_keys = ['!enforce_priv', '!ipv4acl', '!ipv6acl']
        if not compare_partial_dict(want, have, match_keys):
            if 'groups' in want:
                for group in want['groups']:
                    if group in have.get('groups', []):
                        have['groups'] = [g for g in have['groups']
                                          if g != group]
                    want['group'] = group
                    if want['groups'].index(group) == 0:
                        self.addcmd(want, 'users', False)
                    else:
                        self.addcmd(want, 'users.group', False)
            else:
                self.addcmd(want, 'users', False)

            for group in have.get('groups', []):
                have['group'] = group
                self.addcmd(have, 'users.group', True)

        self.compare('users.enforce_priv', want, have)

        match_keys = ['ipv4acl', 'ipv6acl']
        if not compare_partial_dict(want, have, match_keys):
            if any([want.get(match_key) is not None
                    for match_key in match_keys]):
                self._user_acls(want, False)
            else:
                self._user_acls(have, True)

    def _user_delete(self, user):
        self.compare('users.enforce_priv', want={}, have=user)
        self._user_acls(user, True)
        for group in user.get('groups', [])[:-1]:
            user['group'] = group
            self.addcmd(user, 'users.group', True)
        user['group'] = None
        self.addcmd(user, 'users', True)

    def _user_acls(self, user, negate):
        parsers = ['users.ipv4acl_ipv6acl', 'users.ipv4acl', 'users.ipv6acl']
        self.addcmd_first_found(user, parsers, negate)
