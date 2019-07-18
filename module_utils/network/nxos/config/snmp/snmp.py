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



from ansible.module_utils.network. \
    nxos.rm_templates.snmp import SnmpTemplate
from ansible.module_utils.network.common.utils import dict_merge
from ansible.module_utils.network. \
    nxos.facts.facts import Facts
from ansible.module_utils.network.common.rm_module import RmModule
from copy import deepcopy

import q
class Snmp(RmModule):
    """
    The nxos_snmp class
    """
    def __init__(self, module):
        super(Snmp, self).__init__(empty_fact_val={}, facts_module=Facts(),
                                   module=module, resource='snmp',
                                   tmplt=SnmpTemplate())

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        self.gen_config()
        self.run_commands()
        return self.result

    def gen_config(self):
        state = self.state
        entries = ['aaa_user.cache_timeout', 'contact', 'enable',
                   'global_enforce_priv', 'location', 'packetsize',
                   'source_interface.informs', 'source_interface.traps']

        self.compare(entries)
        self._compare_communities()
        self._compare_hosts()
        self._compare_traps()

        if state == 'deleted':
            self._state_deleted()
        elif state in ['merged', 'template']:
            self._state_merged()
        elif state == 'replaced':
            self._state_replaced()

    def _state_deleted(self):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """

        self._compare_users()
        # remove the engine id last, strange order bug in nxos
        # users become orphaned if engine_id changes
        self.addcmd(self.have, 'engine_id.local', True)

    def _state_merged(self):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        # odd behaviour in nxos, if the engineId changes, user ACLs need
        # to be removed prior and then all exisiting reapplied
        inw = self.get_from_dict(self.want, 'engine_id.local')
        inh = self.get_from_dict(self.have, 'engine_id.local')
        if self.want.get('engine_id', {}).get('local') and (inw != inh):
            before = len(self.commands)
            self._compare_users(state='deleted')
            if len(self.commands) != before:
                self.warnings.append('SNMP users removed and reapplied'
                                     ' due to change in engine_id local.')
            self.addcmd(self.want, 'engine_id.local')
            self._compare_users(want=self.have, have={})

        self._compare_users()

    def _state_replaced(self):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        # odd behaviour in nxos, if the engineId changes, user ACLs need
        # to be removed prior and then only the want applied
        inw = self.get_from_dict(self.want, 'engine_id.local')
        inh = self.get_from_dict(self.have, 'engine_id.local')
        if self.want.get('engine_id', {}).get('local') and (inw != inh):
            self._compare_users(state='deleted')
            self.addcmd(self.want, 'engine_id.local')
            before = len(self.commands)
            self._compare_users(want=self.want, have={})
            if len(self.commands) != before:
                self.warnings.append('SNMP users removed and reapplied'
                                     ' due to change in engine_id local.')

        else:
            self._compare_users()

    def _compare_communities(self):
        wantd = {entry['community']: entry
                 for entry in self.want.get('communities', [])}
        haved = {entry['community']: entry
                 for entry in self.have.get('communities', [])}
        if self.state == 'merged':
            wantd = dict_merge(haved, wantd)
        for community, entry in wantd.items():
            self._compare_community(entry, haved.pop(community, {}))
        for community, entry in haved.items():
            self._delete_community(entry)

    def _compare_hosts(self):
        wantd = {entry['host'] + '_' + str(entry.get('udp_port')): entry
                 for entry in self.want.get('hosts', [])}
        haved = {entry['host'] + '_' + str(entry.get('udp_port')): entry
                 for entry in self.have.get('hosts', [])}
        if self.state == 'merged':
            wantd = dict_merge(haved, wantd)
        for host, entry in wantd.items():
            self._compare_host(entry, haved.pop(host, {}))
        for host, entry in haved.items():
            self._delete_host(entry)

    def _compare_traps(self):
        wantd = {trap['type'] + '_' + name['name']:
                 {'name': name['name'],
                  'negate': not name['negate'],
                  'type': trap['type']}
                 for trap in self.want.get('traps', [])
                 for name in trap['names']}

        haved = {trap['type'] + '_' + name['name']:
                 {'name': name['name'],
                  'negate': not name['negate'],
                  'type': trap['type']}
                 for trap in self.have.get('traps', [])
                 for name in trap['names']}

        if self.state == 'merged':
            wantd = dict_merge(haved, wantd)
        for name, entry in wantd.items():
            self.compare(parsers=['traps'], want=entry,
                         have=haved.pop(name, {}))
        for name, entry in haved.items():
            self.compare(parsers=['traps'], want={}, have=entry)

    def _compare_users(self, state=None, want=None, have=None):
        if want is None:
            want = self.want
        if have is None:
            have = self.have
        if state is None:
            state = self.state
        wantd = {entry['username'] + '_' + str(entry.get('engine_id')): entry
                 for entry in want.get('users', [])}
        haved = {entry['username'] + '_' + str(entry.get('engine_id')): entry
                 for entry in have.get('users', [])}
        if state == 'merged':
            wantd = dict_merge(haved, wantd)
        for name, entry in wantd.items():
            self._compare_user(entry, haved.pop(name, {}))
        for name, entry in haved.items():
            self._delete_user(entry)

    def _compare_community(self, want, have):
        parsers = ['communities', 'communities.acl']
        self.compare(parsers=parsers, want=want, have=have)

        match_keys = ['ipv4acl', 'ipv6acl']
        if not self.compare_subdict(want, have, match_keys):
            if any([want.get(match_key) is not None
                    for match_key in match_keys]):
                self._tmplt_community_acls(want, False)
            else:
                if self.state == 'replaced':
                    self._tmplt_community_acls(have, True)

    def _compare_host(self, want, have):
        match_keys = ['!source_interface', '!vrf']
        if not self.compare_subdict(want, have, match_keys):
            self.addcmd(want, 'host', False)

        parsers = ['host.source_interface', 'host.vrf.use']
        self.compare(parsers=parsers, want=want, have=have)

        wantd = {want['host'] + filter: dict_merge(want, {"filter": filter})
                 for filter in self.get_from_dict(want, 'vrf.filter') or []}
        haved = {want['host'] + filter: dict_merge(have, {"filter": filter})
                 for filter in self.get_from_dict(have, 'vrf.filter') or []}
        for name, entry in wantd.items():
            self.compare(parsers=['host.vrf.filter'], want=entry,
                         have=haved.pop(name, {}))
        for name, entry in haved.items():
            self.compare(parsers=['host.vrf.filter'], want={}, have=entry)

    def _compare_user(self, want, have):
        match_keys = ['!enforce_priv', '!ipv4acl', '!ipv6acl']
        if not self.compare_subdict(want, have, match_keys):
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

            if self.state == "replaced":
                for group in have.get('groups', []):
                    have['group'] = group
                    self.addcmd(have, 'users.group', True)

        parsers = ['user.enforce_priv']
        self.compare(parsers=parsers, want=want, have=have)

        match_keys = ['ipv4acl', 'ipv6acl']
        if not self.compare_subdict(want, have, match_keys):
            if any([want.get(match_key) is not None
                    for match_key in match_keys]):
                self._tmplt_user_acls(want, False)
            else:
                if self.state == 'replaced':
                    self._tmplt_user_acls(have, True)

    def _delete_community(self, community):
        self._tmplt_community_acls(community, True)
        self.addcmd(community, 'communities.acl', True)
        self.addcmd(community, 'communities', True)

    def _delete_host(self, host):
        self.addcmd(host, 'host.source_interface', True)
        for vrf in host.get('vrf', {}).get('filter', []):
            thost = deepcopy(host)
            thost['vrf']['filter'] = vrf
            self.addcmd(thost, 'host.vrf.filter', True)
        self.addcmd(host, 'host.vrf.use', True)
        self.addcmd(host, 'host', True)

    def _delete_user(self, user):
        if 'enforce_priv' in user:
            self.addcmd(user, 'users.enforce_priv', user.get('enforce_priv'))
        self._tmplt_user_acls(user, True)
        for group in user.get('groups', [])[:-1]:
            user['group'] = group
            self.addcmd(user, 'users.group', True)
        user['group'] = None
        self.addcmd(user, 'users', True)

    def _tmplt_community_acls(self, community, negate):
        for pname in ['communities.ipv4acl_ipv6acl', 'communities.ipv4acl',
                      'communities.ipv6acl']:
            before = len(self.commands)
            self.addcmd(community, pname, negate)
            if len(self.commands) != before:
                break

    def _tmplt_user_acls(self, user, negate):
        for pname in ['users.ipv4acl_ipv6acl', 'users.ipv4acl',
                      'users.ipv6acl']:
            before = len(self.commands)
            self.addcmd(user, pname, negate)
            if len(self.commands) != before:
                break
