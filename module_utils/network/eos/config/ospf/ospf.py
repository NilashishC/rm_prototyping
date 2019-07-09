#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The eos_ospf class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""


from ansible.module_utils.network. \
    eos.argspec.ospf.ospf import OspfArgs
from ansible.module_utils.network. \
    eos. \
    config.base import ConfigBase
from ansible.module_utils.network. \
    eos.facts.facts import Facts
from ansible.module_utils.network. \
    eos.rm_templates.ospf import OspfTemplate
from ansible.module_utils.network.common.utils import dict_merge
from copy import deepcopy

import q

class Ospf(ConfigBase, OspfArgs):
    """
    The eos_ospf class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ospf',
    ]

    _have = None
    _want = None
    _tmplt = OspfTemplate()

    def get_ospf_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts().get_facts(self._module,
                                             self._connection,
                                             self.gather_subset,
                                             self.gather_network_resources)
        ospf_facts = facts['ansible_network_resources'].get('ospf')
        if not ospf_facts:
            return {}
        return ospf_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        config = self._module.params['config']
        self._want = Facts().generate_final_config(config)
        self._have = self.get_ospf_facts()

        result = {'changed': False}
        result['before'] = deepcopy(self._have)
        result['commands'], result['warnings'] = self.gen_config()

        if result['commands']:
            if not self._module.check_mode:
                response = self._connection.edit_config(result['commands'])
                responses = [r for r in response['response'] if r]
                result['changed'] = True
                result['warnings'].extend(responses)
                result['after'] = self.get_ospf_facts()

        return result

    def gen_config(self):
        """ Select the appropriate function based on the state provided

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        state = self._module.params['state']
        warnings = []

        wantd = {str(entry['id']) + '_' + str(entry.get('vrf')): entry
                 for entry in self._want.get('processes', [])}
        haved = {str(entry['id']) + '_' + str(entry.get('vrf')): entry
                 for entry in self._have.get('processes', [])}

        # turn all lists of dicts into dicts

        for thing in wantd, haved:
            for _pid, proc in thing.items():
                for area in proc.get('areas', []):
                    area['ranges'] = {entry['range']: entry
                                      for entry in area.get('ranges', [])}
                proc['areas'] = {entry['area']: entry
                                 for entry in proc.get('areas', [])}

        # if state is merged, merge want onto have
        if state == 'merged':
            wantd = dict_merge(haved, wantd)

        # for processes common to want/have overridden can be treated
        # like replaced
        commands = []
        if state == 'overridden':
            eff_state = 'replaced'
        else:
            eff_state = state
        for k, want in wantd.items():
            have = haved.pop(k, {})
            commands.extend(self._compare_process(eff_state, want, have))

        # for processes only in have
        # overridded can be treated like deleted
        # replaced doesn't need any changes
        # merged doesn't need any changed
        # apply the del commands prior to the change commands
        # in case there is overlapping config (ie changing the process id for
        # a vrf 'More than 1 OSPF instance is not supported'
        if state in ['overridden', 'deleted']:
            for k, have in haved.items():
                commands[0:0] = self._tmplt.render(have, 'process_id', True)
                commands[0:0] = self._compare_process('deleted', {}, have)

        return commands, warnings

    def _compare_process(self, state, want, have):
        process_simples = ['adjacency.exchange_start.threshold',
                           'auto_cost.reference_bandwidth']
        process_nos = ['bfd.all_interfaces', 'compatible.rfc1583']
        commands = []
        commands.extend(self._compare_simples(state, process_simples, want,
                                              have))
        commands.extend(self._compare_nos(state, process_nos, want,
                                          have))
        commands.extend(self._compare_areas(state, want, have))
        if commands and want:
            commands = self._tmplt.render(want, 'process_id', False) + commands
        elif commands and have:
            commands = self._tmplt.render(have, 'process_id', False) + commands
        return commands

    def _compare_simples(self, state, simples, want, have):
        commands = []
        for simple in simples:
            inw = self._get_from_dict(want, simple)
            inh = self._get_from_dict(have, simple)
            if state == 'merged' and inw is not None and inw != inh:
                commands.extend(self._tmplt.render(want, simple, False))
            elif state == 'deleted' and inh is not None:
                commands.extend(self._tmplt.render(have, simple, True))
            elif state == 'replaced' and inw is None and inh is not None:
                commands.extend(self._tmplt.render(have, simple, True))
            elif state == 'replaced' and inw is not None and inw is not None \
                    and inw != inh:
                commands.extend(self._tmplt.render(want, simple, False))
        return commands

    def _compare_nos(self, state, nos, want, have):
        commands = []
        for entry in nos:
            inw = self._get_from_dict(want, entry)
            inh = self._get_from_dict(have, entry)
            if state == 'merged' and inw is not None and inw != inh:
                commands.extend(self._tmplt.render(want, entry, not inw))
            elif state == 'deleted' and inh is not None:
                commands.extend(self._tmplt.render(have, entry, inh))
            elif state == 'replaced' and inw is None and inh is not None:
                commands.extend(self._tmplt.render(have, entry, inh))
            elif state == 'replaced' and inw is not None and inw is not None \
                    and inw != inh:
                commands.extend(self._tmplt.render(want, entry, not inw))
        return commands

    def _compare_area(self, state, want, have):
        commands = []
        match_keys = ['type', 'default_information']
        if not self._compare_subdict(want, have, match_keys):
            if want.get('default_information', {}).get('originate'):
                commands.extend(self._tmplt.render(want,
                                                   'area.default_information',
                                                   False))
            elif want.get('no_summary') is not True:
                commands.extend(self._tmplt.render(want, 'area', False))

        commands.extend(self._compare_area_filters(state, want, have))
        commands.extend(self._compare_area_ranges(state, want, have))
        return commands

    def _compare_area_filters(self, state, want, have):
        commands = []
        need_filters = [filter for filter in want.get('filters', [])
                        if filter not in have.get('filters', [])]
        remove_filters = [filter for filter in have.get('filters', [])
                          if filter not in want.get('filters', [])]
        for afilter in need_filters:
            data = {'area': want['area'], 'filter': afilter}
            commands.extend(self._tmplt.render(data, 'area.filter', False))
        if state == 'replaced':
            for afilter in remove_filters:
                data = {'area': have['area'], 'filter': afilter}
                commands.extend(self._tmplt.render(data, 'area.filter', True))
        return commands

    def _compare_area_ranges(self, state, want, have):
        commands = []
        for rid, wrange in want.get('ranges', {}).items():
            hrange = have.get('ranges', {}).pop(rid, {})
            if wrange != hrange:
                data = {'area': want['area'], 'range': wrange}
                commands.extend(self._tmplt.render(data, 'area.range', False))
        if state == 'replaced':
            for rid, hrange in have.get('ranges', {}).items():
                data = {'area': have['area'], 'range': hrange}
                commands.extend(self._tmplt.render(hrange, 'area.range', True))
        return commands

    def _compare_areas(self, state, want, have):
        area_simples = ['area.default_cost']
        area_nos = ['area.no_summary', 'area.nssa_only']

        commands = []
        for area_id, w_area in want.get('areas', {}).items():
            h_area = have.get('areas', {}).pop(area_id, {})
            commands.extend(self._compare_nos(state, area_nos,
                                              {'area': w_area},
                                              {'area': h_area}))
            commands.extend(self._compare_simples(state, area_simples,
                                                  {'area': w_area},
                                                  {'area': h_area}))
            if state == 'deleted':
                commands.extend(self._delete_area(h_area))
            elif state in ['merged', 'replaced']:
                commands.extend(self._compare_area(state, w_area, h_area))

        for area_id, h_area in have.get('areas', {}).items():
            commands.extend(self._compare_nos(state, area_nos,
                                              {'area': {}},
                                              {'area': h_area}))
            commands.extend(self._compare_simples(state, area_simples,
                                                  {'area': {}},
                                                  {'area': h_area}))
            if state in ['deleted', 'replaced']:
                commands.extend(self._delete_area(h_area))
        return commands

    def _delete_area(self, area):
        commands = []
        for ifilter in area.get('filters', []):
            data = {'area': area['area'], 'filter': ifilter}
            commands.extend(self._tmplt.render(data, 'area.filter', True))
        for _rid, arange in area.get('ranges', {}).items():
            data = {'area': area['area'], 'range': arange['range']}
            commands.extend(self._tmplt.render(data, 'area.range', True))
        commands.extend(self._tmplt.render({'area': area}, 'area', True))
        return commands
