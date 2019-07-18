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


from ansible.module_utils.network.common.cfg.base import ConfigBase

from ansible.module_utils.network. \
    eos.rm_templates.ospf import OspfTemplate
from ansible.module_utils.network.common.utils import dict_merge
from ansible.module_utils.network. \
    eos.facts.facts import Facts
from ansible.module_utils.network.common.rm_module import RmModule
from ansible.module_utils.network.common.rm_module import cw_mrg


import q


class Ospf(ConfigBase):
    """
    The eos_ospf class
    """
    def __init__(self, module):
        self._rmmod = RmModule(empty_fact_val={}, facts_module=Facts(),
                               module=module, resource='ospf',
                               tmplt=OspfTemplate())

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        self.gen_config()
        self._rmmod.run_commands()
        return self._rmmod.result

    def gen_config(self):
        """ Select the appropriate function based on the state provided

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        state = self._rmmod.state

        wantd = {str(entry['id']) + '_' + str(entry.get('vrf')): entry
                 for entry in self._rmmod.want.get('processes', [])}
        haved = {str(entry['id']) + '_' + str(entry.get('vrf')): entry
                 for entry in self._rmmod.have.get('processes', [])}

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
        if state == 'overridden':
            eff_state = 'replaced'
        else:
            eff_state = state
        for k, want in wantd.items():
            have = haved.pop(k, {})
            res = self._compare_process(eff_state, want, have)
            self._rmmod.cmd_wrn(res)

        # for processes only in have
        # overridded can be treated like deleted
        # replaced doesn't need any changes
        # merged doesn't need any changed
        # apply the del commands prior to the change commands
        # in case there is overlapping config (ie changing the process id for
        # a vrf 'More than 1 OSPF instance is not supported'
        if state in ['overridden', 'deleted']:
            for k, have in haved.items():
                res = self._rmmod.render(have, 'process_id', True)
                self._rmmod.cmd_wrn(res, prepend=True)
                res = self._compare_process('deleted', {}, have)
                self._rmmod.cmd_wrn(res, prepend=True)

    def _compare_process(self, state, want, have):
        res = {'commands': [], 'warnings': []}
        parsers = ['adjacency.exchange_start.threshold',
                   'auto_cost.reference_bandwidth', 'bfd.all_interfaces',
                   'compatible.rfc1583', 'distance.external',
                   'distance.intra_area', 'distance.inter_area',
                   'distribute_list', 'dn_bit_ignore']

        res = cw_mrg(res, self._rmmod.compare(state, parsers, want, have))
        res = cw_mrg(res, self._compare_areas(state, want, have))
        res = cw_mrg(res, self._compare_default_information(state, want, have))
        if res['commands'] and want:
            tres = self._rmmod.render(want, 'process_id', False)
            res['commands'][0:0] = tres['commands']
            res['warnings'].extend(tres['warnings'])
        elif res['commands'] and have:
            tres = self._rmmod.render(have, 'process_id', False)
            res['commands'][0:0] = tres['commands']
            res['warnings'].extend(tres['warnings'])
        return res

    def _compare_area(self, state, want, have):
        res = {'commands': [], 'warnings': []}
        match_keys = ['type', 'default_information']
        if not self._rmmod.compare_subdict(want, have, match_keys):
            if want.get('default_information', {}).get('originate'):
                res = cw_mrg(res, self._rmmod.render
                             (want, 'area.default_information', False))
            elif want.get('no_summary') is not True:
                res = cw_mrg(res, self._rmmod.render(want, 'area', False))
        res = cw_mrg(res, self._compare_area_filters(state, want, have))
        res = cw_mrg(res, self._compare_area_ranges(state, want, have))
        return res

    def _compare_area_filters(self, state, want, have):
        res = {'commands': [], 'warnings': []}
        need_filters = [filter for filter in want.get('filters', [])
                        if filter not in have.get('filters', [])]
        remove_filters = [filter for filter in have.get('filters', [])
                          if filter not in want.get('filters', [])]
        for afilter in need_filters:
            data = {'area': want['area'], 'filter': afilter}
            res = cw_mrg(res, self._rmmod.render(data, 'area.filter', False))
        if state == 'replaced':
            for afilter in remove_filters:
                data = {'area': have['area'], 'filter': afilter}
                res = cw_mrg(res, self._rmmod.render
                             (data, 'area.filter', True))
        return res

    def _compare_area_ranges(self, state, want, have):
        res = {'commands': [], 'warnings': []}
        for rid, wrange in want.get('ranges', {}).items():
            hrange = have.get('ranges', {}).pop(rid, {})
            if wrange != hrange:
                data = {'area': want['area'], 'range': wrange}
                res = cw_mrg(res, self._rmmod.render
                             (data, 'area.range', False))
        if state == 'replaced':
            for rid, hrange in have.get('ranges', {}).items():
                data = {'area': have['area'], 'range': hrange}
                res = cw_mrg(res, self._rmmod.render
                             (hrange, 'area.range', True))
        return res

    def _compare_areas(self, state, want, have):
        res = {'commands': [], 'warnings': []}
        parsers = ['area.default_cost', 'area.no_summary', 'area.nssa_only']
        for area_id, w_area in want.get('areas', {}).items():
            h_area = have.get('areas', {}).pop(area_id, {})
            res = cw_mrg(res, self._rmmod.compare(state, parsers,
                                                  {'area': w_area},
                                                  {'area': h_area}))
            if state == 'deleted':
                res = cw_mrg(res, self._delete_area(h_area))
            elif state in ['merged', 'replaced']:
                res = cw_mrg(res, self._compare_area(state, w_area, h_area))

        for area_id, h_area in have.get('areas', {}).items():
            res = cw_mrg(res, self._rmmod.compare(state, parsers,
                                                  {'area': {}},
                                                  {'area': h_area}))
            if state in ['deleted', 'replaced']:
                res = cw_mrg(res, self._delete_area(h_area))
        return res

    def _compare_default_information(self, _state, want, have):
        res = {'commands': [], 'warnings': []}
        if self._rmmod.get_from_dict(want, 'default_information.originate'):
            wdi = self._rmmod.get_from_dict(want, 'default_information')
            hdi = self._rmmod.get_from_dict(have, 'default_information')
            if wdi != hdi:
                res = cw_mrg(res, self._rmmod.render(want,
                                                     'default_information',
                                                     False))
        else:
            res = cw_mrg(res, self._rmmod.render(have,
                                                 'default_information',
                                                 True))
        return res

    def _delete_area(self, area):
        res = {'commands': [], 'warnings': []}
        for ifilter in area.get('filters', []):
            data = {'area': area['area'], 'filter': ifilter}
            res = cw_mrg(res, self._rmmod.render(data, 'area.filter', True))
        for _rid, arange in area.get('ranges', {}).items():
            data = {'area': area['area'], 'range': arange['range']}
            res = cw_mrg(res, self._rmmod.render(data, 'area.range', True))
        res = cw_mrg(res, self._rmmod.render({'area': area}, 'area', True))
        return res
