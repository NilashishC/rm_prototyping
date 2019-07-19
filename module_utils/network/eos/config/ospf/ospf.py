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

from ansible.module_utils.network.eos.rm_templates.ospf import OspfTemplate
from ansible.module_utils.network.common.utils import dict_merge
from ansible.module_utils.network.eos.facts.facts import Facts
from ansible.module_utils.network.common.rm_module import RmModule

import q

class Ospf(RmModule):
    """
    The eos_ospf class
    """
    def __init__(self, module):
        super(Ospf, self).__init__(empty_fact_val={}, facts_module=Facts(),
                                   module=module, resource='ospf',
                                   tmplt=OspfTemplate())

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        self.gen_config()
        self.run_commands()
        return self.result

    def gen_config(self):
        """ Select the appropriate function based on the state provided

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """

        wantd = {(entry['id'], entry.get('vrf')): entry
                 for entry in self.want.get('processes', [])}
        haved = {(entry['id'], entry.get('vrf')): entry
                 for entry in self.have.get('processes', [])}

        # turn all lists of dicts into dicts prior to merge
        for thing in wantd, haved:
            for _pid, proc in thing.items():
                for area in proc.get('areas', []):
                    area['ranges'] = {entry['range']: entry
                                      for entry in area.get('ranges', [])}
                proc['areas'] = {entry['area']: entry
                                 for entry in proc.get('areas', [])}

        # if state is merged, merge want onto have
        if self.state == 'merged':
            wantd = dict_merge(haved, wantd)

        # if state is deleted, limit the have to anything in want
        # set want to nothing
        if self.state == 'deleted':
            haved = {k: v for k, v in haved.items()
                     if k in wantd or not wantd}
            wantd = {}

        # delete processes first so we do run into "more than one" errs
        if self.state in ['overridden', 'deleted']:
            for k, have in haved.items():
                if k not in wantd:
                    self._compare_process(want={}, have=have)
                    self.addcmd(have, 'process_id', True)

        for k, want in wantd.items():
            self._compare_process(want=want, have=haved.pop(k, {}))

    def _compare_process(self, want, have):
        # begin = len(self.commands)
        parsers = ['adjacency.exchange_start.threshold',
                   'auto_cost.reference_bandwidth', 'bfd.all_interfaces',
                   'compatible.rfc1583', 'distance.external',
                   'distance.intra_area', 'distance.inter_area',
                   'distribute_list', 'dn_bit_ignore']

        self.addcmd(want or have, 'process_id', False)
        self.compare(parsers=parsers, want=want, have=have)
        self._compare_areas(want=want, have=have)
        self._compare_default_information(want, have)
        # if len(self.commands) != begin:
        #     self.commands.insert(begin, self.render(want or have,
        #                                             'process_id', False)[0])

    def _compare_areas(self, want, have):
        wareas = want.get('areas', {})
        hareas = have.get('areas', {})
        for name, entry in wareas.items():
            self._compare_area(want=entry, have=hareas.pop(name, {}))
        for name, entry in hareas.items():
            self._delete_area(entry)

    def _compare_area(self, want, have):
        parsers = ['area.default_cost', 'area.no_summary', 'area.nssa_only']
        self.compare(parsers=parsers, want=want, have=have)

        match_keys = ['type', 'default_information']
        if not self.compare_subdict(want, have, match_keys):
            if want.get('default_information', {}).get('originate'):
                self.addcmd(want, 'area.default_information', False)
            elif want.get('no_summary') is not True:
                self.addcmd(want, 'area', False)

        self._compare_area_filters(want, have)
        self._compare_area_ranges(want, have)

    def _compare_area_filters(self, want, have):
        wantd = {filter: {"area": want['area'], "filter": filter}
                 for filter in want.get('filters', [])}
        haved = {filter: {"area": have['area'], "filter": filter}
                 for filter in have.get('filters', [])}

        for name, entry in wantd.items():
            if entry != haved.pop(name, {}):
                self.addcmd(entry, 'area.filter', False)

        for name, entry in haved.items():
            self.addcmd(entry, 'area.filter', True)

    def _compare_area_ranges(self, want, have):
        wranges = want.get('ranges', {})
        hranges = have.get('ranges', {})
        for name, entry in wranges.items():
            if entry != hranges.pop(name, {}):
                entry['area'] = want['area']
                self.addcmd(entry, 'area.range', False)

        for name, entry in hranges.items():
            entry['area'] = have['area']
            self.addcmd(entry, 'area.range', True)

    def _compare_default_information(self, want, have):
        if self.get_from_dict(want, 'default_information.originate'):
            wdi = self.get_from_dict(want, 'default_information')
            hdi = self.get_from_dict(have, 'default_information')
            if wdi != hdi:
                self.addcmd(want, 'default_information', False)
        else:
            self.addcmd(have, 'default_information', True)

    def _delete_area(self, area):
        for ifilter in area.get('filters', []):
            area['filter'] = ifilter
            self.addcmd(area, 'area.filter', True)
        for _rid, arange in area.get('ranges', {}).items():
            area['range'] = arange['range']
            self.addcmd(area, 'area.range', True)
        self.addcmd(area, 'area.default_cost', True)
        self.addcmd(area, 'area', True)
