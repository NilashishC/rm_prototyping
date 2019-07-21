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
from ansible.module_utils.network.common.rm_utils \
  import get_from_dict, compare_partial_dict


class Ospf(RmModule):
    """
    The eos_ospf class
    """
    def __init__(self, module):
        super(Ospf, self).__init__(empty_fact_val={},
                                   facts_module=Facts(module),
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
                    self._compare(want={}, have=have)
                    self.addcmd(have, 'process_id', True)

        for k, want in wantd.items():
            self._compare(want=want, have=haved.pop(k, {}))

    def _compare(self, want, have):
        # begin = len(self.commands)
        parsers = ['adjacency.exchange_start.threshold',
                   'auto_cost.reference_bandwidth', 'bfd.all_interfaces',
                   'compatible.rfc1583', 'distance.external',
                   'distance.intra_area', 'distance.inter_area',
                   'distribute_list', 'dn_bit_ignore',
                   'graceful_restart.helper']

        self.addcmd(want or have, 'process_id', False)
        self.compare(parsers=parsers, want=want, have=have)
        self._areas_compare(want=want, have=have)
        self._default_information_compare(want, have)
        self._graceful_restart_compare(want, have)

    def _areas_compare(self, want, have):
        wareas = want.get('areas', {})
        hareas = have.get('areas', {})
        for name, entry in wareas.items():
            self._area_compare(want=entry, have=hareas.pop(name, {}))
        for name, entry in hareas.items():
            self._area_delete(entry)

    def _area_compare(self, want, have):
        parsers = ['area.default_cost', 'area.no_summary', 'area.nssa_only']
        self.compare(parsers=parsers, want=want, have=have)

        match_keys = ['type', 'default_information']
        if not compare_partial_dict(want, have, match_keys):
            if want.get('default_information', {}).get('originate'):
                self.addcmd(want, 'area.default_information', False)
            elif want.get('no_summary') is not True:
                self.addcmd(want, 'area', False)

        self._area_compare_filters(want, have)
        self._area_compare_ranges(want, have)

    def _area_compare_filters(self, want, have):
        wantd = {filter: {"area": want['area'], "filter": filter}
                 for filter in want.get('filters', [])}
        haved = {filter: {"area": have['area'], "filter": filter}
                 for filter in have.get('filters', [])}

        for name, entry in wantd.items():
            if entry != haved.pop(name, {}):
                self.addcmd(entry, 'area.filter', False)

        for name, entry in haved.items():
            self.addcmd(entry, 'area.filter', True)

    def _area_compare_ranges(self, want, have):
        wranges = want.get('ranges', {})
        hranges = have.get('ranges', {})
        for name, entry in wranges.items():
            if entry != hranges.pop(name, {}):
                entry['area'] = want['area']
                self.addcmd(entry, 'area.range', False)

        for name, entry in hranges.items():
            entry['area'] = have['area']
            self.addcmd(entry, 'area.range', True)

    def _area_delete(self, area):
        for ifilter in area.get('filters', []):
            area['filter'] = ifilter
            self.addcmd(area, 'area.filter', True)
        for _rid, arange in area.get('ranges', {}).items():
            area['range'] = arange['range']
            self.addcmd(area, 'area.range', True)
        self.addcmd(area, 'area.default_cost', True)
        self.addcmd(area, 'area', True)

    def _default_information_compare(self, want, have):
        inw = want.get('default_information', {})
        inh = have.get('default_information', {})
        if inw not in (inh, {}):
            self.addcmd(want, 'default_information', not inw.get('originate'))
        else:
            self.addcmd(have, 'default_information', inh.get('originate'))

    def _graceful_restart_compare(self, want, have):
        inw = want.get('graceful_restart', {})
        inh = have.get('graceful_restart', {})
        match_keys = ['enable', 'grace_period']
        if not compare_partial_dict(inw, inh, match_keys):
            if any([inw.get(match_key) is not None
                    for match_key in match_keys]):
                self.addcmd(want, 'graceful_restart', not inw.get('enable'))
            else:
                self.addcmd(have, 'graceful_restart', inh.get('enable'))
