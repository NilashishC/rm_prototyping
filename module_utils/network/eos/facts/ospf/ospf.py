#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The nxos snmp fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from ansible.module_utils.network. \
    eos.facts.base import FactsBase
from ansible.module_utils.network. \
    eos.rm_templates.ospf import OspfTemplate
from ansible.module_utils.network.common.utils import dict_merge


class OspfFacts(FactsBase):
    """ The nxos snmp fact class
    """

    def populate_facts(self, module, connection):
        """ Populate the facts for snmp
        :param module: the module instance
        :param connection: the device connection
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """

        data = connection.get('sho run | section ospf')
        ospf = OspfTemplate(lines=data.splitlines())
        current = ospf.parse()

        current = dict_merge(self.generated_spec, current)
        current = self.generate_final_config(current)

        # convert some of the dicts to lists
        for key, sortv in [('processes', 'id')]:
            if key in current and current[key]:
                current[key] = current[key].values()
                current[key] = sorted(current[key],
                                      key=lambda k, sk=sortv: k[sk])

        for process in current.get('processes', []):
            if 'areas' in process:
                process['areas'] = process['areas'].values()
                process['areas'] = sorted(process['areas'],
                                          key=lambda k, sk='area': k[sk])
                for area in process['areas']:
                    if 'ranges' in area:
                        area['ranges'] = sorted(area['ranges'],
                                                key=lambda k, s='range': k[s])
                    if 'filters' in area:
                        area['filters'].sort()

        self.ansible_facts['ansible_network_resources'].pop('ospf', None)
        facts = {}
        if current:
            facts['ospf'] = dict(sorted(current.items()))

        self.ansible_facts['ansible_network_resources'].update(facts)
        return self.ansible_facts
