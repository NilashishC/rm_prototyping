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

from copy import deepcopy

from ansible.module_utils.network. \
    nxos.rm_templates.snmp import SnmpTemplate
from ansible.module_utils.network.common import utils
from ansible.module_utils.network.common.utils import dict_merge
from ansible.module_utils.network.common.rm_module_parse import RmModuleParse
from ansible.module_utils.network.nxos.argspec.snmp.snmp import SnmpArgs


class SnmpFacts(object):
    """ The nxos snmp fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = SnmpArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for interfaces
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """

        data = connection.get('show running-config | i snmp-server')
        rmmod = RmModuleParse(lines=data.splitlines(), tmplt=SnmpTemplate())
        current = rmmod.parse()

        # convert some of the dicts to lists
        for key, sortv in [('communities', 'community'), ('hosts', 'host'),
                           ('users', 'username'), ('traps', 'type')]:
            if key in current and current[key]:
                current[key] = current[key].values()
                current[key] = sorted(current[key],
                                      key=lambda k, sk=sortv: k[sk])

        # sort the user's groups
        for user in current.get('users', []):
            if 'groups' in user:
                if not any(user['groups']):
                    user.pop('groups')
                else:
                    user['groups'].sort()

        ansible_facts['ansible_network_resources'].pop('snmp', None)
        facts = {}
        if current:
            params = utils.validate_config(self.argument_spec,
                                           {'config': current})
            params = utils.remove_empties(params)

            facts['snmp'] = params['config']

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts
