#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The ios interfaces fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
import re
from copy import deepcopy

from ansible.module_utils.network.common import utils
from ansible.module_utils.network.ios.argspec.interfaces.interfaces \
    import InterfacesArgs

from ansible.module_utils.network. \
    ios.rm_templates.interfaces import InterfacesTemplate
from ansible.module_utils.network.common.rm_module_parse import RmModuleParse


class InterfacesFacts(object):
    """ The ios interfaces fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = InterfacesArgs.argument_spec
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
        data = connection.get('sho run | section interface')
        rmmod = RmModuleParse(lines=data.splitlines(),
                              tmplt=InterfacesTemplate())
        current = rmmod.parse().values()

        for interface in current:
            if 'enable' not in interface:
                interface['enable'] = True

        ansible_facts['ansible_network_resources'].pop('interfaces', None)
        facts = {}
        if current:
            params = utils.validate_config(self.argument_spec,
                                           {'config': current})
            params = utils.remove_empties(params)

            facts['interfaces'] = params['config']

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts
