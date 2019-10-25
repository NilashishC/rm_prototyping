#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The nxos acls fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from copy import deepcopy
import re
from ansible.module_utils.network.nxos.rm_templates.acls import ACLsTemplate
from ansible.module_utils.network.common import utils
from ansible.module_utils.network.common.rm_module_parse import RmModuleParse
from ansible.module_utils.network.nxos.argspec.acls.acls import AclsArgs


class AclsFacts(object):
    """ The nxos acls fact class
    """

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = AclsArgs.argument_spec
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
        """ Populate the facts for acls
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        data = connection.get("show running-config | section 'ip access-list'")
        rmmod = RmModuleParse(lines=data.splitlines(), tmplt=ACLsTemplate())
        current = rmmod.parse()

        objs = list(current.values())
        for obj in objs:
            if 'entries' in obj:
                obj['entries'] = list(obj['entries'].values())
                for entry in obj['entries']:
                    if 'match' in entry:
                        if 'udf' in entry['match']:
                            entry['match']['udf'] = [{'name': x[0],
                                                      'value': x[1],
                                                      'mask': x[2]}
                                                     for x in [y.split() for y in re.findall(r'\S+\s\S+\s\S+', entry['match']['udf'].strip())]]

        # Sort the ACLs by name
        objs = sorted(objs, key=lambda k, sk='name': k[sk])

        # Sort the ACEs
        for obj in objs:
            if 'entries' in obj:
                obj['entries'] = sorted(obj['entries'],
                                        key=lambda k, sk='sequence': k[sk])

        ansible_facts["ansible_network_resources"].pop("acls", None)
        facts = {}
        if objs:
            objs = utils.remove_empties({"config": objs})
            params = utils.validate_config(
                self.argument_spec, objs
            )
            params = utils.remove_empties(params)
            facts["acls"] = params["config"]

        ansible_facts["ansible_network_resources"].update(facts)
        return ansible_facts
