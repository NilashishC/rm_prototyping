#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The ios_interfaces class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from ansible.module_utils.network.ios.facts.facts import Facts
from ansible.module_utils.network.ios.rm_templates.interfaces \
  import InterfacesTemplate
from ansible.module_utils.network.common.utils import dict_merge
from ansible.module_utils.network.common.rm_module import RmModule

import q

class Interfaces(RmModule):
    """
    The ios_interfaces class
    """
    def __init__(self, module):
        super(Interfaces, self).__init__(empty_fact_val={},
                                         facts_module=Facts(module),
                                         module=module, resource='interfaces',
                                         tmplt=InterfacesTemplate())

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
        wantd = {entry['name']: entry for entry in self.want}
        haved = {entry['name']: entry for entry in self.have}

        # add a shutdown key for easier processing
        for thing in wantd, haved:
            for _name, entry in thing.items():
                if entry.get('enable', None) is False:
                    entry['shutdown'] = True

        # if state is merged, merge want onto have
        if self.state == 'merged':
            wantd = dict_merge(haved, wantd)

        # if state is deleted, limit the have to anything in want
        # set want to nothing
        if self.state == 'deleted':
            haved = {k: v for k, v in haved.items()
                     if k in wantd or not wantd}
            wantd = {}

        # handle everything common to want and have
        for k, want in wantd.items():
            self._compare_interface(want=want, have=haved.pop(k, {}))

        # anything left in have can be deleted
        for k, have in haved.items():
            if k not in wantd:
                self._compare_interface(want={}, have=have)

    def _compare_interface(self, want, have):
        parsers = ['description', 'duplex', 'mtu', 'shutdown', 'speed']
        begin = len(self.commands)
        self.compare(parsers=parsers, want=want, have=have)
        if len(self.commands) != begin:
            self.commands.insert(begin, self.render(want or have,
                                                    'interface',
                                                    False))
