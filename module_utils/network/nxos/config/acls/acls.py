#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The nxos_acls class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from copy import deepcopy
from ansible.module_utils.network.nxos.rm_templates.acls import ACLsTemplate
from ansible.module_utils.network.common.utils import dict_merge
from ansible.module_utils.network.nxos.facts.facts import Facts
from ansible.module_utils.network.common.rm_module import RmModule
from ansible.module_utils.network.common.utils import validate_config
from ansible.module_utils.network.nxos.argspec.acls.acls import AclsArgs
from collections import OrderedDict

from ansible.module_utils.network.common.rm_utils \
    import get_from_dict, compare_partial_dict
class Acls(RmModule):
    """
    The nxos_acls class
    """

    def __init__(self, module):
        super(Acls, self).__init__(empty_fact_val=[],
                                   facts_module=Facts(module),
                                   module=module, resource='acls',
                                   tmplt=ACLsTemplate())

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        self.gen_config()
        self.run_commands()
        return self.result

    @staticmethod
    def xform(data):
        """ tranform the lists into dictionaries
            keyed by there uid
            acls, keyed by acl name
            entries, keyed by their sequence
            udf, keyed by their name
        """
        xfrmd = {entry['name']: entry for entry in data}
        for _name, acl in xfrmd.items():
            for entry in acl.get('entries', []):
                if 'match' in entry and 'udf' in entry['match']:
                    entry['match']['udf'] = {udf['name']: udf
                                             for udf in entry['match']['udf']}
            acl['entries'] = {entry['sequence']: entry for entry in acl.get('entries', [])}
            # sort the entries by key so commands are applied in order
            acl['entries'] = OrderedDict(sorted(acl['entries'].items()))
        return xfrmd

    @staticmethod
    def deform(data):
        """ revert the changes made in xform
            this is necessary so we can pass the merged want + have
            back through the argspec to make sure we're not
            working with invalid data
        """

        xfrmd = list(data.values())
        for acl in xfrmd:
            acl['entries'] = list(acl['entries'].values())
            for entry in acl['entries']:
                if 'match' in entry and 'udf' in entry['match']:
                    entry['match']['udf'] = list(entry['match']['udf'].values())
        return xfrmd

    def gen_config(self):
        wantd = self.xform(self.want)
        haved = self.xform(self.have)

        # if state is merged, merge want onto have
        if self.state == 'merged':
            wantd = deepcopy(dict_merge(haved, wantd))
            # validate the merged data through the argument_spec
            validate_config(
                AclsArgs.argument_spec, {
                    "config": self.deform(deepcopy(wantd))}
            )

        # if state is deleted, limit the have to anything in want
        # set want to nothing
        if self.state == 'deleted':
            haved = {k: v for k, v in haved.items()
                     if k in wantd or not wantd}
            wantd = {}

        # handle everything common to want and have
        for k, want in wantd.items():
            self._compare_acl(want=want, have=haved.pop(k, {}))

        # anything left should be deleted if deleted or overridden
        if self.state in ['deleted', 'overridden']:
            for k, have in haved.items():
                self.addcmd(have, 'name', True)

    def _compare_acl(self, want, have):
        begin = len(self.commands)
        for k, wentry in want.get('entries', {}).items():
            hentry = have.get('entries', {}).pop(k, {})
            if wentry != hentry:
                if hentry:
                    self._render_entry(hentry, True)
                self._render_entry(wentry, False)
        for k, hentry in have.get('entries', {}).items():
            self._render_entry(hentry, True)
        if len(self.commands) != begin:
            self.commands.insert(begin, self.render(want or have,
                                                    'name',
                                                    False))

    def _render_entry(self, entry, negate):
        if 'remark' in entry:
            self.addcmd(entry, 'remark', negate)
        else:
            self.addcmd(entry, 'entry', negate)
