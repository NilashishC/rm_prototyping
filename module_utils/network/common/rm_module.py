

from functools import reduce  # forward compatibility for Python 3
import operator
from copy import deepcopy

from ansible.module_utils.connection import Connection
from ansible.module_utils.network.common.utils import remove_empties
from ansible.module_utils.network.common.rm_module_render import RmModuleRender


class RmModule(RmModuleRender):  # pylint: disable=R0902
    """ rm
    """
    def __init__(self, *_args, **kwargs):
        self._empty_fact_val = kwargs.get('empty_fact_val', [])
        self._facts_module = kwargs.get('facts_module', None)
        self._gather_subset = kwargs.get('gather_subset', ['!all', '!min'])
        self._module = kwargs.get('module', None)
        self._resource = kwargs.get('resource', None)
        self._tmplt = kwargs.get('tmplt', None)

        self._connection = None
        self._get_connection()

        self.after = None
        self.before = deepcopy(self.get_facts(self._empty_fact_val))
        self.changed = False
        self.commands = []
        self.warnings = []

        self.state = self._module.params['state']
        self.have = deepcopy(self.before)
        self.want = remove_empties(self._module.params['config'])
        super(RmModule, self).__init__(tmplt=self._tmplt)

    @property
    def result(self):
        """ result
        """
        result = {'after': self.get_facts(self._empty_fact_val),
                  'changed': self.changed,
                  'commands': self.commands,
                  'before': self.before,
                  'warnings': self.warnings}
        return result

    def addcmd(self, data, tmplts, negate=False):
        """ addcmd
        """
        self.commands.extend(self.render(data, tmplts, negate))

    def get_facts(self, empty_val=None):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        if empty_val is None:
            empty_val = []
        facts, _warnings = self._facts_module.get_facts(self._module,
                                                        self._connection,
                                                        self._gather_subset,
                                                        [self._resource])
        facts = facts['ansible_network_resources'].get(self._resource)
        if not facts:
            return empty_val
        return facts

    def _get_connection(self):
        if self._connection:
            return self._connection
        # pylint: disable=W0212
        self._connection = Connection(self._module._socket_path)
        # pylint: enable=W0212
        return self._connection

    @staticmethod
    def get_from_dict(data_dict, keypath):
        """ get from dictionary
        """
        map_list = keypath.split('.')
        try:
            return reduce(operator.getitem, map_list, data_dict)
        except KeyError:
            return None

    @staticmethod
    def compare_subdict(want, have, compare_keys):
        """ compare
        """
        rmkeys = [ckey[1:] for ckey in compare_keys if ckey.startswith('!')]
        kkeys = [ckey for ckey in compare_keys if not ckey.startswith('!')]
        kkeys = kkeys or 'all'

        wantd = {}
        for key, val in want.items():
            if key not in rmkeys:
                if key in kkeys or kkeys == 'all':
                    wantd[key] = val

        haved = {}
        for key, val in have.items():
            if key not in rmkeys:
                if key in kkeys or kkeys == 'all':
                    haved[key] = val
        return wantd == haved

    def compare(self, parsers, want=None, have=None):
        """ compare
        """
        if want is None:
            want = self.want
        if have is None:
            have = self.have
        for parser in parsers:
            compval = self._tmplt.PARSERS[parser].get('compval')
            if not compval:
                compval = parser
            inw = self.get_from_dict(want, compval)
            inh = self.get_from_dict(have, compval)
            if inw is not None and inw != inh:
                if isinstance(inw, bool):
                    self.addcmd(want, parser, not inw)
                else:
                    self.addcmd(want, parser, False)
            elif inw is None and inh is not None:
                if isinstance(inh, bool):
                    self.addcmd(have, parser, inh)
                else:
                    self.addcmd(have, parser, True)

    def run_commands(self):
        """ run_commands
        """
        if self.commands:
            if not self._module.check_mode:
                response = self._connection.edit_config(self.commands)
                self.warnings.extend([r for r in response['response'] if r])
                self.changed = True
