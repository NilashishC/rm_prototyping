
from copy import deepcopy
from ansible.module_utils.connection import Connection
from ansible.module_utils.network.common.utils import remove_empties, to_list
from ansible.module_utils.network.common.rm_module_render import RmModuleRender
from ansible.module_utils.network.common.rm_utils import get_from_dict

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

        self.before = deepcopy(self.get_facts(self._empty_fact_val))
        self.changed = False
        self.commands = []
        self.warnings = []

        self.state = self._module.params['state']
        self.have = deepcopy(self.before)
        self.want = remove_empties(
            self._module.params).get('config', self._empty_fact_val)
        super(RmModule, self).__init__(tmplt=self._tmplt)

    @property
    def result(self):
        """ result
        """
        if self.state == 'gathered':
            after = self._empty_fact_val
        else:
            after = self.get_facts(self._empty_fact_val)
        result = {'after': after,
                  'changed': self.changed,
                  'commands': self.commands,
                  'before': self.before,
                  'warnings': self.warnings}
        return result

    def addcmd(self, data, tmplt, negate=False):
        """ addcmd
        """
        command = self.render(data, tmplt, negate)
        if command:
            self.commands.append(command)

    def addcmd_first_found(self, data, tmplts, negate=False):
        """ addcmd first found
        """
        for pname in tmplts:
            before = len(self.commands)
            self.addcmd(data, pname, negate)
            if len(self.commands) != before:
                break

    def get_facts(self, empty_val=None):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        if empty_val is None:
            empty_val = []
        facts, _warnings = self._facts_module.get_facts(
            resource_facts_type=[self._resource])

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

    def compare(self, parsers, want=None, have=None):
        """ compare
        """
        if want is None:
            want = self.want
        if have is None:
            have = self.have
        for parser in to_list(parsers):
            compval = self.get_parser(parser).get('compval')
            if not compval:
                compval = parser
            inw = get_from_dict(want, compval)
            inh = get_from_dict(have, compval)
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
