from ansible.errors import AnsibleUndefinedVariable
import ansible.template


class RmModuleRender(object):
    def __init__(self, tmplt):
        self._tmplt = tmplt
        self._templar = ansible.template.Templar(loader=None)

    def get_parser(self, name):
        """ get_parsers
        """
        res = [p for p in self._tmplt.PARSERS if p['name'] == name]
        return res[0]

    def _render(self, tmplt, data, negate):
        try:
            if callable(tmplt):
                res = tmplt(data)
            else:
                self._templar._available_variables = data
                res = self._templar.do_template(tmplt)
        except (KeyError, AnsibleUndefinedVariable):
            return None
        if negate:
            return 'no ' + res
        return res

    def render(self, data, parser_name, negate=False):
        """ render
        """
        if negate:
            tmplt = self.get_parser(parser_name).get('remval') or \
                    self.get_parser(parser_name)['setval']
        else:
            tmplt = self.get_parser(parser_name)['setval']
        command = self._render(tmplt, data, negate)
        return command
