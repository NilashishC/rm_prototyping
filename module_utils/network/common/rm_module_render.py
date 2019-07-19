
class RmModuleRender(object):
    def __init__(self, tmplt):
        self._tmplt = tmplt

    def get_parser(self, name):
        res = [p for p in self._tmplt.PARSERS if p['name'] == name]
        return res[0]

    @staticmethod
    def _render(tmplt, data, negate):
        if callable(tmplt):
            res = tmplt(data)
        else:
            res = tmplt.format(**data)
        if negate:
            return 'no ' + res
        return res

    def render(self, data, parser_name, negate=False):
        try:
            if negate:
                tmplt = self.get_parser(parser_name).get('remval') or \
                        self.get_parser(parser_name)['setval']
            else:
                tmplt = self.get_parser(parser_name)['setval']
            command = self._render(tmplt, data, negate)
        except KeyError:
            command = None
        return command
