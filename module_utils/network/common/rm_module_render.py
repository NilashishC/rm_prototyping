
class RmModuleRender(object):
    def __init__(self, tmplt):
        self._tmplt = tmplt

    def render(self, data, parser_names, negate=False):
        if not isinstance(parser_names, list):
            parser_names = [parser_names]
        commands = []
        warnings = []
        for pname in parser_names:
            try:
                if negate:
                    tmplt = self._tmplt.PARSERS[pname].get('remval')
                    if tmplt:
                        if callable(tmplt):
                            res = tmplt(data)
                        else:
                            res = tmplt.format(**data)
                    else:
                        tmplt = self._tmplt.PARSERS[pname]['setval']
                        if callable(tmplt):
                            res = 'no ' + tmplt(data)
                        else:
                            res = 'no ' + tmplt.format(**data)
                else:
                    tmplt = self._tmplt.PARSERS[pname]['setval']
                    if callable(tmplt):
                        res = tmplt(data)
                    else:
                        res = tmplt.format(**data)
                commands.append(res)
            except KeyError:
                pass
        return {'commands': commands, 'warnings': warnings}
