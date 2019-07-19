import re
from copy import deepcopy
from ansible.module_utils.network.common.utils import dict_merge

class RmModuleParse(object):
    def __init__(self, lines, tmplt):
        self._lines = lines
        self._tmplt = tmplt

    @staticmethod
    def to_bool(string):
        if string:
            return True
        return False

    @staticmethod
    def to_int(string):
        if string:
            return int(string)
        return None

    @staticmethod
    def no_means_true(string):
        if string == 'no':
            return True
        return False

    @staticmethod
    def no_means_false(string):
        if string == 'no':
            return False
        return True

    @staticmethod
    def true_or_none(string):
        if string:
            return True
        return None

    @staticmethod
    def false_or_none(string):
        if string:
            return False
        return None

    def _deepformat(self, tmplt, data):
        wtmplt = deepcopy(tmplt)

        if isinstance(tmplt, str):
            for dkey, dval in data.items():
                if tmplt == "{{{x}}}".format(x=dkey):
                    return dval

        if isinstance(tmplt, dict):
            for tkey, tval in tmplt.items():
                ftkey = tkey.format(**data)
                if ftkey != tkey:
                    wtmplt.pop(tkey)
                if isinstance(tval, dict):
                    wtmplt[ftkey] = self._deepformat(tval, data)
                elif isinstance(tval, list):
                    wtmplt[ftkey] = [self._deepformat(x, data)
                                     for x in tval]
                elif isinstance(tval, str):
                    for dkey, dval in data.items():
                        if tval == "{{{x}}}".format(x=dkey):
                            wtmplt[ftkey] = dval
                            break
                    if wtmplt[ftkey] == 'None' or wtmplt[ftkey] is None:
                        wtmplt.pop(ftkey)
        return wtmplt

    def parse(self):
        result = {}
        shared = {}
        for line in self._lines:
            for parser in self._tmplt.PARSERS:
                cap = re.match(parser['getval'], line)
                if cap:
                    capdict = cap.groupdict()
                    for key, val in capdict.items():
                        if key in parser.get('cast', {}):
                            capdict[key] = getattr(self,
                                                   parser['cast'][key])(val)
                    if parser.get('shared'):
                        shared = capdict
                    vals = dict_merge(capdict, shared)
                    res = self._deepformat(deepcopy(parser['result']), vals)
                    result = dict_merge(result, res)
                    break
        return result
