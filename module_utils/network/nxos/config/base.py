#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The base class for all nxos resource modules
"""

from ansible.module_utils.connection import Connection
from functools import reduce  # forward compatibility for Python 3
import operator


class ConfigBase(object):  # pylint: disable=R0903
    """ The base class for all nxos resource modules
    """
    _connection = None

    def __init__(self, module):
        self._module = module
        self._connection = self._get_connection()

    def _get_connection(self):
        if self._connection:
            return self._connection
        # pylint: disable=W0212
        self._connection = Connection(self._module._socket_path)
        # pylint: enable=W0212
        return self._connection

    @staticmethod
    def _get_from_dict(data_dict, keypath):
        map_list = keypath.split('.')
        try:
            return reduce(operator.getitem, map_list, data_dict)
        except KeyError:
            return None

    @staticmethod
    def _compare_partial_dict(want, have, compare_keys):
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
