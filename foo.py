import ansible_runner
from pprint import pprint
import yaml
import json
from functools import reduce
import operator


def dict_get(data_dict, keypath):
    map_list = keypath.split('.')
    try:
        return reduce(operator.getitem, map_list, data_dict)
    except KeyError:
        return None

class Playbook(object):
    def __init__(self, hosts='all', gather_facts=False):
        self.hosts = hosts
        self.gather_facts = gather_facts
        self.tasks = []

class Task(object):
    def __init__(self, module, config=None, state='merged'):
        self.module = module
        self.config = config
        self.state = state

playbook = Playbook()

playbook.tasks.append(Task(module='eos_ospf', state='deleted'))

print(playbook.__dict__)

print(yaml.dump(playbook))
