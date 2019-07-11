""" ansible runner demo
"""
from functools import reduce
import operator
import yaml
import ansible_runner


def dict_get(data_dict, keypath):
    map_list = keypath.split('.')
    try:
        return reduce(operator.getitem, map_list, data_dict)
    except KeyError:
        return None


INVENTORY = {
    "all": {
        "hosts": {
            "eos101": {
                "ansible_network_os": "eos",
                "ansible_user": "admin",
                "ansible_password": "password",
                "ansible_become_pass": "password",
                "ansible_become": True,
                "ansible_become_method": "enable",
                "ansible_facts_modules": "eos_facts",
                "ansible_connection": "network_cli"
            }
        }
    }
}

PLAYBOOK = {
    "hosts": "all",
    "gather_facts": False,
    "tasks": [
        {"eos_ospf": {'state': 'deleted'}},
        {"eos_ospf": {
            "config": {
                "processes": [{
                    "id": 200,
                    "vrf": "blue",
                    "auto_cost": {
                        "reference_bandwidth": 1000
                    }
                }]
            }
        }},
        {"eos_ospf": {'state': 'deleted'}},
    ]
}


ROBJ = {"playbook": [PLAYBOOK],
        "inventory": INVENTORY,
        "quiet": False}


def main():
    """ runnerit
    """
    robj = ansible_runner.run(**ROBJ)
    for event in robj.events:
        if event['event'] in ['runner_on_ok']:
            for resval in ['changed', 'before', 'after']:
                result = dict_get(event, f"event_data.res.{resval}")
                if result is not None:
                    print(f"****** {resval}")
                    print(yaml.dump(result, default_flow_style=False))


if __name__ == '__main__':
    main()
