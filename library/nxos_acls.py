#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#############################################
#                WARNING                    #
#############################################
#
# This file is auto generated by the resource
#   module builder playbook.
#
# Do not edit this file manually.
#
# Changes to this file will be over written
#   by the resource module builder.
#
# Changes should be made in the model used to
#   generate this file or in the resource module
#   builder template.
#
#############################################

"""
The module file for nxos_acls
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
  'metadata_version': '1.1',
  'status': ['preview'],
  'supported_by': 'network'
}

DOCUMENTATION = """
---
module: nxos_acls
version_added: 2.9
short_description: Manage named ACLs on NX-OS
description: Manage Manage named ACLs on NX-OS
author: Bradley Thornton (cidrblock)
notes:
  - Tested against <network_os> 7.3.(0)D1(1) on VIRL
options:
  config:
    description: A list of ACLs
    type: list
    elements: dict
    suboptions:
      name:
        description: The name of the ACL
        type: str
      entries:
        description: The entries within the ACL
        elements: dict
        type: list
        suboptions:
          action:
            type: str
          additional_parameters:
            type: str
          destination:
            type: dict
            suboptions:
              address:
                type: str
              addrgroup:
                type: str
              any:
                type: bool
              port_protocol:
                type: dict
                suboptions:
                  eq:
                    type: str
                  gt:
                    type: str
                  lt:
                    type: str
                  neq:
                    type: str
                  portgroup:
                    type: str
                  range:
                    type: dict
                    suboptions:
                      start:
                        type: str
                      end:
                        type: str
              prefix:
                type: str
              wildcard_bits:
                type: str
          log:
            type: bool
          match:
            type: dict
            suboptions:
              ack:
                type: bool
              dscp:
                type: str
              established:
                type: bool
              fin:
                type: bool
              http_method:
                type: str
              packet_length:
                type: dict
                suboptions:
                  eq:
                    type: int
                  gt:
                    type: int
                  lt:
                    type: int
                  neq:
                    type: int
                  range:
                    type: dict
                    suboptions:
                      start:
                        type: int
                      end:
                        type: int
              precedence:
                type: str
              psh:
                type: bool
              rst:
                type: bool
              syn:
                type: bool
              ttl:
                type: int
              udf:
                type: list
                elements: dict
                suboptions:
                  mask:
                    type: str
                  name:
                    type: str
                  value:
                    type: str
              urg:
                type: bool
              vlan:
                type: str
          protocol:
            type: str
          remark:
            type: str
          sequence:
            required: True
            type: int
          source:
            type: dict
            suboptions:
              address:
                type: str
              addrgroup:
                type: str
              any:
                type: bool
              port_protocol:
                type: dict
                suboptions:
                  eq:
                    type: str
                  gt:
                    type: str
                  lt:
                    type: str
                  neq:
                    type: str
                  portgroup:
                    type: str
                  range:
                    type: dict
                    suboptions:
                      start:
                        type: str
                      end:
                        type: str
              prefix:
                type: str
              wildcard_bits:
                type: str
  state:
    description:
      - The state the configuration should be left in.
    type: str
    choices:
      - deleted
      - gathered
      - merged
      - overridden
      - rendered
      - replaced
    default: merged
"""
EXAMPLES = """












"""
RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The resulting configuration model invocation.
  returned: when changed
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.nxos.argspec.acls.acls import AclsArgs
from ansible.module_utils.network.nxos.config.acls.acls import Acls


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=AclsArgs.argument_spec,
                           supports_check_mode=True)

    result = Acls(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()