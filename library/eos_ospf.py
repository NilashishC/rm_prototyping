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
The module file for eos_ospf
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type  # pylint: disable=C0103

ANSIBLE_METADATA = {
  'metadata_version': '1.1',
  'status': ['preview'],
  'supported_by': 'network'
}

DOCUMENTATION = """
---
module: eos_ospf
version_added: 2.9
short_description: Manage the OSPF configuration on EOS
description: Manage the OSPF configuration on EOS
author: Bradley Thornton (cidrblock)
notes:
  - Tested against EOS 4.21.1.1F
options:
  config:
    description: A list of OSPF processes
    type: dict
    suboptions:
      processes:
        description:
        - A list of OSPF proccesses
        type: list
        elements: dict
        suboptions:
          adjacency:
            description: Configure adjacency options for OSPF instance
            type: dict
            suboptions:
              exchange_start:
                description: Configure exchange-start options for OSPF instance
                type: dict
                suboptions:
                  threshold:
                    description: Configure the maximum threshold of EXCH-START peers to bring up simultaneously
                    type: int
          areas:
            description: Configure OSPF areas
            type: list
            elements: dict
            suboptions:
              area:
                description: The OSPF area
                type: str
              default_cost:
                description: Specify the cost for default summary route in stub/NSSA area
                type: int
              default_information:
                description: Configure default Type 7 LSA
                type: dict
                suboptions:
                  metric:
                    description: Metric for default route
                    type: int
                  metric_type:
                    description: Metric type for default route
                    type: int
                    choices: [1,2]
                  nssa_only:
                    description: Limit default advertisement to this NSSA area
                    type: bool
                  originate:
                    description: Originate default Type 7 LSA
                    type: bool
              filters:
                description: Specify filters for incoming summary LSAs
                type: list
                elements: str
              no_summary:
                description: Filter all type-3 LSAs in the area
                type: bool
              nssa_only:
                description: Disable Type-7 LSA p-bit setting
                type: bool
              ranges:
                description: Configure route summarization
                type: list
                elements: dict
                suboptions:
                  cost:
                    description: Configure the metric
                    type: int
                  not_advertise:
                    description: Disable Advertisement of the range
                    type: bool
                  range:
                    description: The range for summarization
                    type: str
              type:
                description: The area type (stub/NSSA)
                type: str
          auto_cost:
            description: Set auto-cost
            type: dict
            suboptions:
              reference_bandwidth:
                description: Set the reference bandwidth
                type: int
          bfd:
            description: Enable BFD
            type: dict
            suboptions:
              all_interfaces:
                description: Enable BFD on all interfaces
                type: bool
          compatible:
            description: Set compatibility
            type: dict
            suboptions:
              rfc1583:
                description: Compatible with RFC 1583
                type: bool
          default_information:
            description: Control distribution of default information
            type: dict
            suboptions:
              always:
                description: Always advertise default route
                type: bool
              metric:
                description: Metric for default route
                type: int
              metric_type:
                description: Metric type for default route
                type: int
                choices: [1,2]
              originate:
                description: Originate default Type 7 LSA
                type: bool
              route_map:
                description: Specify which route map to use
                type: str
          distance:
            description: Configure administrative distance
            type: dict
            suboptions:
              external:
                description: Routes external to the area
                type: int
              inter_area:
                description: Routes from other areas
                type: int
              intra_area:
                description: Routes within an area
                type: int
          distribute_list:
            description: Specify the inbound distribute-list
            type: dict
            suboptions:
              name:
                description: Specify the name for the distribute list
                type: str
              type:
                description: Specify the type of distribute list
                type: str
                choices: ['prefix-list', 'route-map']
          id:
            description: The process ID
            type: int
          vrf:
            description: The VPN Routing/Forwarding Instance
            type: str

  state:
    description:
      - The state the configuration should be left in.
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - deleted
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


# pylint: disable=C0413
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network. \
    eos.config.ospf.ospf import Ospf
# pylint: enable=C0413


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Ospf.argument_spec,
                           supports_check_mode=True)

    result = Ospf(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()