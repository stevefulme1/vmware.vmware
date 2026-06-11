#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: esxi_host_info
short_description: Gathers information about ESXi hosts
description:
    - Gathers information about one or more ESXi hosts in vCenter.
    - You can search for hosts based on the host name, datacenter, cluster, or folder.
author:
    - Ansible Cloud Team (@ansible-collections)

options:
    esxi_host_name:
        description:
            - The name of the ESXi host to gather info about.
            - If not provided, all hosts matching other criteria will be returned.
        type: str
        required: false
        aliases: [host_name, name]
    datacenter:
        description:
            - The name of the datacenter.
            - At least one of O(datacenter), O(cluster), O(folder), or O(esxi_host_name) is required.
        type: str
        required: false
        aliases: [datacenter_name]
    cluster:
        description:
            - The name of the cluster.
            - If provided, only hosts in this cluster will be returned.
        type: str
        required: false
        aliases: [cluster_name]
    folder:
        description:
            - Name of the folder containing hosts.
            - Can be an absolute or relative path.
        type: str
        required: false
    folder_paths_are_absolute:
        description:
            - If true, any folder path parameters are treated as absolute paths.
            - If false, modules will try to intelligently determine if the path is absolute or relative.
        type: bool
        required: false
        default: false
    gather_tags:
        description:
            - If true, gather any tags attached to the host(s)
            - This has no affect if the O(schema) is set to V(vsphere). In that case, add 'tag' to O(properties) or leave O(properties) unset.
        type: bool
        default: false
        required: false
    schema:
        description:
            - Specify the output schema desired.
            - The V(summary) output schema is the legacy output from the module.
            - The V(vsphere) output schema is the vSphere API class definition.
        choices: ['summary', 'vsphere']
        default: 'summary'
        type: str
    properties:
        description:
            - If the schema is 'vsphere', gather these specific properties only
        type: list
        elements: str

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options
'''

EXAMPLES = r'''
- name: Gather Information About All Hosts
  vmware.vmware.esxi_host_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
  register: all_hosts

- name: Gather Information About A Specific Host
  vmware.vmware.esxi_host_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    esxi_host_name: esxi-01.example.com
  register: host_info

- name: Gather Information About All Hosts In A Cluster
  vmware.vmware.esxi_host_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    cluster_name: MyCluster
  register: cluster_hosts

- name: Gather Specific Properties About A Host
  vmware.vmware.esxi_host_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    esxi_host_name: esxi-01.example.com
    schema: vsphere
    properties:
      - name
      - summary.hardware.cpuMhz
      - summary.hardware.memorySize
  register: host_info
'''

RETURN = r'''
hosts:
    description:
        - A dictionary that describes the hosts found by the search parameters
        - The keys are the host names and the values are dictionaries with the host info.
    returned: On success
    type: dict
    sample: {
        "hosts": {
            "esxi-01.example.com": {
                "name": "esxi-01.example.com",
                "moid": "host-123",
                "datacenter": "DC01",
                "cluster": "MyCluster",
                "connection_state": "connected",
                "power_state": "poweredOn",
                "maintenance_mode": false,
                "cpu_mhz": 2400,
                "num_cpu_cores": 24,
                "memory_mb": 131072,
                "version": "8.0.0",
                "build": "12345678",
                "tags": []
            }
        }
    }
'''

try:
    from pyVmomi import vim
except ImportError:
    pass
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import (
    ModulePyvmomiBase
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    rest_compatible_argument_spec
)
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import ModuleRestBase
from ansible_collections.vmware.vmware.plugins.module_utils._facts import (
    vmware_obj_to_json
)


class EsxiHostInfo(ModulePyvmomiBase):
    def __init__(self, module):
        super(EsxiHostInfo, self).__init__(module)
        self.rest_client = None
        if module.params['gather_tags']:
            self.rest_client = ModuleRestBase(module)

    def get_hosts(self):
        """
        Gets hosts matching the search parameters input by the user.
        Returns: List of hosts to gather info about
        """
        datacenter, search_folder = None, None

        if self.params.get('datacenter'):
            datacenter = self.get_datacenter_by_name_or_moid(self.params.get('datacenter'), fail_on_missing=True)
            search_folder = datacenter.hostFolder

        if self.params.get('cluster'):
            cluster = self.get_cluster_by_name_or_moid(self.params.get('cluster'), fail_on_missing=True, datacenter=datacenter)
            search_folder = cluster

        if self.params.get('folder'):
            search_folder = self.get_folder_by_absolute_path(
                folder_path=self.params['folder'],
                fail_on_missing=True
            )

        if self.params.get('esxi_host_name'):
            host = self.get_host_by_name_or_moid(
                self.params.get('esxi_host_name'),
                fail_on_missing=False,
                datacenter=datacenter
            )
            return [host] if host else []
        else:
            hosts = self.get_all_objs_by_type(
                [vim.HostSystem],
                folder=search_folder,
                recurse=True
            )
            return hosts

    def gather_info_for_hosts(self):
        """
        Gather information about one or more hosts
        """
        all_host_info = {}
        for host in self.get_hosts():
            host_info = {}
            if self.params['schema'] == 'summary':
                host_info = self._build_summary_info(host)
            else:
                try:
                    host_info = vmware_obj_to_json(host, self.params['properties'])
                except AttributeError as e:
                    self.module.fail_json(str(e))

            all_host_info[host.name] = host_info

        return all_host_info

    def _build_summary_info(self, host):
        """
        Build summary information for a host
        """
        info = {
            'name': host.name,
            'moid': host._moId,
            'connection_state': host.runtime.connectionState,
            'power_state': host.runtime.powerState,
            'maintenance_mode': host.runtime.inMaintenanceMode,
            'tags': self._get_tags(host)
        }

        # Add datacenter
        datacenter = self.get_parent_datacenter(host)
        if datacenter:
            info['datacenter'] = datacenter.name

        # Add cluster if the host is in a cluster
        if host.parent and isinstance(host.parent, vim.ClusterComputeResource):
            info['cluster'] = host.parent.name
        else:
            info['cluster'] = None

        # Add hardware summary
        if host.summary.hardware:
            info['cpu_mhz'] = host.summary.hardware.cpuMhz
            info['num_cpu_cores'] = host.summary.hardware.numCpuCores
            info['memory_mb'] = host.summary.hardware.memorySize / (1024 * 1024)
            info['vendor'] = host.summary.hardware.vendor
            info['model'] = host.summary.hardware.model

        # Add version info
        if host.summary.config:
            info['version'] = host.summary.config.product.version
            info['build'] = host.summary.config.product.build

        return info

    def _get_tags(self, host):
        """
        Gets the tags on a host. Tags are formatted as a list of dictionaries corresponding to each tag
        """
        output = []
        if not self.params.get('gather_tags') or not self.rest_client:
            return output

        tags = self.rest_client.get_tags_by_host_moid(host._moId)
        for tag in tags:
            output.append(self.rest_client.format_tag_identity_as_dict(tag))

        return output


def main():
    module = AnsibleModule(
        argument_spec={
            **rest_compatible_argument_spec(), **dict(
                esxi_host_name=dict(type='str', aliases=['host_name', 'name']),
                datacenter=dict(type='str', aliases=['datacenter_name']),
                cluster=dict(type='str', aliases=['cluster_name']),
                folder=dict(type='str'),
                folder_paths_are_absolute=dict(type='bool', default=False),
                gather_tags=dict(type='bool', default=False),
                schema=dict(type='str', choices=['summary', 'vsphere'], default='summary'),
                properties=dict(type='list', elements='str'),
            )
        },
        supports_check_mode=True,
    )
    if module.params['schema'] != 'vsphere' and module.params.get('properties'):
        module.fail_json(msg="The option 'properties' is only valid when the schema is 'vsphere'")

    host_info = EsxiHostInfo(module)
    hosts = host_info.gather_info_for_hosts()
    module.exit_json(changed=False, hosts=hosts)


if __name__ == '__main__':
    main()
