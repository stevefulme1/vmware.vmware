#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: tag_associations_info
short_description: Gathers information about tags associated with a vSphere object
description:
    - This module allows you to gather information about tags attached to a vSphere object.

author:
    - Ansible Cloud Team (@ansible-collections)

options:
    object_moid:
        description:
            - The managed object ID (MOID) of the object to query.
            - One of O(object_moid) or O(object_name) is required.
        type: str
        required: false

    object_name:
        description:
            - The name of the object to query.
            - One of O(object_moid) or O(object_name) is required.
        type: str
        required: false

    object_type:
        description:
            - The type of the object to query.
        type: str
        required: true
        choices:
            - VirtualMachine
            - Datacenter
            - ClusterComputeResource
            - HostSystem
            - DistributedVirtualSwitch
            - DistributedVirtualPortgroup
            - Datastore
            - DatastoreCluster
            - ResourcePool
            - Folder

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options

seealso:
    - module: vmware.vmware.tag_associations
    - module: vmware.vmware.tags
"""

EXAMPLES = r"""
- name: Get tags attached to a VM by MOID
  vmware.vmware.tag_associations_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    object_moid: "vm-123"
    object_type: VirtualMachine
  register: vm_tags

- name: Get tags attached to a cluster
  vmware.vmware.tag_associations_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    object_name: "MyCluster"
    object_type: ClusterComputeResource
  register: cluster_tags

- name: Get tags attached to a datastore
  vmware.vmware.tag_associations_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    object_name: "datastore1"
    object_type: Datastore
  register: datastore_tags
"""

RETURN = r"""
tags:
    description:
        - List of tags attached to the object
        - Each tag is represented as a dictionary with tag details
    returned: always
    type: list
    sample: [
        {
            "id": "urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL",
            "name": "my-tag",
            "description": "Tag description",
            "category_id": "urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL",
            "category_name": "my-category"
        }
    ]
object_moid:
    description:
        - The MOID of the object that was queried
    returned: always
    type: str
    sample: "vm-123"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import (
    ModuleRestBase,
)
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import (
    ModulePyvmomiBase,
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    rest_compatible_argument_spec,
)

try:
    from com.vmware.vapi.std.errors_client import NotFound
    from com.vmware.cis.tagging_client import TagAssociation
except ImportError:
    pass


class TagAssociationsInfo(ModuleRestBase):
    def __init__(self, module):
        super(TagAssociationsInfo, self).__init__(module)
        self.pyvmomi = ModulePyvmomiBase(module)

    def get_object_moid(self):
        """
        Get the MOID of the object based on name or use the provided MOID
        """
        if self.params.get('object_moid'):
            return self.params['object_moid']

        # Use object_name to find the MOID
        object_name = self.params.get('object_name')
        object_type = self.params.get('object_type')

        # Map object_type to pyVmomi types
        type_mapping = {
            'VirtualMachine': 'vim.VirtualMachine',
            'Datacenter': 'vim.Datacenter',
            'ClusterComputeResource': 'vim.ClusterComputeResource',
            'HostSystem': 'vim.HostSystem',
            'DistributedVirtualSwitch': 'vim.DistributedVirtualSwitch',
            'DistributedVirtualPortgroup': 'vim.DistributedVirtualPortgroup',
            'Datastore': 'vim.Datastore',
            'DatastoreCluster': 'vim.StoragePod',
            'ResourcePool': 'vim.ResourcePool',
            'Folder': 'vim.Folder',
        }

        # For simplicity, get the object by name using pyvmomi methods
        # This is a simplified approach - in production you'd want more robust object lookup
        if object_type == 'VirtualMachine':
            obj = self.pyvmomi.get_vm_by_name_or_moid(object_name, fail_on_missing=True)
        elif object_type == 'ClusterComputeResource':
            obj = self.pyvmomi.get_cluster_by_name_or_moid(object_name, fail_on_missing=True)
        elif object_type == 'Datacenter':
            obj = self.pyvmomi.get_datacenter_by_name_or_moid(object_name, fail_on_missing=True)
        elif object_type == 'HostSystem':
            obj = self.pyvmomi.get_host_by_name_or_moid(object_name, fail_on_missing=True)
        else:
            self.module.fail_json(msg=f"Object type {object_type} lookup by name not yet implemented. Please use object_moid.")

        return obj._moId

    def gather_tag_associations(self):
        """
        Gather information about tags attached to the object
        """
        moid = self.get_object_moid()
        object_type = self.params['object_type']

        # Build the dynamic ID for the object
        dynamic_id = self.api_client.tagging.TagAssociation.DynamicID(
            type=object_type,
            id=moid
        )

        # Get all tags attached to the object
        try:
            tag_ids = self.api_client.tagging.TagAssociation.list_attached_tags(dynamic_id)
        except Exception as e:
            self.module.fail_json(msg=f"Failed to get tags for object: {str(e)}")

        # Gather detailed information about each tag
        tags_info = []
        for tag_id in tag_ids:
            try:
                tag = self.api_client.tagging.Tag.get(tag_id)
                category = self.api_client.tagging.Category.get(tag.category_id)

                tag_info = {
                    'id': tag.id,
                    'name': tag.name,
                    'description': tag.description if tag.description else '',
                    'category_id': tag.category_id,
                    'category_name': category.name
                }
                tags_info.append(tag_info)
            except NotFound:
                # Tag or category not found, skip it
                continue

        return tags_info, moid


def main():
    module = AnsibleModule(
        argument_spec={
            **rest_compatible_argument_spec(), **dict(
                object_moid=dict(type='str'),
                object_name=dict(type='str'),
                object_type=dict(
                    type='str',
                    required=True,
                    choices=[
                        'VirtualMachine',
                        'Datacenter',
                        'ClusterComputeResource',
                        'HostSystem',
                        'DistributedVirtualSwitch',
                        'DistributedVirtualPortgroup',
                        'Datastore',
                        'DatastoreCluster',
                        'ResourcePool',
                        'Folder'
                    ]
                ),
            )
        },
        supports_check_mode=True,
        required_one_of=[
            ('object_moid', 'object_name')
        ],
        mutually_exclusive=[
            ('object_moid', 'object_name')
        ]
    )

    tag_assoc_info = TagAssociationsInfo(module)
    tags, moid = tag_assoc_info.gather_tag_associations()
    module.exit_json(changed=False, tags=tags, object_moid=moid)


if __name__ == '__main__':
    main()
