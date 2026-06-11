#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: folder_info
short_description: Gathers information about one or more folders
description:
    - >-
      Gathers information about one or more folders.
      You can search for folders based on the folder path, datacenter name, or folder type.
author:
    - Ansible Cloud Team (@ansible-collections)

options:
    datacenter:
        description:
            - The name of the datacenter where the folder exists.
            - Only used if the O(relative_path) option is used.
        type: str
        required: false
        aliases: [datacenter_name]
    folder_type:
        description:
            - The type of folder to search for.
            - For example, a folder at path /DC-01/vm/my/folder has folder type 'vm'.
            - Only used if the O(relative_path) option is used.
        type: str
        required: false
        choices: [vm, host, datastore, network]
    relative_path:
        description:
            - The relative path of the folder. The relative path should include neither the datacenter nor the folder type.
            - For example the relative path for the folder /DC-01/vm/my/folder is my/folder
            - One of O(relative_path) or O(absolute_path) must be specified.
        type: str
    absolute_path:
        description:
            - The absolute path of the folder. The absolute path should include the datacenter and the folder type.
            - The leading slash is not required. For example the absolute path could be /DC-01/vm/my/folder or DC-01/vm/my/folder
            - One of O(relative_path) or O(absolute_path) must be specified.
        type: str
    gather_tags:
        description:
            - If true, gather any tags attached to the folder(s)
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
- name: Gather Folder Information Using Absolute Path
  vmware.vmware.folder_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    absolute_path: /DC-01/vm/my/folder
  register: _out

- name: Gather Folder Information Using Relative Path
  vmware.vmware.folder_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    datacenter_name: DC-01
    folder_type: vm
    relative_path: my/folder
  register: _out

- name: Gather Specific Properties About a Folder
  vmware.vmware.folder_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    absolute_path: /DC-01/vm/my/folder
    schema: vsphere
    properties:
      - name
      - parent
  register: _out
'''

RETURN = r'''
folders:
    description:
        - A dictionary that describes the folders found by the search parameters
        - The keys are the folder paths and the values are dictionaries with the folder info.
    returned: On success
    type: dict
    sample: {
        "folders": {
            "/DC-01/vm/my/folder": {
                "moid": "group-v123",
                "name": "folder",
                "parent": "/DC-01/vm/my",
                "path": "/DC-01/vm/my/folder",
                "type": "vm",
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
from ansible_collections.vmware.vmware.plugins.module_utils._folder_paths import (
    prepend_datacenter_and_folder_type
)


class FolderInfo(ModulePyvmomiBase):
    def __init__(self, module):
        super(FolderInfo, self).__init__(module)
        self.rest_client = None
        if module.params['gather_tags']:
            self.rest_client = ModuleRestBase(module)

        if self.params['absolute_path']:
            self.absolute_folder_path = self.params['absolute_path']
        else:
            self.absolute_folder_path = prepend_datacenter_and_folder_type(
                folder_path=self.params['relative_path'],
                datacenter_name=self.params['datacenter'],
                folder_type=self.params['folder_type'],
            )
        self.absolute_folder_path = self.absolute_folder_path.strip('/')

    def get_folders(self):
        """
        Gets folders matching the search parameters input by the user.
        Returns: List of folders to gather info about
        """
        folder = self.get_folder_by_absolute_path(
            folder_path=self.absolute_folder_path,
            fail_on_missing=False
        )
        return [folder] if folder else []

    def gather_info_for_folders(self):
        """
        Gather information about one or more folders
        """
        all_folder_info = {}
        for folder in self.get_folders():
            folder_info = {}
            if self.params['schema'] == 'summary':
                folder_info = {
                    'moid': folder._moId,
                    'name': folder.name,
                    'path': self.absolute_folder_path,
                    'parent': '/'.join(self.absolute_folder_path.split('/')[:-1]),
                    'type': self.absolute_folder_path.split('/')[1] if '/' in self.absolute_folder_path else None,
                    'tags': self._get_tags(folder)
                }
            else:
                try:
                    folder_info = vmware_obj_to_json(folder, self.params['properties'])
                except AttributeError as e:
                    self.module.fail_json(str(e))

            all_folder_info[self.absolute_folder_path] = folder_info

        return all_folder_info

    def _get_tags(self, folder):
        """
        Gets the tags on a folder. Tags are formatted as a list of dictionaries corresponding to each tag
        """
        output = []
        if not self.params.get('gather_tags') or not self.rest_client:
            return output

        tags = self.rest_client.get_tags_by_folder_moid(folder._moId)
        for tag in tags:
            output.append(self.rest_client.format_tag_identity_as_dict(tag))

        return output


def main():
    module = AnsibleModule(
        argument_spec={
            **rest_compatible_argument_spec(), **dict(
                datacenter=dict(type='str', required=False, aliases=['datacenter_name']),
                folder_type=dict(type='str', choices=['vm', 'host', 'network', 'datastore'], required=False),
                relative_path=dict(type='str', required=False),
                absolute_path=dict(type='str', required=False),
                gather_tags=dict(type='bool', default=False),
                schema=dict(type='str', choices=['summary', 'vsphere'], default='summary'),
                properties=dict(type='list', elements='str'),
            )
        },
        supports_check_mode=True,
        required_one_of=[
            ('relative_path', 'absolute_path')
        ],
        mutually_exclusive=[
            ('absolute_path', 'relative_path')
        ],
        required_by={
            'relative_path': ('datacenter', 'folder_type')
        }
    )
    if module.params['schema'] != 'vsphere' and module.params.get('properties'):
        module.fail_json(msg="The option 'properties' is only valid when the schema is 'vsphere'")

    folder_info = FolderInfo(module)
    folders = folder_info.gather_info_for_folders()
    module.exit_json(changed=False, folders=folders)


if __name__ == '__main__':
    main()
