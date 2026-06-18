#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vm_advanced_settings_info
short_description: Gathers information about VM advanced settings
description:
    - Gathers information about the advanced settings for a VM.
author:
    - Ansible Cloud Team (@ansible-collections)

options:
    datacenter:
        description:
            - The name of the datacenter to search for the VM.
            - This is only used if O(folder) is also used.
        type: str
        required: false
        aliases: [datacenter_name]
    name:
        description:
            - Name of the virtual machine to work with.
            - This is required if O(moid) or O(uuid) is not supplied.
        type: str
    name_match:
        description:
            - If multiple virtual machines matching the name, use the first or last found.
        default: first
        choices: [ first, last ]
        type: str
    uuid:
        description:
            - UUID of the instance to query.
            - This is required if O(name) or O(moid) is not supplied.
        type: str
    moid:
        description:
            - Managed Object ID of the instance to query.
            - This is required if O(name) or O(uuid) is not supplied.
        type: str
    use_instance_uuid:
        description:
            - Whether to use the VMware instance UUID rather than the BIOS UUID.
        default: false
        type: bool
    folder:
        description:
            - Folder path to find the VM.
            - Should be the full folder path, with or without the 'datacenter/vm/' prefix
            - For example 'datacenter_name/vm/path/to/folder' or 'path/to/folder'
        type: str
        required: false
    folder_paths_are_absolute:
        description:
            - If true, any folder path parameters are treated as absolute paths.
            - If false, modules will try to intelligently determine if the path is absolute or relative.
        type: bool
        required: false
        default: false
    setting_key:
        description:
            - If provided, only return information about this specific setting.
            - If not provided, all advanced settings will be returned.
        type: str
        required: false

extends_documentation_fragment:
    - vmware.vmware.base_options
'''

EXAMPLES = r'''
- name: Gather all advanced settings for a VM
  vmware.vmware.vm_advanced_settings_info:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    name: my-test-vm
  register: vm_settings

- name: Gather a specific advanced setting
  vmware.vmware.vm_advanced_settings_info:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    name: my-test-vm
    setting_key: "isolation.tools.copy.disable"
  register: vm_setting

- name: Gather settings by VM UUID
  vmware.vmware.vm_advanced_settings_info:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    uuid: "{{ vm_uuid }}"
  register: vm_settings
'''

RETURN = r'''
settings:
    description:
        - Dictionary of advanced settings for the VM
        - Keys are setting names, values are setting values
    returned: always
    type: dict
    sample: {
        "isolation.tools.copy.disable": "TRUE",
        "isolation.tools.paste.disable": "TRUE",
        "tools.guest.desktop.autolock": "FALSE"
    }
vm_name:
    description:
        - Name of the VM
    returned: always
    type: str
    sample: "my-test-vm"
vm_moid:
    description:
        - Managed Object ID of the VM
    returned: always
    type: str
    sample: "vm-12345"
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
    base_argument_spec
)


class VmAdvancedSettingsInfo(ModulePyvmomiBase):
    def __init__(self, module):
        super(VmAdvancedSettingsInfo, self).__init__(module)
        self.vm = None

    def get_vm(self):
        """
        Get the VM object based on the parameters
        """
        vms = self.get_vms_using_params(fail_on_missing=True)
        if isinstance(vms, list):
            self.vm = vms[0]
        else:
            self.vm = vms

    def gather_settings_info(self):
        """
        Gather advanced settings information from the VM
        """
        settings = {}
        setting_key = self.params.get('setting_key')

        # Get all extra config settings
        if self.vm.config and self.vm.config.extraConfig:
            for option in self.vm.config.extraConfig:
                # If a specific setting is requested, only include that one
                if setting_key:
                    if option.key == setting_key:
                        settings[option.key] = str(option.value)
                        break
                else:
                    settings[option.key] = str(option.value)

        return settings


def main():
    module = AnsibleModule(
        argument_spec={
            **base_argument_spec(), **dict(
                name=dict(type='str'),
                name_match=dict(type='str', choices=['first', 'last'], default='first'),
                uuid=dict(type='str'),
                moid=dict(type='str'),
                use_instance_uuid=dict(type='bool', default=False),
                folder=dict(type='str'),
                folder_paths_are_absolute=dict(type='bool', default=False),
                datacenter=dict(type='str', aliases=['datacenter_name']),
                setting_key=dict(type='str', no_log=False),
            )
        },
        supports_check_mode=True,
        required_one_of=[
            ['name', 'uuid', 'moid']
        ],
        mutually_exclusive=[
            ['name', 'uuid', 'moid']
        ]
    )

    settings_info = VmAdvancedSettingsInfo(module)
    settings_info.get_vm()
    settings = settings_info.gather_settings_info()

    module.exit_json(
        changed=False,
        settings=settings,
        vm_name=settings_info.vm.name,
        vm_moid=settings_info.vm._moId
    )


if __name__ == '__main__':
    main()
