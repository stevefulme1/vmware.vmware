#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vm_snapshot_info
short_description: Gathers information about virtual machine snapshots
description:
    - This module can be used to gather information about snapshots of a virtual machine.
author:
    - Ansible Cloud Team (@ansible-collections)
options:
    name:
        description:
            - Name of the virtual machine.
            - This is required parameter, if O(uuid) or O(moid) is not supplied.
        type: str
    name_match:
        description:
            - If multiple VMs with the same name exist, use the first or last found.
        default: 'first'
        choices: ['first', 'last']
        type: str
    uuid:
        description:
            - UUID of the instance to manage. This is VMware's BIOS UUID by default.
            - This is required if O(name) or O(moid) parameter is not supplied.
        type: str
    moid:
        description:
            - Managed Object ID of the virtual machine.
            - This is required if O(name) or O(uuid) is not supplied.
        type: str
    use_instance_uuid:
        description:
            - Whether to use the VMware instance UUID rather than the BIOS UUID.
        default: false
        type: bool
    folder:
        description:
            - Absolute or relative folder path to search for the virtual machine.
            - This parameter is required if O(name) is supplied.
            - For example 'datacenter name/vm/path/to/folder' or 'path/to/folder'
        type: str
    folder_paths_are_absolute:
        description:
            - If true, any folder path parameters are treated as absolute paths.
            - If false, modules will try to intelligently determine if the path is absolute or relative.
        type: bool
        required: false
        default: false
    datacenter:
        description:
            - Datacenter to search for the virtual machine.
        type: str
    snapshot_name:
        description:
            - The name of a specific snapshot to gather information about.
            - If not provided, all snapshots will be returned.
        type: str

extends_documentation_fragment:
    - vmware.vmware.base_options
'''

EXAMPLES = r'''
- name: Gather information about all snapshots of a VM
  vmware.vmware.vm_snapshot_info:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ datacenter_name }}"
    folder: "/{{ datacenter_name }}/vm/"
    name: "{{ guest_name }}"
  register: snapshot_info

- name: Gather information about a specific snapshot
  vmware.vmware.vm_snapshot_info:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    datacenter: "{{ datacenter_name }}"
    folder: "/{{ datacenter_name }}/vm/"
    name: "{{ guest_name }}"
    snapshot_name: snap1
  register: snapshot_info

- name: Gather snapshot information using VM UUID
  vmware.vmware.vm_snapshot_info:
    hostname: "{{ vcenter_hostname }}"
    username: "{{ vcenter_username }}"
    password: "{{ vcenter_password }}"
    uuid: "{{ vm_uuid }}"
  register: snapshot_info
'''

RETURN = r'''
snapshots:
    description:
        - List of snapshots for the virtual machine
        - Each snapshot is represented as a dictionary with snapshot details
    returned: On success
    type: list
    sample: [
        {
            "id": 1,
            "name": "snap1",
            "description": "First snapshot",
            "creation_time": "2024-01-01 12:00:00",
            "state": "poweredOn",
            "quiesced": false,
            "parent_snapshot": null,
            "child_snapshots": []
        },
        {
            "id": 2,
            "name": "snap2",
            "description": "Second snapshot",
            "creation_time": "2024-01-02 12:00:00",
            "state": "poweredOn",
            "quiesced": false,
            "parent_snapshot": "snap1",
            "child_snapshots": []
        }
    ]
vm_name:
    description:
        - Name of the virtual machine
    returned: On success
    type: str
    sample: "my-vm"
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


class VmSnapshotInfo(ModulePyvmomiBase):
    def __init__(self, module):
        super(VmSnapshotInfo, self).__init__(module)
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

    def gather_snapshot_info(self):
        """
        Gather information about snapshots
        """
        if not self.vm.snapshot:
            return []

        all_snapshots = []
        snapshot_name = self.params.get('snapshot_name')

        # Recursively walk the snapshot tree
        self._walk_snapshot_tree(self.vm.snapshot.rootSnapshotList, None, all_snapshots, snapshot_name)

        return all_snapshots

    def _walk_snapshot_tree(self, snapshots, parent_name, all_snapshots, target_name=None):
        """
        Recursively walk through snapshot tree and collect information
        """
        for snapshot in snapshots:
            snapshot_info = {
                'id': snapshot.id,
                'name': snapshot.name,
                'description': snapshot.description if snapshot.description else '',
                'creation_time': str(snapshot.createTime),
                'state': snapshot.state,
                'quiesced': snapshot.quiesced,
                'parent_snapshot': parent_name,
                'child_snapshots': [child.name for child in snapshot.childSnapshotList] if snapshot.childSnapshotList else []
            }

            # If we're looking for a specific snapshot, only add it if the name matches
            if target_name is None or snapshot.name == target_name:
                all_snapshots.append(snapshot_info)

            # Recursively process child snapshots
            if snapshot.childSnapshotList:
                self._walk_snapshot_tree(
                    snapshot.childSnapshotList,
                    snapshot.name,
                    all_snapshots,
                    target_name
                )


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
                datacenter=dict(type='str'),
                snapshot_name=dict(type='str'),
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

    snapshot_info = VmSnapshotInfo(module)
    snapshot_info.get_vm()
    snapshots = snapshot_info.gather_snapshot_info()
    module.exit_json(changed=False, snapshots=snapshots, vm_name=snapshot_info.vm.name)


if __name__ == '__main__':
    main()
