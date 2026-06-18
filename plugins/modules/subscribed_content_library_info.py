#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: subscribed_content_library_info
short_description: Gathers information about subscribed content libraries
description:
    - Gathers information about one or more subscribed content libraries.
    - You can search for libraries by name or retrieve all subscribed libraries.
author:
    - Ansible Cloud Team (@ansible-collections)
requirements:
    - vSphere Automation SDK

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options

options:
    name:
        description:
            - The name of the subscribed content library to gather information about.
            - If not provided, all subscribed content libraries will be returned.
        type: str
        required: false
        aliases: [library_name]
    library_id:
        description:
            - The ID of the subscribed content library to gather information about.
            - If provided, only this library will be returned.
        type: str
        required: false
'''

EXAMPLES = r'''
- name: Gather information about all subscribed content libraries
  vmware.vmware.subscribed_content_library_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
  register: all_libraries

- name: Gather information about a specific library by name
  vmware.vmware.subscribed_content_library_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    name: my-subscribed-library
  register: library_info

- name: Gather information about a library by ID
  vmware.vmware.subscribed_content_library_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    library_id: 12345678-1234-1234-1234-123456789012
  register: library_info
'''

RETURN = r'''
libraries:
    description:
        - Dictionary of subscribed content libraries found.
        - The key is the library ID, the value is a dictionary with library information.
    returned: always
    type: dict
    sample: {
        "12345678-1234-1234-1234-123456789012": {
            "id": "12345678-1234-1234-1234-123456789012",
            "name": "my-subscribed-library",
            "description": "My subscribed content library",
            "type": "SUBSCRIBED",
            "creation_time": "2024-01-01T00:00:00.000Z",
            "last_modified_time": "2024-01-01T00:00:00.000Z",
            "storage_backings": [
                {
                    "datastore_id": "datastore-123",
                    "type": "DATASTORE"
                }
            ],
            "subscription_info": {
                "authentication_method": "BASIC",
                "automatic_sync_enabled": true,
                "on_demand": false,
                "subscription_url": "https://vcenter.example.com/..."
            },
            "version": "1"
        }
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import (
    ModuleRestBase,
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    rest_compatible_argument_spec,
)

try:
    from com.vmware.vapi.std.errors_client import NotFound
    from com.vmware.content_client import LibraryModel
except ImportError:
    pass


class SubscribedContentLibraryInfo(ModuleRestBase):
    def __init__(self, module):
        super(SubscribedContentLibraryInfo, self).__init__(module)

    def gather_libraries_info(self):
        """
        Gather information about subscribed content libraries based on the search parameters
        """
        all_libraries_info = {}

        # If library_id is provided, get that specific library
        if self.params.get('library_id'):
            try:
                library = self.api_client.content.SubscribedLibrary.get(self.params['library_id'])
                if library.type == LibraryModel.LibraryType.SUBSCRIBED:
                    all_libraries_info[library.id] = self._library_to_dict(library)
            except NotFound:
                self.module.fail_json(msg=f"Library with ID {self.params['library_id']} not found")
            return all_libraries_info

        # Get all subscribed libraries
        library_ids = self.api_client.content.SubscribedLibrary.list()
        for library_id in library_ids:
            library = self.api_client.content.SubscribedLibrary.get(library_id)
            # Filter by name if provided
            if self.params.get('name') and library.name != self.params['name']:
                continue
            all_libraries_info[library.id] = self._library_to_dict(library)

        return all_libraries_info

    def _library_to_dict(self, library):
        """
        Convert a library object to a dictionary
        """
        library_dict = {
            'id': library.id,
            'name': library.name,
            'description': library.description if library.description else '',
            'type': library.type,
            'creation_time': str(library.creation_time) if library.creation_time else None,
            'last_modified_time': str(library.last_modified_time) if library.last_modified_time else None,
            'storage_backings': [],
            'version': library.version if hasattr(library, 'version') else None
        }

        # Add storage backings
        if library.storage_backings:
            for backing in library.storage_backings:
                library_dict['storage_backings'].append({
                    'datastore_id': backing.datastore_id,
                    'type': backing.type
                })

        # Add subscription info if available
        if library.subscription_info:
            library_dict['subscription_info'] = {
                'authentication_method': (
                    library.subscription_info.authentication_method
                ),
                'automatic_sync_enabled': (
                    library.subscription_info.automatic_sync_enabled
                    if hasattr(
                        library.subscription_info, 'automatic_sync_enabled'
                    )
                    else None
                ),
                'on_demand': (
                    library.subscription_info.on_demand
                    if hasattr(library.subscription_info, 'on_demand')
                    else None
                ),
                'subscription_url': (
                    library.subscription_info.subscription_url
                    if hasattr(library.subscription_info, 'subscription_url')
                    else None
                ),
            }

        return library_dict


def main():
    module = AnsibleModule(
        argument_spec={
            **rest_compatible_argument_spec(), **dict(
                name=dict(type='str', aliases=['library_name']),
                library_id=dict(type='str'),
            )
        },
        supports_check_mode=True,
        mutually_exclusive=[
            ('name', 'library_id'),
        ]
    )

    library_info = SubscribedContentLibraryInfo(module)
    libraries = library_info.gather_libraries_info()
    module.exit_json(changed=False, libraries=libraries)


if __name__ == '__main__':
    main()
