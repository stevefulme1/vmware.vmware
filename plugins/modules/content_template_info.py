#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: content_template_info
short_description: Gathers information about templates in content library
description:
    - Gathers information about VM templates in content libraries.
    - Content Library feature is introduced in vSphere 6.0 version.
author:
    - Ansible Cloud Team (@ansible-collections)
requirements:
    - vSphere Automation SDK
options:
    template_name:
        description:
            - The name of the template to gather information about.
            - If not provided, all templates in the specified library will be returned.
        type: str
        required: false
        aliases: [template, name]
    library:
        description:
            - The name of the content library to search.
            - If not provided, all templates across all libraries will be returned.
        type: str
        required: false
        aliases: [library_name]
    library_id:
        description:
            - The ID of the content library to search.
            - If provided, only templates in this library will be returned.
        type: str
        required: false

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options
'''

EXAMPLES = r'''
- name: Gather information about all templates
  vmware.vmware.content_template_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
  register: all_templates

- name: Gather information about templates in a specific library
  vmware.vmware.content_template_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    library: my-library
  register: library_templates

- name: Gather information about a specific template
  vmware.vmware.content_template_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    library: my-library
    template_name: my-template
  register: template_info
'''

RETURN = r'''
templates:
    description:
        - Dictionary of templates found
        - The key is the template ID, the value is a dictionary with template information
    returned: always
    type: dict
    sample: {
        "12345678-1234-1234-1234-123456789012": {
            "id": "12345678-1234-1234-1234-123456789012",
            "name": "my-template",
            "description": "Template description",
            "library_id": "abcd1234-5678-9012-3456-789012345678",
            "library_name": "my-library",
            "type": "vm-template",
            "version": "1",
            "creation_time": "2024-01-01T00:00:00.000Z",
            "last_modified_time": "2024-01-01T00:00:00.000Z",
            "size": 1234567890
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


class ContentTemplateInfo(ModuleRestBase):
    def __init__(self, module):
        super(ContentTemplateInfo, self).__init__(module)

    def get_library_id(self):
        """
        Get library ID from library name or return the provided library_id
        """
        if self.params.get('library_id'):
            return self.params['library_id']

        if self.params.get('library'):
            library_name = self.params['library']
            # Search for library by name
            local_libs = self.api_client.content.LocalLibrary.list()
            for lib_id in local_libs:
                lib = self.api_client.content.LocalLibrary.get(lib_id)
                if lib.name == library_name:
                    return lib_id

            # Also check subscribed libraries
            sub_libs = self.api_client.content.SubscribedLibrary.list()
            for lib_id in sub_libs:
                lib = self.api_client.content.SubscribedLibrary.get(lib_id)
                if lib.name == library_name:
                    return lib_id

            self.module.fail_json(msg=f"Library '{library_name}' not found")

        return None

    def gather_templates_info(self):
        """
        Gather information about templates in content libraries
        """
        all_templates_info = {}
        library_id = self.get_library_id()
        template_name = self.params.get('template_name')

        # Get all library items
        if library_id:
            item_ids = self.api_client.content.library.Item.list(library_id)
        else:
            # Get all items from all libraries
            item_ids = []
            for lib_id in self.api_client.content.LocalLibrary.list():
                item_ids.extend(self.api_client.content.library.Item.list(lib_id))
            for lib_id in self.api_client.content.SubscribedLibrary.list():
                item_ids.extend(self.api_client.content.library.Item.list(lib_id))

        # Filter for VM templates
        for item_id in item_ids:
            try:
                item = self.api_client.content.library.Item.get(item_id)

                # Filter by template type (vm-template)
                if item.type != 'vm-template':
                    continue

                # Filter by name if specified
                if template_name and item.name != template_name:
                    continue

                # Get library name
                try:
                    library = self.api_client.content.LocalLibrary.get(item.library_id)
                except Exception:
                    try:
                        library = self.api_client.content.SubscribedLibrary.get(item.library_id)
                    except Exception:
                        library = None

                template_info = {
                    'id': item.id,
                    'name': item.name,
                    'description': item.description if item.description else '',
                    'library_id': item.library_id,
                    'library_name': library.name if library else None,
                    'type': item.type,
                    'version': item.version if hasattr(item, 'version') else None,
                    'creation_time': str(item.creation_time) if item.creation_time else None,
                    'last_modified_time': str(item.last_modified_time) if item.last_modified_time else None,
                    'size': item.size if hasattr(item, 'size') else None
                }

                all_templates_info[item.id] = template_info

            except NotFound:
                continue

        return all_templates_info


def main():
    module = AnsibleModule(
        argument_spec={
            **rest_compatible_argument_spec(), **dict(
                template_name=dict(type='str', aliases=['template', 'name']),
                library=dict(type='str', aliases=['library_name']),
                library_id=dict(type='str'),
            )
        },
        supports_check_mode=True,
        mutually_exclusive=[
            ('library', 'library_id'),
        ]
    )

    template_info = ContentTemplateInfo(module)
    templates = template_info.gather_templates_info()
    module.exit_json(changed=False, templates=templates)


if __name__ == '__main__':
    main()
