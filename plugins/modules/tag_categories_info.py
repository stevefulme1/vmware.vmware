#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: tag_categories_info
short_description: Gathers information about VMware tag categories
description:
    - This module allows you to gather information about VMware tag categories.
    - You can query categories by name or ID, or retrieve all categories.

author:
    - Ansible Cloud Team (@ansible-collections)

options:
    category_name:
        description:
            - The name of the category to gather information about.
            - If not provided, all categories will be returned.
        type: str
        required: false
        aliases: [name]
    category_id:
        description:
            - The id of the category to gather information about.
            - If provided, only this category will be returned.
        type: str
        required: false
        aliases: [id]

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options

seealso:
    - module: vmware.vmware.tag_categories
    - module: vmware.vmware.tags
"""

EXAMPLES = r"""
- name: Gather information about all tag categories
  vmware.vmware.tag_categories_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
  register: all_categories

- name: Gather information about a specific category by ID
  vmware.vmware.tag_categories_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    category_id: urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL
  register: category_info

- name: Gather information about a category by name
  vmware.vmware.tag_categories_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    category_name: my-category
  register: category_info
"""

RETURN = r"""
categories:
    description:
        - Dictionary of tag categories found.
        - The key is the category ID, the value is a dictionary with category information.
    returned: always
    type: dict
    sample: {
        "urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL": {
            "id": "urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL",
            "name": "my-category",
            "description": "Category description",
            "cardinality": "MULTIPLE",
            "associable_types": ["VirtualMachine", "Folder"],
            "used_by": []
        }
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import (
    ModuleRestBase,
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    rest_compatible_argument_spec,
)

try:
    from com.vmware.vapi.std.errors_client import NotFound
except ImportError:
    pass


class TagCategoriesInfo(ModuleRestBase):
    def __init__(self, module):
        super(TagCategoriesInfo, self).__init__(module)

    def gather_categories_info(self):
        """
        Gather information about tag categories based on the search parameters
        """
        all_categories_info = {}

        # If category_id is provided, get that specific category
        if self.params.get('category_id'):
            try:
                category = self.api_client.tagging.Category.get(self.params['category_id'])
                all_categories_info[category.id] = self._category_to_dict(category)
            except NotFound:
                self.module.fail_json(msg=f"Category with ID {self.params['category_id']} not found")
            return all_categories_info

        # If category_name is provided, search for that specific category
        if self.params.get('category_name'):
            category_ids = self.api_client.tagging.Category.list()
            for category_id in category_ids:
                category = self.api_client.tagging.Category.get(category_id)
                if category.name == self.params['category_name']:
                    all_categories_info[category.id] = self._category_to_dict(category)
            return all_categories_info

        # Get all categories
        category_ids = self.api_client.tagging.Category.list()
        for category_id in category_ids:
            category = self.api_client.tagging.Category.get(category_id)
            all_categories_info[category.id] = self._category_to_dict(category)

        return all_categories_info

    def _category_to_dict(self, category):
        """
        Convert a category object to a dictionary
        """
        return {
            'id': category.id,
            'name': category.name,
            'description': category.description if category.description else '',
            'cardinality': category.cardinality,
            'associable_types': list(category.associable_types) if category.associable_types else [],
            'used_by': list(category.used_by) if category.used_by else []
        }


def main():
    module = AnsibleModule(
        argument_spec={
            **rest_compatible_argument_spec(), **dict(
                category_name=dict(type='str', aliases=['name']),
                category_id=dict(type='str', aliases=['id']),
            )
        },
        supports_check_mode=True,
        mutually_exclusive=[
            ('category_name', 'category_id'),
        ]
    )

    categories_info = TagCategoriesInfo(module)
    categories = categories_info.gather_categories_info()
    module.exit_json(changed=False, categories=categories)


if __name__ == '__main__':
    main()
