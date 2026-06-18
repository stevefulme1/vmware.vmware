#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: tags_info
short_description: Gathers information about VMware tags
description:
    - This module allows you to gather information about VMware tags.
    - You can query tags by name, category, or retrieve all tags.

author:
    - Ansible Cloud Team (@ansible-collections)

options:
    tag_name:
        description:
            - The name of the tag to gather information about.
            - If not provided, all tags will be returned.
        type: str
        required: false
        aliases: [name]
    tag_id:
        description:
            - The id of the tag to gather information about.
            - If provided, only this tag will be returned.
        type: str
        required: false
        aliases: [id]
    category_name:
        description:
            - Filter tags by category name.
            - If provided along with O(tag_name), find a specific tag in this category.
        type: str
        required: false
    category_id:
        description:
            - Filter tags by category ID.
            - If provided along with O(tag_name), find a specific tag in this category.
        type: str
        required: false

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options

seealso:
    - module: vmware.vmware.tags
    - module: vmware.vmware.tag_categories
"""

EXAMPLES = r"""
- name: Gather information about all tags
  vmware.vmware.tags_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
  register: all_tags

- name: Gather information about a specific tag by ID
  vmware.vmware.tags_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    tag_id: urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL
  register: tag_info

- name: Gather information about a tag by name and category
  vmware.vmware.tags_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    tag_name: my-test-tag
    category_name: my-category
  register: tag_info

- name: Gather all tags in a specific category
  vmware.vmware.tags_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    category_id: urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL
  register: category_tags
"""

RETURN = r"""
tags:
    description:
        - Dictionary of tags found.
        - The key is the tag ID, the value is a dictionary with tag information.
    returned: always
    type: dict
    sample: {
        "urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL": {
            "category_id": "urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL",
            "name": "tag1",
            "description": "Description of tag1",
            "id": "urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL",
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


class TagsInfo(ModuleRestBase):
    def __init__(self, module):
        super(TagsInfo, self).__init__(module)

    def gather_tags_info(self):
        """
        Gather information about tags based on the search parameters
        """
        all_tags_info = {}

        # If tag_id is provided, get that specific tag
        if self.params.get('tag_id'):
            try:
                tag = self.api_client.tagging.Tag.get(self.params['tag_id'])
                all_tags_info[tag.id] = self._tag_to_dict(tag)
            except NotFound:
                self.module.fail_json(msg=f"Tag with ID {self.params['tag_id']} not found")
            return all_tags_info

        # Get category_id if category_name is provided
        category_id = self.params.get('category_id')
        if self.params.get('category_name') and not category_id:
            category_id = self._get_category_id_by_name(self.params['category_name'])

        # If tag_name is provided, search for that specific tag
        if self.params.get('tag_name'):
            tag_ids = self.api_client.tagging.Tag.list()
            for tag_id in tag_ids:
                tag = self.api_client.tagging.Tag.get(tag_id)
                if tag.name == self.params['tag_name']:
                    # If category filter is provided, check it matches
                    if category_id and tag.category_id != category_id:
                        continue
                    all_tags_info[tag.id] = self._tag_to_dict(tag)
            return all_tags_info

        # Get all tags, optionally filtered by category
        tag_ids = self.api_client.tagging.Tag.list()
        for tag_id in tag_ids:
            tag = self.api_client.tagging.Tag.get(tag_id)
            # Apply category filter if provided
            if category_id and tag.category_id != category_id:
                continue
            all_tags_info[tag.id] = self._tag_to_dict(tag)

        return all_tags_info

    def _tag_to_dict(self, tag):
        """
        Convert a tag object to a dictionary
        """
        return {
            'id': tag.id,
            'name': tag.name,
            'description': tag.description if tag.description else '',
            'category_id': tag.category_id,
            'used_by': list(tag.used_by) if tag.used_by else []
        }

    def _get_category_id_by_name(self, category_name):
        """
        Get category ID by name
        """
        category_ids = self.api_client.tagging.Category.list()
        for category_id in category_ids:
            category = self.api_client.tagging.Category.get(category_id)
            if category.name == category_name:
                return category.id
        self.module.fail_json(msg=f"Category with name {category_name} not found")


def main():
    module = AnsibleModule(
        argument_spec={
            **rest_compatible_argument_spec(), **dict(
                tag_name=dict(type='str', aliases=['name']),
                tag_id=dict(type='str', aliases=['id']),
                category_name=dict(type='str'),
                category_id=dict(type='str'),
            )
        },
        supports_check_mode=True,
        mutually_exclusive=[
            ('tag_name', 'tag_id'),
        ]
    )

    tags_info = TagsInfo(module)
    tags = tags_info.gather_tags_info()
    module.exit_json(changed=False, tags=tags)


if __name__ == '__main__':
    main()
