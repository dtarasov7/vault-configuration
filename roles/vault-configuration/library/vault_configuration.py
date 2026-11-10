#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Ansible interface; all work runs on the chosen execution host."""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vault_configuration.common import ConfigurationError
from ansible.module_utils.vault_configuration.executor import PartialApply
from ansible.module_utils.vault_configuration.runner import run

DOCUMENTATION = r'''
---
module: vault_configuration
short_description: Plan, apply or export Vault Community identity and KV v2 ACL configuration
version_added: '1.0.0'
description:
  - Uses one existing administrative token for every API operation; never reads or writes user KV data.
  - Uses a durable execution-host registry for ownership and recovery.
  - Saves dry reports as YAML when config.report_destination is supplied by the role.
requirements:
  - PyYAML on the execution host for YAML exports and dry reports.
options:
  config:
    description: Strict schema version 1 connection, management and safety settings.
    type: dict
    required: true
  token:
    description: Single existing administrative token for discovery, mounts, LDAP, identities and ACLs; never logged.
    type: str
    required: true
  passwords:
    description: External userpass passwords indexed by inventory user ID.
    type: dict
    default: {}
  users:
    description: Desired users; missing userpass auth mounts are created. Omit to leave the section unmanaged.
    type: list
    elements: dict
  ldap:
    description: LDAP/Active Directory integrations and bind password revisions.
    type: list
    elements: dict
  ldap_passwords:
    description: External LDAP bind passwords indexed by integration ID.
    type: dict
    default: {}
  groups:
    description: Desired identity groups.
    type: list
    elements: dict
  grants:
    description: Desired KV v2 or existing-policy assignments.
    type: list
    elements: dict
  auth_roles:
    description: Existing Kubernetes, JWT/OIDC or AppRole references.
    type: list
    elements: dict
  personal_access:
    description: Personal policy using entity_id or ldap_login, with automatically resolved LDAP accessor and optional path_prefix.
    type: dict
  export:
    description: Export scope, output files, filters and explicit partial audit mode.
    type: dict
    default: {}
author:
  - vault-configuration maintainers
'''
EXAMPLES = r'''
- name: Build a read-only access plan
  vault_configuration:
    config:
      mode: "{{ vault_configuration_config_mode }}"
      connection:
        address: "{{ vault_configuration_config_connection_address }}"
      management:
        owner: "{{ vault_configuration_config_management_owner }}"
        policy_prefix: "{{ vault_configuration_config_management_policy_prefix }}"
        state_file: "{{ vault_configuration_config_management_state_file }}"
    token: "{{ vault_configuration_token }}"
    users: "{{ vault_configuration_users | default(omit) }}"
    grants: "{{ vault_configuration_grants | default(omit) }}"
  no_log: true
'''
RETURN = r'''
report:
  description: Safe structured plan, digest, three summaries or export audit summary.
  type: dict
  returned: always
'''


def main():
    """Translate Ansible arguments into a sanitized role result.
    RU: Преобразовать аргументы Ansible в безопасный результат роли.

    Returns:
        None: Exits through Ansible result helpers / завершает работу через функции результата Ansible.

    Raises:
        SystemExit: Ansible success or failure result / результат успеха или ошибки Ansible.
    """
    specification = {
        'config': {'type': 'dict', 'required': True},
        'token': {'type': 'str', 'required': True, 'no_log': True},
        'passwords': {'type': 'dict', 'default': {}, 'no_log': True},
        'users': {'type': 'list', 'elements': 'dict'},
        'ldap': {'type': 'list', 'elements': 'dict'},
        'ldap_passwords': {'type': 'dict', 'default': {}, 'no_log': True},
        'groups': {'type': 'list', 'elements': 'dict'},
        'grants': {'type': 'list', 'elements': 'dict'},
        'auth_roles': {'type': 'list', 'elements': 'dict'},
        'personal_access': {'type': 'dict'}, 'export': {'type': 'dict', 'default': {}},
    }
    module = AnsibleModule(argument_spec=specification, supports_check_mode=True)
    for user in module.params.get('users') or []:
        password = user.get('password')
        if isinstance(password, str) and password:
            module.no_log_values.add(password)
    sections = {key: module.params[key] for key in ('users', 'groups', 'grants', 'auth_roles', 'personal_access', 'ldap')}
    try:
        result = run(module.params['config'], sections, module.params['token'], module.params['passwords'],
                     module.params['export'], module.check_mode, module._diff, ldap_passwords=module.params['ldap_passwords'])
    except PartialApply as error:
        module.fail_json(msg=str(error), changed=bool(error.confirmed) or bool(error.uncertain),
                         report={'changed': bool(error.confirmed) or bool(error.uncertain), 'error': str(error), 'confirmed': error.confirmed, 'uncertain': error.uncertain})
    except ConfigurationError as error:
        module.fail_json(msg=str(error), report={'error': str(error)})
    except Exception:
        # Never include arbitrary HTTP/TLS exceptions, response bodies, arguments or tracebacks.
        module.fail_json(msg='Unexpected execution error; inspect execution-host permissions and runtime dependencies',
                         report={'error': 'Unexpected execution error; no sensitive exception details returned'})
    else:
        module.exit_json(changed=result['changed'], diff=result.get('diff', []), report=result)


if __name__ == '__main__':
    main()
