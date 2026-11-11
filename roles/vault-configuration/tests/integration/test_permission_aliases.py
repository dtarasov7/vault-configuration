"""Real Vault verifies alias idempotence, explicit exports and personal ACLs."""
import copy
import tempfile
import unittest
from pathlib import Path

from test_vault import ROOT, Server
from vault_configuration.runner import run
from vault_configuration.compiler import PERMISSIONS, expand_permissions


class PermissionAliasIntegration(unittest.TestCase):
    def test_aliases_match_explicit_inventory_without_acl_changes(self):
        with tempfile.TemporaryDirectory(prefix='permission-alias-', dir=str(ROOT / '.work')) as temporary:
            server = Server(Path(temporary))
            try:
                config = {'mode': 'apply', 'connection': server.connection, 'mounts': ['apps', 'users'],
                          'management': {'owner': 'aliases', 'policy_prefix': 'vam-aliases-'},
                          'safety': {'allow_destructive_grants': True}}
                sections = {'users': [{'id': 'alice', 'name': 'alias-alice', 'source': 'userpass',
                                       'auth_mount': 'userpass', 'login': 'alias-alice'}],
                            'grants': [{'id': 'access', 'subjects': [{'kind': 'user', 'id': 'alice'}],
                                        'paths': [{'mount': 'apps', 'path': 'team', 'scope': 'subtree', 'permissions': 'all'}]}],
                            'personal_access': {'enabled': True, 'mount': 'users', 'permissions': ['all'],
                                                'subjects': [{'kind': 'user', 'id': 'alice'}]}}
                result = run(config, sections, server.token, passwords={'alice': 'alias-test-only'})
                self.assertTrue(result['changed'])
                exported = run(dict(config, mode='export'), {}, server.token)['_export_variables']
                self.assertEqual(exported['vault_configuration_grants'][0]['paths'][0]['permissions'], sorted(PERMISSIONS))
                self.assertEqual(exported['vault_configuration_personal_access']['permissions'], sorted(PERMISSIONS))
                entity = server.client.read('identity/entity/name/alias-alice')['id']
                token = server.client.request('POST', 'auth/userpass/login/alias-alice', {'password': 'alias-test-only'})['auth']['client_token']
                for alias in ('all', 'read_only', 'read_write'):
                    sections['grants'][0]['paths'][0]['permissions'] = alias
                    sections['personal_access']['permissions'] = [alias]
                    run(config, sections, server.token)
                    explicit = copy.deepcopy(sections)
                    explicit['grants'][0]['paths'][0]['permissions'] = expand_permissions(alias)
                    explicit['personal_access']['permissions'] = expand_permissions(alias)
                    self.assertFalse(run(config, explicit, server.token)['changed'])
                    aliased_plan = run(dict(config, mode='dry'), sections, server.token)['plan']
                    explicit_plan = run(dict(config, mode='dry'), explicit, server.token)['plan']
                    self.assertEqual(aliased_plan['digest'], explicit_plan['digest'])
                    expected_data = {'all': {'read', 'create', 'update', 'patch', 'delete'},
                                     'read_only': {'read'}, 'read_write': {'read', 'create', 'update', 'patch'}}[alias]
                    for path in ('apps/data/team/test', 'users/data/' + entity + '/mail'):
                        actual = server.client.request('POST', 'sys/capabilities', {'token': token, 'paths': [path]})['data']['capabilities']
                        self.assertEqual(set(actual), expected_data)
            finally:
                server.close()
