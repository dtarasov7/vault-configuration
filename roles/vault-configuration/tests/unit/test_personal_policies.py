"""Multiple personal scopes retain independent bindings and legacy compatibility."""
import csv
import io
import unittest

from test_core import config, view, user, grant
from vault_configuration.validation import validate
from vault_configuration.planner import Planner
from vault_configuration.compiler import policy_name
from vault_configuration.common import ConfigurationError
from vault_configuration.runner import run


def declarations():
    return {'users': [dict(user(), id=name, name=name, aliases=[{'auth_mount': 'ldap', 'name': name}])
                      for name in ('alice', 'bob', 'carol', 'dave')],
            'groups': [{'id': name, 'name': name, 'type': 'internal', 'members': [member]}
                       for name, member in [('opensource-admins', 'alice'), ('db-admins', 'bob'), ('linux-admins', 'carol'), ('xz-admins', 'dave')]],
            'personal_access': [
                {'id': 'standard-home', 'enabled': True, 'identity_source': 'ldap_login', 'auth_mount': 'ldap',
                 'mount': 'users', 'path_prefix': '', 'permissions': 'all',
                 'subjects': [{'kind': 'group', 'id': 'opensource-admins'}, {'kind': 'group', 'id': 'db-admins'}]},
                {'id': 'xz-home', 'enabled': True, 'identity_source': 'ldap_login', 'auth_mount': 'ldap',
                 'mount': 'users-xz', 'path_prefix': '', 'permissions': 'all',
                 'subjects': [{'kind': 'group', 'id': 'xz-admins'}]}]}


class MultiplePersonalTests(unittest.TestCase):
    def settings(self):
        settings = config()
        settings['mounts'] = ['users', 'users-xz']
        settings['safety'] = {'allow_destructive_grants': True}
        return settings

    def test_inventory_matrix_keeps_groups_and_mounts_independent(self):
        report = run(dict(self.settings(), mode='matrix'), declarations(), '', matrix={'source': 'inventory'})
        rows = {(row['mount'], row['path']): row for row in csv.DictReader(io.StringIO(report['_matrix_csv']), delimiter=';')}
        for user_name in ('alice', 'bob'):
            self.assertEqual(rows[('users', user_name + '/*')]['u:' + user_name], 'LRWPMUDVNXZ')
        self.assertEqual(rows[('users-xz', 'dave/*')]['u:dave'], 'LRWPMUDVNXZ')
        for row in rows.values(): self.assertEqual(row['u:carol'], '...........')
        self.assertEqual(rows[('users-xz', 'dave/*')]['u:alice'], '...........')
        self.assertEqual(rows[('users', 'alice/*')]['u:dave'], '...........')

    def test_memberships_combine_without_an_implicit_linux_deny(self):
        desired = declarations()
        next(group for group in desired['groups'] if group['id'] == 'db-admins')['members'].append('carol')
        next(group for group in desired['groups'] if group['id'] == 'xz-admins')['members'].append('alice')
        report = run(dict(self.settings(), mode='matrix'), desired, '', matrix={'source': 'inventory'})
        rows = {(row['mount'], row['path']): row for row in csv.DictReader(io.StringIO(report['_matrix_csv']), delimiter=';')}
        self.assertEqual(rows[('users', 'carol/*')]['u:carol'], 'LRWPMUDVNXZ')
        self.assertEqual(rows[('users', 'alice/*')]['u:alice'], 'LRWPMUDVNXZ')
        self.assertEqual(rows[('users-xz', 'alice/*')]['u:alice'], 'LRWPMUDVNXZ')

    def test_safe_ids_with_dots_work_in_offline_templates(self):
        desired = declarations()
        desired['personal_access'][0]['id'] = 'standard.home'
        report = run(dict(self.settings(), mode='matrix'), desired, '', matrix={'source': 'inventory'})
        self.assertIn('alice/*', report['_matrix_csv'])

    def test_invalid_ids_types_mounts_and_destructive_permissions_fail(self):
        for mutate in (lambda p: p[1].update(id='standard-home'), lambda p: p[0].pop('id'),
                       lambda p: p[0].update(mount='missing'), lambda p: p.append('invalid')):
            desired = declarations()
            mutate(desired['personal_access'])
            with self.assertRaises(ConfigurationError): validate(self.settings(), desired, {})
        settings = self.settings()
        settings['safety']['allow_destructive_grants'] = False
        with self.assertRaisesRegex(ConfigurationError, 'Destructive'): validate(settings, declarations(), {})
        desired = declarations()
        desired['personal_access'] = 'invalid'
        with self.assertRaises(ConfigurationError): validate(self.settings(), desired, {})

    def test_named_personal_namespace_is_preserved_when_only_grants_are_managed(self):
        current = view()
        legacy = policy_name('vam-test-', 'personal')
        named = policy_name('vam-test-', 'personal-standard-home')
        entry = {'uuid': 'alice', 'path': 'identity/entity/id/alice', 'data': {
            'name': 'alice', 'disabled': False, 'metadata': {'vam_owner': 'test', 'vam_id': 'alice'},
            'policies': [legacy, named, 'foreign', 'vam-test-ordinary']}}
        current['entities']['alice'] = entry
        current['objects'][entry['path']] = entry['data']
        settings, desired = validate(self.settings(), {'grants': []}, {})
        planner = Planner(settings, desired, current)
        planner.build()
        self.assertEqual(set(next(model for model in planner.models.values() if model['kind'] == 'entity')['payload']['policies']), {legacy, named, 'foreign'})
        for personal in ([], {'enabled': False}):
            settings, desired = validate(self.settings(), {'personal_access': personal}, {})
            planner = Planner(settings, desired, current)
            planner.build()
            self.assertEqual(set(next(model for model in planner.models.values() if model['kind'] == 'entity')['payload']['policies']), {'foreign', 'vam-test-ordinary'})

    def test_grant_namespace_collision_fails(self):
        desired = {'users': [user()], 'grants': [dict(grant(), id='personal-home')]}
        with self.assertRaisesRegex(ConfigurationError, 'reserved'): validate(config(), desired, {})
