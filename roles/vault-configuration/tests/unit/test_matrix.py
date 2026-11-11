"""Matrix ACL specificity, group provenance and private controller outputs."""
import csv
import io
import json
import tempfile
import unittest
from unittest.mock import Mock

from test_core import config, view, grant, user
import test_stateless
from test_stateless import artifacts
from vault_configuration.matrix import build_matrix, parse_policy, evaluate, POSITIONS
from vault_configuration.validation import validate
from vault_configuration.runner import run
from vault_configuration.common import ConfigurationError


def rows(report):
    return {(row['mount'], row['path']): row for row in csv.DictReader(io.StringIO(report['_matrix_csv']), delimiter=';')}


class MatrixTests(unittest.TestCase):
    def offline(self, sections, settings=None):
        settings = settings or config()
        settings['mode'] = 'matrix'
        return run(settings, sections, '', matrix={'source': 'inventory'})

    def test_fixed_positions_all_permissions_and_distinct_metadata_operations(self):
        settings = config()
        settings['safety'] = {'allow_destructive_grants': True}
        sections = {'users': [user()], 'grants': [grant([permission for permission, _ in POSITIONS])]}
        report = self.offline(sections, settings)
        row = rows(report)[('apps', 'payments/prod/*')]
        self.assertEqual(row['u:alice'], 'LRWPMUDVNXZ')
        self.assertEqual(len(row['u:alice']), 11)
        sections['grants'] = [grant(['delete_latest'])]
        self.assertEqual(rows(self.offline(sections))[('apps', 'payments/prod/*')]['u:alice'], '......D....')

    def test_nested_group_rights_provenance_and_disabled_user(self):
        access = grant(['read'])
        access['subjects'] = [{'kind': 'group', 'id': 'parent'}]
        sections = {'users': [user(), dict(user(), id='bob', name='bob', disabled=True)],
                    'groups': [{'id': 'child', 'name': 'child', 'type': 'internal', 'members': ['alice', 'bob']},
                               {'id': 'parent', 'name': 'parent', 'type': 'internal', 'member_groups': ['child']}],
                    'grants': [access]}
        report = self.offline(sections)
        row = rows(report)[('apps', 'payments/prod/*')]
        for label in ('u:alice', 'g:child', 'g:parent'): self.assertEqual(row[label], '.R.........')
        self.assertEqual(row['u:bob'], '!!!!!!!!!!!')
        notes = json.loads(report['_matrix_notes'])
        self.assertIn('u:alice <- g:child <- g:parent <- grant:access', notes['policy_sources']['u:alice']['grant:access'][0])

    def test_unknown_external_policy_is_not_hidden_by_known_precise_rule(self):
        sections = {'users': [user()], 'grants': [grant(['read']),
                    {'id': 'unknown', 'subjects': [{'kind': 'user', 'id': 'alice'}], 'existing_policies': ['external']}]}
        report = self.offline(sections)
        self.assertEqual(rows(report)[('apps', 'payments/prod/*')]['u:alice'], '???????????')
        self.assertGreater(report['unknown_cells'], 0)

    def test_identity_templates_substitute_known_ldap_login_and_preserve_unknown(self):
        sections = {'users': [dict(user(), aliases=[{'auth_mount': 'ldap', 'name': 'alice'}]), dict(user(), id='bob', name='bob')],
                    'personal_access': {'enabled': True, 'mount': 'users', 'identity_source': 'ldap_login',
                                        'auth_mount': 'ldap', 'path_prefix': 'dep1', 'permissions': ['read', 'write'],
                                        'subjects': [{'kind': 'user', 'id': 'alice'}, {'kind': 'user', 'id': 'bob'}]}}
        report = self.offline(sections)
        self.assertEqual(rows(report)[('users', 'dep1/alice/*')]['u:alice'], '.RW........')
        self.assertTrue(any('{{identity.entity.aliases.' in path for mount, path in rows(report)))
        self.assertIn('Unresolved personal templates', report['_matrix_notes'])

    def test_most_specific_rule_overrides_broad_rule_and_same_patterns_union(self):
        rules = parse_policy('''# broad deny can be overridden by a more specific path
          path "apps/data/*" { capabilities = ["deny"] }
          path "apps/data/team/*" { capabilities = ["read"] }
          path "apps/data/team/*" { capabilities = ["update", "create"] }
          path "apps/data/team/private/*" { capabilities = ["deny"] }
        ''')
        self.assertEqual(evaluate(rules, 'apps/data/team/secret', 'read'), 'allow')
        self.assertEqual(evaluate(rules, 'apps/data/other/secret', 'read'), 'deny')
        self.assertEqual(evaluate(rules, 'apps/data/team/private/secret', 'read'), 'deny')
        self.assertEqual(evaluate(rules, 'apps/data/team/*', 'update'), 'allow')
        self.assertEqual(evaluate(rules, 'apps/data/team/missing', 'delete'), 'absent')

    def test_restrictions_and_plus_masks_are_unknown_and_scoped(self):
        rules = parse_policy('''path "apps/data/team/*" {
            capabilities = ["read"]
            allowed_parameters = { "key" = ["value"] }
        }
        path "infra/data/+/test" { capabilities = ["read"] }''')
        self.assertEqual(evaluate(rules, 'apps/data/team/test', 'read'), 'unknown')
        self.assertEqual(evaluate(rules, 'infra/data/prod/test', 'read'), 'unknown')
        self.assertEqual(evaluate(rules, 'users/data/prod/test', 'read'), 'absent')
        with self.assertRaisesRegex(ConfigurationError, 'unbalanced'):
            parse_policy('path "apps/data/*" { capabilities = ["read"]')

    def test_json_policies_and_comments_empty_policy(self):
        rules = parse_policy(json.dumps({'path': {'apps/data/*': {'capabilities': ['read']}}}))
        self.assertEqual(evaluate(rules, 'apps/data/test', 'read'), 'allow')
        self.assertEqual(parse_policy('/* empty */ # empty\n// empty'), [])
        self.assertTrue(parse_policy('name = "unknown"')[0]['opaque'])

    def test_cluster_model_reads_all_kv_mounts_and_foreign_policies_login_separate(self):
        current = view()
        current['auth'] = {'userpass/': {'type': 'userpass', 'accessor': 'accessor'}}
        current['entities']['id'] = {'path': 'identity/entity/id/id', 'data': {'name': 'alice', 'policies': ['manual']}}
        current['aliases']['a'] = {'kind': 'entity_alias', 'data': {'name': 'alice', 'canonical_id': 'id', 'mount_accessor': 'accessor'}}
        current['policies'] = {'manual': {'data': {'policy': 'path "infra/data/*" {capabilities=["read"]}'}},
                               'login': {'data': {'policy': 'path "infra/data/*" {capabilities=["create", "update"]}'}},
                               'default': {'data': {'policy': ''}}}
        current['userpass'] = {'userpass/alice': {'path': 'auth/userpass/users/alice', 'data': {'token_policies': ['login']}}}
        report = build_matrix(config(), view=current)
        row = rows(report)[('infra', '*')]
        self.assertEqual(row['u:alice'], '.R.........')
        self.assertEqual(row['a:userpass/alice'], '.RW........')
        self.assertNotIn('a:userpass/alice', json.loads(report['_matrix_notes'])['disabled_subjects'])

    def test_cluster_group_cycles_fail_and_valid_nested_groups_inherit(self):
        current = view()
        current['entities']['alice'] = {'path': 'identity/entity/id/alice', 'data': {'name': 'alice', 'policies': []}}
        current['groups'] = {
            'child': {'path': 'identity/group/id/child', 'data': {'name': 'child', 'policies': [], 'member_entity_ids': ['alice']}},
            'parent': {'path': 'identity/group/id/parent', 'data': {'name': 'parent', 'policies': ['read'], 'member_group_ids': ['child']}}}
        current['policies']['read'] = {'data': {'policy': 'path "apps/data/*" {capabilities=["read"]}'}}
        report = build_matrix(config(), view=current)
        self.assertEqual(rows(report)[('apps', '*')]['u:alice'], '.R.........')
        current['groups']['child']['data']['member_group_ids'] = ['parent']
        with self.assertRaisesRegex(ConfigurationError, 'cycle'): build_matrix(config(), view=current)

    def test_inventory_roles_with_same_name_in_different_mounts_are_distinct(self):
        report = self.offline({'auth_roles': [{'id': 'a', 'type': 'approle', 'auth_mount': 'a', 'name': 'backend'},
                                             {'id': 'b', 'type': 'approle', 'auth_mount': 'b', 'name': 'backend'}]})
        self.assertIn('r:a/backend', report['_matrix_csv'])
        self.assertIn('r:b/backend', report['_matrix_csv'])

    def test_partial_write_capabilities_are_unknown(self):
        current = view()
        current['entities']['id'] = {'path': 'identity/entity/id/id', 'data': {'name': 'alice', 'policies': ['partial']}}
        current['policies']['partial'] = {'data': {'policy': 'path "apps/data/*" {capabilities=["create"]}'}}
        self.assertEqual(rows(build_matrix(config(), view=current))[('apps', '*')]['u:alice'], '..?........')

    def test_formula_fields_escaped_and_no_secrets_in_payload(self):
        current = view()
        current['policies']['manual'] = {'data': {'policy': 'path "apps/data/=formula" {capabilities=["read"]}'}}
        current['entities']['id'] = {'path': 'identity/entity/id/id', 'data': {'name': 'alice', 'policies': ['manual'], 'password': 'do-not-export'}}
        report = build_matrix(config(), view=current)
        self.assertIn(('apps', "'=formula"), rows(report))
        self.assertNotIn('do-not-export', json.dumps(report))

    def test_empty_report_has_root_rows_and_no_network_dependency(self):
        report = self.offline({})
        self.assertEqual(report['subjects'], 0)
        self.assertEqual(report['rows'], len(validate(config(), {}, {})[0]['mounts']))
        self.assertIn('mount;path\n', report['_matrix_csv'])


class MatrixArtifactsTests(unittest.TestCase):
    def test_raw_inventory_password_expressions_removed_before_templating(self):
        renderer = Mock()
        renderer.template.side_effect = lambda values: values
        values = {'vault_configuration_users': [dict(user(), password="{{ lookup('file', '/must-not-read') }}")],
                  'vault_configuration_token': "{{ lookup('file', '/must-not-read-token') }}"}
        result = artifacts.inventory_sections(values, renderer)
        self.assertNotIn('password', result['users'][0])
        self.assertNotIn('must-not-read', json.dumps(renderer.template.call_args.args))
        values['vault_configuration_users'] = '{{ arbitrary }}'
        with self.assertRaises(ValueError): artifacts.inventory_sections(values, renderer)

    def test_matrix_controller_files_private_check_mode_and_payload_hidden(self):
        helper = test_stateless.ControllerArtifactsTests()
        with tempfile.TemporaryDirectory() as directory:
            settings = helper.settings(directory)
            settings.update(mode='matrix', matrix_destination='matrix.csv', report_destination=None,
                            execution='target', matrix_source='inventory')
            context = artifacts.context(settings)
            self.assertEqual(context['connection'], 'local')
            payload = {'mode': 'matrix', 'changed': False, '_matrix_csv': 'private-csv', '_matrix_notes': 'private-notes'}
            import pathlib
            result = helper.action({'context': context, 'report': payload}, check=True)
            self.assertTrue(result['changed'])
            self.assertFalse((pathlib.Path(directory) / 'matrix.csv').exists())
            result = helper.action({'context': context, 'report': payload})
            self.assertEqual((pathlib.Path(directory) / 'matrix.csv').stat().st_mode & 0o777, 0o600)
            self.assertTrue((pathlib.Path(directory) / 'matrix.csv.notes.txt').exists())
            self.assertNotIn('private-csv', json.dumps(result))
            self.assertNotIn('private-notes', json.dumps(result))
            settings['matrix_destination'] = 'export.yml'
            with self.assertRaises(ValueError): artifacts.context(settings)

    def test_failure_keeps_previous_matrix_and_notes_unchanged(self):
        helper = test_stateless.ControllerArtifactsTests()
        import pathlib
        with tempfile.TemporaryDirectory() as directory:
            settings = helper.settings(directory)
            settings.update(mode='matrix', matrix_destination='matrix.csv', report_destination=None)
            context = artifacts.context(settings)
            context['mode'] = test_stateless.AnsibleUnsafeText('matrix')
            csv_path = pathlib.Path(directory) / 'matrix.csv'
            notes_path = pathlib.Path(directory) / 'matrix.csv.notes.txt'
            csv_path.write_text('previous csv')
            notes_path.write_text('previous notes')
            result = helper.action({'context': context, 'report': {'mode': 'matrix', 'error': 'API read failed'}})
            self.assertFalse(result['changed'])
            self.assertEqual(csv_path.read_text(), 'previous csv')
            self.assertEqual(notes_path.read_text(), 'previous notes')
