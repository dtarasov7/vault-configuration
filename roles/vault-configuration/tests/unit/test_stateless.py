"""Stateless ownership, password rules and controller artifact safety."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from ansible.utils.unsafe_proxy import AnsibleUnsafeText

from test_core import ROLE, config, view, user, grant
from vault_configuration.validation import validate
from vault_configuration.planner import Planner
from vault_configuration.compiler import policy_name
from vault_configuration.common import ConfigurationError

spec = importlib.util.spec_from_file_location('artifact_action', ROLE / 'action_plugins/vault_configuration_report.py')
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


class StatelessPlannerTests(unittest.TestCase):
    def plan(self, sections, current=None):
        settings, desired = validate(config(), sections, {})
        planner = Planner(settings, desired, current or view())
        return planner, planner.build()

    def owned(self, current, identifier='alice', kind='entity', policies=None):
        data = {'name': identifier, 'metadata': {'vam_owner': 'test', 'vam_id': identifier},
                'policies': sorted(policies or [])}
        if kind == 'entity': data['disabled'] = False
        else: data.update(type='internal', member_entity_ids=[], member_group_ids=[])
        entry = {'uuid': identifier, 'path': 'identity/' + kind + '/id/' + identifier, 'data': data}
        current['entities' if kind == 'entity' else 'groups'][identifier] = entry
        current['objects'][entry['path']] = data
        return entry

    def test_same_metadata_adopts_live_identity_without_local_history(self):
        current = view()
        self.owned(current)
        _, plan = self.plan({'users': [user()]}, current)
        self.assertEqual([operation['action'] for operation in plan['operations']], ['noop'])
        declaration = dict(user(), name='renamed')
        planner, _ = self.plan({'users': [declaration]}, current)
        self.assertEqual(planner.identifiers['entity:alice'], 'alice')

    def test_foreign_owner_and_unmarked_identity_require_explicit_action(self):
        current = view()
        entry = self.owned(current)
        entry['data']['metadata']['vam_owner'] = 'other'
        with self.assertRaises(ConfigurationError): self.plan({'users': [user()]}, current)
        entry['data']['metadata'] = {}
        with self.assertRaisesRegex(ConfigurationError, 'adoption'): self.plan({'users': [user()]}, current)

    def test_omitted_scope_keeps_policies_and_empty_scope_detaches_only_own_prefix(self):
        current = view()
        entry = self.owned(current, policies=['foreign', 'vam-test-old'])
        _, preserved = self.plan({'users': [user()], 'grants': None}, current)
        self.assertEqual(preserved['operations'][0]['action'], 'noop')
        planner, changed = self.plan({'grants': []}, current)
        self.assertEqual(len(changed['operations']), 1)
        model = next(iter(planner.models.values()))
        self.assertEqual(model['payload']['policies'], ['foreign'])
        self.assertEqual(entry['data']['policies'], ['foreign', 'vam-test-old'])
        self.assertFalse(any(operation['action'] == 'delete' for operation in changed['operations']))

    def test_personal_and_ordinary_scopes_are_independent(self):
        current = view()
        personal = policy_name('vam-test-', 'personal')
        self.owned(current, policies=[personal, 'vam-test-old', 'foreign'])
        planner, _ = self.plan({'personal_access': {'enabled': False}}, current)
        self.assertEqual(next(iter(planner.models.values()))['payload']['policies'], ['foreign', 'vam-test-old'])

    def test_internal_group_membership_is_authoritative(self):
        current = view()
        group = self.owned(current, 'team', 'group')
        group['data']['member_entity_ids'] = ['foreign-member']
        planner, _ = self.plan({'groups': [{'id': 'team', 'name': 'team', 'type': 'internal', 'members': []}]}, current)
        self.assertEqual(planner.models['group:team']['payload']['member_entity_ids'], [])

    def test_duplicate_live_inventory_id_is_rejected(self):
        current = view()
        self.owned(current)
        duplicate = copy.deepcopy(current['entities']['alice'])
        duplicate['uuid'] = 'other'
        current['entities']['other'] = duplicate
        with self.assertRaisesRegex(ConfigurationError, 'Duplicate'): self.plan({'users': [user()]}, current)

    def test_removed_registry_and_revision_inputs_fail_validation(self):
        for key, value in [('state_file', '/tmp/state.json'), ('prune', True), ('recovery', {})]:
            settings = config()
            settings['management'][key] = value
            with self.assertRaises(ConfigurationError): validate(settings, {}, {})
        with self.assertRaises(ConfigurationError):
            self.plan({'users': [dict(user(), source='userpass', auth_mount='local', login='alice', password_revision='r1')]})

    def test_missing_password_fails_during_planning(self):
        with self.assertRaisesRegex(ConfigurationError, 'password is missing'):
            self.plan({'users': [dict(user(), source='userpass', auth_mount='local', login='alice')]})

    def test_adoption_is_explicit_and_protected_objects_stay_protected(self):
        current = view()
        entry = self.owned(current)
        entry['data']['metadata'] = {}
        settings = config()
        settings['management']['adoption'] = [{'kind': 'entity', 'id': 'alice', 'uuid': 'alice'}]
        normalized, sections = validate(settings, {'users': [user()]}, {})
        planner = Planner(normalized, sections, current)
        planner.build()
        self.assertEqual(planner.models['entity:alice']['payload']['metadata']['vam_owner'], 'test')
        settings['safety'] = {'protected_entities': ['alice']}
        normalized, sections = validate(settings, {'users': [user()]}, {})
        with self.assertRaisesRegex(ConfigurationError, 'Protected'):
            Planner(normalized, sections, current).build()

    def test_existing_user_password_needs_explicit_always_policy(self):
        current = view()
        self.owned(current)
        current['auth']['local/'] = {'type': 'userpass', 'accessor': 'local-accessor'}
        current['userpass']['local/alice'] = {'path': 'auth/local/users/alice', 'data': {'token_policies': []}}
        declaration = dict(user(), source='userpass', auth_mount='local', login='alice')
        planner, _ = self.plan({'users': [declaration]}, current)
        self.assertIsNone(planner.models['userpass:alice']['password'])
        declaration.update(password_policy='always', password='fixture-password')
        planner, plan = self.plan({'users': [declaration]}, current)
        self.assertEqual(planner.models['userpass:alice']['password'], 'fixture-password')
        self.assertNotIn('fixture-password', json.dumps(plan))

    def test_ldap_bind_password_is_not_repeated_without_always(self):
        current = view()
        current['auth']['ldap/'] = {'type': 'ldap', 'accessor': 'ldap-accessor'}
        current['objects']['auth/ldap/config'] = {'url': 'ldaps://dc.example.org:636',
            'binddn': 'cn=service,dc=example,dc=org', 'userdn': 'dc=example,dc=org', 'groupdn': 'dc=example,dc=org'}
        item = {'id': 'directory', 'auth_mount': 'ldap', 'config': dict(current['objects']['auth/ldap/config'])}
        planner, _ = self.plan({'ldap': [item]}, current)
        self.assertIsNone(planner.models['ldap_config:directory']['password'])
        item['bind_password_policy'] = 'always'
        with self.assertRaisesRegex(ConfigurationError, 'bind password is missing'):
            self.plan({'ldap': [item]}, current)


class ControllerArtifactsTests(unittest.TestCase):
    def settings(self, root):
        return dict(hostname='vault.example.org', execution='controller', scheme='https', port=8200,
                    loopback=False, root=root, mode='dry', report_destination='dry.yml',
                    destination='export.yml', audit_destination='export.audit.json', controller_python='/python')

    def action(self, args, check=False):
        action = artifacts.ActionModule.__new__(artifacts.ActionModule)
        action._task = SimpleNamespace(args=args, check_mode=check)
        with patch('ansible.plugins.action.ActionBase.run', return_value={}):
            return action.run()

    def test_endpoint_uses_hostname_and_controller_connection_is_always_local(self):
        values = self.settings('/playbooks')
        values['target_connection'] = 'ssh'
        context = artifacts.context(values)
        self.assertEqual(context['address'], 'https://vault.example.org:8200')
        self.assertEqual(context['delegate'], 'localhost')
        self.assertEqual(context['connection'], 'local')
        self.assertEqual(context['report_destination'], '/playbooks/dry.yml')
        values.update(port='8200', loopback='false')
        self.assertEqual(artifacts.context(values)['address'], 'https://vault.example.org:8200')

    def test_loopback_only_on_target_and_tls_not_implicitly_disabled(self):
        values = self.settings('/playbooks')
        values['loopback'] = True
        with self.assertRaises(ValueError): artifacts.context(values)
        values['execution'] = 'target'
        context = artifacts.context(values)
        self.assertEqual(context['address'], 'https://127.0.0.1:8200')
        self.assertNotIn('validate_tls', context)
        self.assertEqual(context['delegate'], 'vault.example.org')

    def test_invalid_host_port_and_scheme_fail_before_api(self):
        for key, value in [('hostname', '192.0.2.1'), ('hostname', 'bad/name'), ('port', 0),
                           ('port', True), ('scheme', 'ftp'), ('execution', 'other')]:
            args = self.settings('/playbooks')
            args[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): artifacts.context(args)

    def test_relative_outputs_collision_and_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            args = self.settings(root)
            args['audit_destination'] = 'export.yml'
            with self.assertRaises(ValueError): artifacts.context(args)
            args['audit_destination'] = 'audit.json'
            os.symlink('export.yml', os.path.join(root, 'dry.yml'))
            with self.assertRaises(ValueError): artifacts.context(args)

    def test_private_atomic_files_and_check_mode(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, 'private', 'nested', 'dry.yml')
            self.assertTrue(artifacts.atomic_write(path, 'content\n', True))
            self.assertFalse(os.path.exists(os.path.dirname(path)))
            self.assertTrue(artifacts.atomic_write(path, 'content\n'))
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(root, 'private')).st_mode), 0o700)
            self.assertFalse(artifacts.atomic_write(path, 'content\n'))
            os.chmod(path, 0o644)
            self.assertTrue(artifacts.atomic_write(path, 'content\n'))

    def test_export_payload_is_saved_but_never_printed(self):
        with tempfile.TemporaryDirectory() as root:
            args = self.settings(root)
            args.update(mode='export', report_destination=None)
            context = artifacts.context(args)
            report = {'mode': 'export', 'changed': False, '_export_variables': {'private-payload': 'value'},
                      '_export_audit': {'objects': []}}
            result = self.action({'context': context, 'report': report})
            self.assertTrue(result['changed'])
            self.assertNotIn('private-payload', json.dumps(result))
            self.assertIn('private-payload', Path(context['destination']).read_text())
            self.assertFalse(self.action({'context': context, 'report': report})['changed'])

    def test_dry_file_is_controller_local_and_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as root:
            context = artifacts.context(self.settings(root))
            report = {'mode': 'dry', 'changed': False, 'error': 'safe failure'}
            result = self.action({'context': context, 'report': report}, check=True)
            self.assertTrue(result['changed'])
            self.assertFalse(Path(context['report_destination']).exists())
            self.action({'context': context, 'report': report})
            self.assertIn('safe failure', Path(context['report_destination']).read_text())

    def test_ansible_unsafe_strings_are_serialized_without_evaluation(self):
        with tempfile.TemporaryDirectory() as root:
            context = artifacts.context(self.settings(root))
            template = "{{ lookup('file', '/must-not-read') }}"
            report = {AnsibleUnsafeText('mode'): AnsibleUnsafeText('dry'), 'changed': False,
                      AnsibleUnsafeText('literal'): AnsibleUnsafeText(template)}
            result = self.action({'context': context, 'report': report})
            self.assertFalse(result.get('failed', False))
            self.assertEqual(artifacts.yaml.safe_load(Path(context['report_destination']).read_text())['literal'], template)
