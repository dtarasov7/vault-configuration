"""Real Vault and Ansible tests for registry-free execution and controller outputs."""
import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from test_vault import Server, ROOT
from vault_configuration.runner import run
from vault_configuration.client import Client, VaultHTTPError
from vault_configuration.executor import PartialApply
from vault_configuration.compiler import policy_name


class StatelessIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='stateless-', dir=str(ROOT / '.work'))
        cls.root = Path(cls.temporary.name)
        cls.server = Server(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.server.close()
        cls.temporary.cleanup()

    def setUp(self):
        self.name = self._testMethodName.replace('test_', '')
        self.work = self.root / self.name
        self.work.mkdir()
        self.config = {'mode': 'apply', 'connection': self.server.connection, 'mounts': ['apps'],
                       'management': {'owner': self.name, 'policy_prefix': 'vam-' + self.name + '-'}}
        self.sections = {'users': [{'id': self.name, 'name': self.name, 'source': 'userpass',
                                    'auth_mount': 'userpass', 'login': self.name}],
                         'grants': [{'id': 'read', 'subjects': [{'kind': 'user', 'id': self.name}],
                                     'paths': [{'mount': 'apps', 'path': self.name, 'scope': 'subtree', 'permissions': ['read']}]}]}
        self.password = 'fixture-secret-' + self.name[:20]

    def apply(self, sections=None, passwords=None):
        return run(self.config, self.sections if sections is None else sections, self.server.token,
                   passwords={self.name: self.password} if passwords is None else passwords)

    def test_fresh_controller_rename_and_omitted_objects_need_no_registry(self):
        legacy = self.work / 'state.json'
        legacy.write_text('unrelated invalid legacy registry')
        self.assertTrue(self.apply()['changed'])
        self.assertFalse(self.apply(passwords={})['changed'])
        uuid = self.server.client.read('identity/entity/name/' + self.name)['id']
        self.sections['users'][0]['name'] += '-renamed'
        self.assertTrue(self.apply(passwords={})['changed'])
        self.assertEqual(self.server.client.read('identity/entity/name/' + self.name + '-renamed')['id'], uuid)
        self.apply({'users': [], 'groups': [], 'grants': []}, passwords={})
        self.assertIsNotNone(self.server.client.read('identity/entity/id/' + uuid))
        self.assertEqual(self.server.client.read('identity/entity/id/' + uuid)['policies'], [])
        self.assertEqual(legacy.read_text(), 'unrelated invalid legacy registry')
        self.assertEqual(list(self.work.iterdir()), [legacy])

    def test_owned_policy_detach_preserves_manual_policy_and_other_owner(self):
        self.apply()
        client = self.server.client
        uuid = client.read('identity/entity/name/' + self.name)['id']
        own = policy_name(self.config['management']['policy_prefix'], 'read')
        client.request('POST', 'sys/policies/acl/manual-' + self.name,
                       {'policy': 'path "apps/data/manual" { capabilities = ["read"] }'})
        other = 'other-owner-' + self.name
        client.request('POST', 'sys/policies/acl/' + other,
                       {'policy': 'path "apps/data/other" { capabilities = ["read"] }'})
        client.request('POST', 'identity/entity/id/' + uuid, {'policies': [own, 'manual-' + self.name, other]})
        result = self.apply({'grants': []}, passwords={})
        self.assertTrue(result['changed'])
        self.assertEqual(set(client.read('identity/entity/id/' + uuid)['policies']), {'manual-' + self.name, other})
        self.assertIsNotNone(client.read('sys/policies/acl/' + own))
        self.assertFalse(self.apply({'grants': []}, passwords={})['changed'])

    def test_explicit_password_write_response_loss_has_no_automatic_retry(self):
        self.apply()
        changed_sections = copy.deepcopy(self.sections)
        changed_sections['users'][0]['password_policy'] = 'always'
        server = self.server
        path = 'auth/userpass/users/' + self.name
        class LostReply(Client):
            def request(self, method, api_path, payload=None, missing=False):
                result = super().request(method, api_path, payload, missing)
                if method == 'POST' and api_path == path:
                    raise VaultHTTPError(method, 'transport', True)
                return result
        client = LostReply(server.connection, server.token)
        replacement = self.password + '-replacement'
        with self.assertRaises(PartialApply) as raised:
            run(self.config, changed_sections, server.token, passwords={self.name: replacement}, client=client)
        self.assertTrue(raised.exception.uncertain['password_write'])
        self.assertNotIn(replacement, str(raised.exception) + json.dumps(raised.exception.uncertain))
        server.client.request('POST', 'auth/userpass/login/' + self.name, {'password': replacement})
        self.assertFalse(self.apply(passwords={})['changed'])
        self.assertEqual(list(self.work.iterdir()), [])

    def ansible(self, directory, hostname='localhost', execution='controller', loopback=False, mode='apply', extra=None, limit=None, multi=False):
        directory.mkdir(exist_ok=True)
        inventory = directory / 'hosts.ini'
        inventory.write_text('[selected]\n' + hostname + ' ansible_connection=' + ('local' if execution == 'target' else 'ssh') +
                             ' ansible_host=192.0.2.123\n' + ('[others]\nother.invalid\n' if multi else ''))
        variables = {'vault_configuration_api_execution': execution, 'vault_configuration_api_scheme': 'http',
                     'vault_configuration_api_port': self.server.port, 'vault_configuration_api_use_loopback': loopback,
                     'vault_configuration_config_mode': mode, 'vault_configuration_token': self.server.token,
                     'vault_configuration_config_mounts': ['apps'],
                     'vault_configuration_config_management_owner': self.name,
                     'vault_configuration_config_management_policy_prefix': 'vam-' + self.name + '-',
                     'vault_configuration_passwords': {self.name: self.password}}
        variables.update({'vault_configuration_' + key: value for key, value in self.sections.items()})
        variables.update(extra or {})
        play = [{'hosts': 'all', 'gather_facts': False, 'vars': variables, 'roles': ['vault-configuration']}]
        playbook = directory / 'play.yml'
        playbook.write_text(json.dumps(play))
        environment = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / 'ansible.cfg'), ANSIBLE_ROLES_PATH=str(ROOT / 'roles'))
        command = ['ansible-playbook', '-i', str(inventory), str(playbook)]
        if limit: command += ['--limit', limit]
        response = subprocess.run(command, env=environment, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.assertNotIn(self.server.token, response.stdout)
        self.assertNotIn(self.password, response.stdout)
        return response

    def test_controller_only_api_no_ssh_dry_export_and_second_controller(self):
        first = self.work / 'controller-a'
        dry = self.ansible(first, mode='dry', multi=True, limit='selected')
        self.assertEqual(dry.returncode, 0, dry.stdout)
        report = first / 'vault-configuration-localhost-dry.yml'
        self.assertTrue(report.exists())
        self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
        self.assertIsNone(self.server.client.read('identity/entity/name/' + self.name, missing=True))
        applied = self.ansible(first)
        self.assertEqual(applied.returncode, 0, applied.stdout)
        second = self.work / 'controller-b'
        repeated = self.ansible(second, extra={'vault_configuration_passwords': {}})
        self.assertEqual(repeated.returncode, 0, repeated.stdout)
        self.assertIn('changed=0', repeated.stdout)
        exported = self.ansible(second, mode='export', extra={'vault_configuration_export_destination': 'exports/access.yml',
                               'vault_configuration_passwords': "{{ lookup('file', '/must-not-evaluate-passwords') }}"})
        self.assertEqual(exported.returncode, 0, exported.stdout)
        self.assertTrue((second / 'exports/access.yml').is_file())
        self.assertTrue((second / 'exports/access.yml.audit.json').is_file())
        self.assertFalse((ROOT / 'exports/access.yml').exists())
        self.assertFalse(list(self.work.rglob('state.json')))

    def test_target_execution_uses_loopback_and_outputs_stay_on_controller(self):
        controller = self.work / 'controller'
        applied = self.ansible(controller, hostname='vault-target.invalid', execution='target', loopback=True)
        self.assertEqual(applied.returncode, 0, applied.stdout)
        dry = self.ansible(controller, hostname='vault-target.invalid', execution='target', loopback=True, mode='dry')
        self.assertEqual(dry.returncode, 0, dry.stdout)
        self.assertTrue((controller / 'vault-configuration-vault-target.invalid-dry.yml').exists())
        invalid = self.ansible(controller, hostname='vault-target.invalid', execution='controller', loopback=True)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn('only with api_execution: target', invalid.stdout)

    def test_multi_target_fails_before_api_and_legacy_settings_are_rejected(self):
        controller = self.work / 'controller'
        response = self.ansible(controller, multi=True)
        self.assertNotEqual(response.returncode, 0)
        self.assertIn('Select exactly one Vault target', response.stdout)
        for key, value in [('vault_configuration_execution_host', 'localhost'),
                           ('vault_configuration_config_management_state_file', '/tmp/obsolete.json'),
                           ('vault_configuration_config_management_prune', True)]:
            response = self.ansible(controller, extra={key: value})
            self.assertNotEqual(response.returncode, 0)
            self.assertIn('Require flat configuration', response.stdout)
