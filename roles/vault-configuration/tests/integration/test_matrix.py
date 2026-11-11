"""Actual Vault ACL comparisons and Ansible online/offline CSV publishing."""
import copy
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_vault import ROOT, Server
from vault_configuration.runner import run
from vault_configuration.client import Client


def rows(report):
    return {row['path']: row for row in csv.DictReader(io.StringIO(report['_matrix_csv']), delimiter=';') if row['mount'] == 'apps'}


class MatrixIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='matrix-', dir=str(ROOT / '.work'))
        cls.directory = Path(cls.temporary.name)
        cls.server = Server(cls.directory)

    @classmethod
    def tearDownClass(cls):
        cls.server.close()
        cls.temporary.cleanup()

    def setUp(self):
        self.client = self.server.client
        self.name = self._testMethodName.replace('test_', '')
        self.config = {'mode': 'matrix', 'connection': self.server.connection, 'mounts': ['apps'],
                       'management': {'owner': self.name, 'policy_prefix': 'vam-' + self.name + '-'}}

    def policy(self, suffix, text):
        name = self.name + '-' + suffix
        self.client.request('POST', 'sys/policies/acl/' + name, {'policy': text})
        return name

    def test_acl_priority_union_and_deny_match_vault_capabilities(self):
        broad = self.policy('broad', 'path "apps/data/*" { capabilities = ["deny"] }')
        specific = self.policy('specific', '''path "apps/data/team/*" { capabilities = ["read"] }
            path "apps/data/team/private/*" { capabilities = ["deny"] }
            path "apps/data/team/concrete" { capabilities = ["read", "create"] }''')
        equal = self.policy('equal', 'path "apps/data/team/*" { capabilities = ["create", "update"] }')
        entity = self.client.request('POST', 'identity/entity', {'name': self.name, 'policies': [broad, specific, equal]})['data']['id']
        token = self.client.request('POST', 'auth/token/create', {'policies': [broad, specific, equal], 'no_default_policy': True})['auth']['client_token']
        self.client.requests.clear()
        report = run(self.config, {}, self.server.token, client=self.client, matrix={'source': 'cluster'})
        self.assertTrue(all(entry['method'] in {'GET', 'LIST'} for entry in self.client.requests))
        self.assertFalse(any('/data/' in entry['path'] for entry in self.client.requests))
        result = rows(report)
        label = 'u:' + self.name
        self.assertEqual(result['team/*'][label], '.RW........')
        self.assertEqual(result['team/private/*'][label], '.!!!..!....')
        self.assertEqual(result['team/concrete'][label], '.R?........')
        for relative in ('team/example', 'team/private/example', 'other/example', 'team/concrete'):
            actual = self.client.request('POST', 'sys/capabilities', {'token': token, 'paths': ['apps/data/' + relative]})['data']['capabilities']
            if relative == 'team/example': self.assertEqual(set(actual), {'read', 'create', 'update'})
            elif relative == 'team/concrete': self.assertEqual(set(actual), {'read', 'create'})
            else: self.assertEqual(actual, ['deny'])
        self.assertNotIn(entity, report['_matrix_csv'])

    def test_ldap_mappings_groups_login_baseline_and_personal_templates(self):
        mount = 'ldap-' + self.name
        self.client.request('POST', 'sys/auth/' + mount, {'type': 'ldap'})
        base = self.policy('base', 'path "apps/metadata/*" { capabilities = ["list"] }')
        group_policy = self.policy('group', 'path "apps/data/team/*" { capabilities = ["read"] }')
        self.client.request('POST', 'auth/' + mount + '/config', {'url': 'ldap://127.0.0.1:389', 'userdn': 'dc=test',
            'groupdn': 'dc=test', 'token_policies': [base]})
        self.client.request('POST', 'auth/' + mount + '/groups/dev', {'policies': [group_policy]})
        self.client.request('POST', 'auth/' + mount + '/users/alice', {'groups': ['dev']})
        accessor = self.client.read('sys/auth')[mount + '/']['accessor']
        personal = self.policy('personal', 'path "apps/data/dep1/{{identity.entity.aliases.' + accessor + '.name}}/*" { capabilities = ["read", "create", "update"] }')
        entity = self.client.request('POST', 'identity/entity', {'name': self.name, 'policies': [personal]})['data']['id']
        self.client.request('POST', 'identity/entity-alias', {'name': 'alice', 'canonical_id': entity, 'mount_accessor': accessor})
        self.client.requests.clear()
        report = run(self.config, {}, self.server.token, client=self.client)
        self.assertTrue(all(entry['method'] in {'GET', 'LIST'} for entry in self.client.requests))
        result = rows(report)
        self.assertEqual(result['team/*']['ldap-group:' + mount + '/dev'], '.R.........')
        self.assertEqual(result['team/*']['a:' + mount + '/alice'], 'LR.........')
        self.assertEqual(result['dep1/alice/*']['u:' + self.name], '.RW........')
        self.assertEqual(result['dep1/alice/*']['a:' + mount + '/alice'], 'LRW........')
        self.assertNotIn(self.server.token, report['_matrix_notes'])

    def test_ansible_cluster_writes_controller_files_ignores_desired_passwords(self):
        work = self.directory / self.name
        work.mkdir()
        variables = {'vault_configuration_config_mode': 'matrix', 'vault_configuration_api_scheme': 'http',
                     'vault_configuration_api_port': self.server.port, 'vault_configuration_token': self.server.token,
                     'vault_configuration_matrix_destination': 'reports/access.csv',
                     'vault_configuration_users': "{{ lookup('file', '/do-not-read-users') }}",
                     'vault_configuration_passwords': "{{ lookup('file', '/do-not-read-passwords') }}"}
        result = ansible(work, variables)
        self.assertEqual(result.returncode, 0, result.stdout)
        csv_file = work / 'reports/access.csv'
        self.assertEqual(csv_file.stat().st_mode & 0o777, 0o600)
        self.assertTrue((work / 'reports/access.csv.notes.txt').exists())
        self.assertNotIn(self.server.token, result.stdout)
        self.assertNotIn('_matrix_csv', result.stdout)


def ansible(work, variables, check=False, host='localhost'):
    inventory = work / 'hosts.ini'
    inventory.write_text(host + ' ansible_host=192.0.2.123 ansible_connection=ssh\n')
    play = [{'hosts': 'all', 'gather_facts': False, 'vars': variables, 'roles': ['vault-configuration']}]
    playbook = work / 'play.yml'
    playbook.write_text(json.dumps(play))
    environment = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / 'ansible.cfg'), ANSIBLE_ROLES_PATH=str(ROOT / 'roles'))
    command = ['ansible-playbook', '-i', str(inventory), str(playbook)]
    if check: command.append('--check')
    return subprocess.run(command, env=environment, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


class OfflineMatrixIntegration(unittest.TestCase):
    def test_no_ssh_api_token_or_password_lookup_and_check_mode(self):
        with tempfile.TemporaryDirectory(prefix='matrix-offline-', dir=str(ROOT / '.work')) as temporary:
            work = Path(temporary)
            variables = {'vault_configuration_config_mode': 'matrix', 'vault_configuration_matrix_source': 'inventory',
                         'vault_configuration_api_execution': 'target', 'vault_configuration_matrix_destination': 'offline.csv',
                         'vault_configuration_token': "{{ lookup('file', '/do-not-read-token') }}",
                         'vault_configuration_passwords': "{{ lookup('file', '/do-not-read-passwords') }}",
                         'vault_configuration_ldap_passwords': "{{ lookup('file', '/do-not-read-bindpass') }}",
                         'vault_configuration_ldap': "{{ lookup('file', '/do-not-read-ldap') }}",
                         'vault_configuration_users': [{'id': 'alice', 'name': 'alice', 'source': 'userpass', 'auth_mount': 'local',
                            'login': 'alice', 'password': "{{ lookup('file', '/do-not-read-inline-password') }}"}],
                         'vault_configuration_grants': [{'id': 'access', 'subjects': [{'kind': 'user', 'id': 'alice'}],
                            'paths': [{'mount': 'infra', 'path': 'team', 'scope': 'subtree', 'permissions': ['list', 'read', 'write']}]}]}
            checked = ansible(work, variables, check=True, host='vault.invalid')
            self.assertEqual(checked.returncode, 0, checked.stdout)
            self.assertFalse((work / 'offline.csv').exists())
            result = ansible(work, variables, host='vault.invalid')
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertTrue((work / 'offline.csv').exists())
            matrix = list(csv.DictReader(io.StringIO((work / 'offline.csv').read_text()), delimiter=';'))
            row = next(row for row in matrix if row['mount'] == 'infra' and row['path'] == 'team/*')
            self.assertEqual(row['u:alice'], 'LRW........')
            contents = (work / 'offline.csv').read_text() + (work / 'offline.csv.notes.txt').read_text() + result.stdout
            self.assertNotIn('do-not-read', contents)
