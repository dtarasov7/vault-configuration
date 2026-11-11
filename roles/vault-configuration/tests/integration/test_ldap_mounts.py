"""Real LDAP logins and create-only mounts on an isolated Vault and OpenLDAP."""
import copy
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import yaml

from test_vault import Server, ROOT, free_port
from vault_configuration.client import Client, VaultHTTPError
from vault_configuration.common import ConfigurationError
from vault_configuration.runner import run
from vault_configuration.validation import DEFAULTS
from vault_configuration.compiler import policy_name

LDAP_IMAGE = 'osixia/openldap:1.5.0@sha256:18742e9c449c9c1afe129d3f2f3ee15fb34cc43e5f940a20f3399728f41d7c28'


class LDAPAndMounts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='vault-ldap-', dir=str(ROOT / '.work'))
        cls.directory = Path(cls.temporary.name)
        cls.server = Server(cls.directory)
        cls.client = cls.server.client
        cls.ldap_port = free_port()
        cls.container = 'vault-configuration-ldap-' + str(cls.ldap_port)
        subprocess.run(['docker', 'run', '--rm', '-d', '--name', cls.container,
                        '-p', '127.0.0.1:' + str(cls.ldap_port) + ':389',
                        '-e', 'LDAP_DOMAIN=example.test', '-e', 'LDAP_ORGANISATION=Role Test',
                        '-e', 'LDAP_ADMIN_PASSWORD=fixture-admin', '-e', 'LDAP_TLS=false', LDAP_IMAGE],
                       check=True, stdout=subprocess.DEVNULL)
        base = ['docker', 'exec', '-i', cls.container, 'ldapadd', '-x', '-H', 'ldap://127.0.0.1',
                '-D', 'cn=admin,dc=example,dc=test', '-w', 'fixture-admin']
        ready = ['docker', 'exec', cls.container, 'ldapwhoami', '-x', '-H', 'ldap://127.0.0.1',
                 '-D', 'cn=admin,dc=example,dc=test', '-w', 'fixture-admin']
        for attempt in range(100):
            response = subprocess.run(ready, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            startup = subprocess.run(['docker', 'logs', cls.container], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            if response.returncode == 0 and 'Running /container/run/process/slapd/run' in startup.stdout:
                break
            time.sleep(0.1)
        else:
            cls.tearDownClass()
            raise RuntimeError('OpenLDAP fixture did not become ready')
        ldif = '''dn: ou=people,dc=example,dc=test
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=example,dc=test
objectClass: organizationalUnit
ou: groups

dn: uid=alice,ou=people,dc=example,dc=test
objectClass: inetOrgPerson
cn: Alice
sn: Alice
uid: alice
userPassword: fixture-alice

dn: uid=bob,ou=people,dc=example,dc=test
objectClass: inetOrgPerson
cn: Bob
sn: Bob
uid: bob
userPassword: fixture-bob

dn: cn=developers,ou=groups,dc=example,dc=test
objectClass: groupOfNames
cn: developers
member: uid=alice,ou=people,dc=example,dc=test
'''
        subprocess.run(base, input=ldif, text=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    @classmethod
    def tearDownClass(cls):
        subprocess.run(['docker', 'rm', '-f', cls.container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.server.close()
        cls.temporary.cleanup()

    def config(self, name):
        configuration = copy.deepcopy(DEFAULTS)
        configuration.update(mode='apply', connection=self.server.connection)
        configuration['mounts'] = [name]
        configuration['management'].update(owner=name, policy_prefix='vam-' + name + '-')
        return configuration

    def integration(self, name):
        return [{'id': name, 'auth_mount': name, 'bind_password_policy': 'on_create', 'allow_insecure_ldap': True,
                 'config': {'url': 'ldap://127.0.0.1:' + str(self.ldap_port),
                            'binddn': 'cn=admin,dc=example,dc=test', 'userdn': 'ou=people,dc=example,dc=test',
                            'groupdn': 'ou=groups,dc=example,dc=test', 'userattr': 'uid', 'groupattr': 'cn',
                            'groupfilter': '(&(objectClass=groupOfNames)(member={{.UserDN}}))'}}]

    def test_create_mounts_ldap_login_and_group_permissions(self):
        name = 'ldap-real'
        config = self.config(name)
        sections = {'ldap': self.integration(name), 'groups': [
            {'id': 'developers', 'name': name + '-developers', 'type': 'external',
             'alias': {'auth_mount': name, 'name': 'Developers'}}],
            'grants': [{'id': 'read', 'subjects': [{'kind': 'group', 'id': 'developers'}],
                        'paths': [{'mount': name, 'path': 'payments/prod', 'scope': 'subtree', 'permissions': ['read']}]}]}
        for mode, check_mode in [('dry', False), ('apply', True)]:
            client = Client(self.server.connection, self.server.token)
            result = run(dict(config, mode=mode), sections, self.server.token,
                         ldap_passwords={name: 'fixture-admin'}, check_mode=check_mode, client=client, diff=True)
            self.assertNotIn(name + '/', self.client.read('sys/mounts'))
            self.assertNotIn(name + '/', self.client.read('sys/auth'))
            self.assertTrue(all(request['method'] in {'GET', 'LIST'} for request in client.requests))
            self.assertNotIn('fixture-admin', json.dumps(result))
        self.assertTrue(run(config, sections, self.server.token, ldap_passwords={name: 'fixture-admin'})['changed'])
        self.assertFalse(run(config, sections, self.server.token)['changed'])
        self.client.request('POST', 'auth/' + name + '/config', {'token_ttl': 300})
        sections['ldap'][0]['config']['connection_timeout'] = 12
        self.assertTrue(run(config, sections, self.server.token)['changed'])
        self.assertEqual(self.client.read('auth/' + name + '/config')['token_ttl'], 300)
        self.client.request('POST', name + '/data/payments/prod/backend', {'data': {'value': 'fixture'}})
        alice = self.client.request('POST', 'auth/' + name + '/login/alice', {'password': 'fixture-alice'})
        ordinary = Client(self.server.connection, alice['auth']['client_token'])
        self.assertEqual(ordinary.read(name + '/data/payments/prod/backend')['data']['value'], 'fixture')
        bob = self.client.request('POST', 'auth/' + name + '/login/bob', {'password': 'fixture-bob'})
        denied = Client(self.server.connection, bob['auth']['client_token'])
        with self.assertRaises(VaultHTTPError):
            denied.read(name + '/data/payments/prod/backend')
        with self.assertRaises(VaultHTTPError):
            self.client.request('POST', 'auth/' + name + '/login/alice', {'password': 'wrong-fixture'})
        exported = self.directory / name / 'export.yml'
        result = run(dict(config, mode='export'), {}, self.server.token, export={'destination': str(exported)})
        exported.parent.mkdir(parents=True, exist_ok=True)
        exported_text = yaml.safe_dump(result['_export_variables'], allow_unicode=True, sort_keys=True)
        exported.write_text(exported_text)
        variables = yaml.safe_load(exported_text)
        self.assertFalse(exported_text.lstrip().startswith('{'))
        self.assertEqual(variables['vault_configuration_ldap'][0]['auth_mount'], name)
        self.assertNotIn('fixture-admin', exported.read_text())
        self.assertNotIn('fixture-admin', json.dumps(result))
        # The exported Go filters must survive a real vars_files round trip on another Vault.
        target_directory = self.directory / 'ldap-target'
        target_directory.mkdir()
        target = Server(target_directory)
        try:
            selected_export = target_directory / 'ldap-vars.yml'
            selected_variables = {'vault_configuration_ldap': variables['vault_configuration_ldap']}
            selected_yaml = yaml.safe_dump(selected_variables, allow_unicode=True, sort_keys=True)
            selected_export.write_text(selected_yaml)
            target_vars = {'vault_configuration_config_mode': 'apply',
                           'vault_configuration_api_scheme': 'http',
                           'vault_configuration_api_port': target.port,
                           'vault_configuration_config_mounts': [],
                           'vault_configuration_config_management_owner': 'ldap-import',
                           'vault_configuration_config_management_policy_prefix': 'vam-ldap-import-',
                           'vault_configuration_token': target.token,
                           'vault_configuration_ldap_passwords': {entry['id']: 'fixture-admin' for entry in variables['vault_configuration_ldap']}}
            target_file = target_directory / 'target-vars.json'
            target_file.write_text(json.dumps(target_vars))
            target_file.chmod(0o600)
            playbook = target_directory / 'playbook.json'
            playbook.write_text(json.dumps([{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                                            'vars_files': [str(selected_export), str(target_file)], 'roles': ['vault-configuration']}]))
            environment = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / 'ansible.cfg'), ANSIBLE_ROLES_PATH=str(ROOT / 'roles'))
            for attempt in range(2):
                response = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(playbook)], env=environment,
                                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                self.assertEqual(response.returncode, 0, response.stdout)
                self.assertNotIn('fixture-admin', response.stdout)
            self.assertIn('changed=0', response.stdout)
            self.assertEqual(target.client.read('auth/' + name + '/config')['groupfilter'],
                             '(&(objectClass=groupOfNames)(member={{.UserDN}}))')
        finally:
            target.close()
        # Matrix combines observed Identity membership with direct LDAP group mappings
        # for the LDAP login only, even if mappings were added after the previous login.
        direct_policy = name + '-matrix-direct'
        self.client.request('POST', 'sys/policies/acl/' + direct_policy,
                            {'policy': 'path "' + name + '/data/audit/*" { capabilities = ["read"] }'})
        self.client.request('POST', 'auth/' + name + '/groups/developers', {'policies': [direct_policy]})
        matrix = run(dict(config, mode='matrix'), {}, self.server.token)
        matrix_rows = {row['path']: row for row in csv.DictReader(io.StringIO(matrix['_matrix_csv']), delimiter=';')
                       if row['mount'] == name}
        self.assertEqual(matrix_rows['payments/prod/*']['a:' + name + '/alice'], '.R.........')
        self.assertEqual(matrix_rows['payments/prod/*']['a:' + name + '/bob'], '...........')
        self.assertEqual(matrix_rows['audit/*']['a:' + name + '/alice'], '.R.........')
        self.assertEqual(matrix_rows['audit/*']['a:' + name + '/bob'], '...........')
        self.assertNotIn('fixture-admin', matrix['_matrix_notes'])
        # An empty desired LDAP scope and prune can never remove the integration or its mount.
        client = Client(self.server.connection, self.server.token)
        config['mounts'] = []
        run(config, {'ldap': []}, self.server.token, client=client)
        self.assertIn(name + '/', self.client.read('sys/mounts'))
        self.assertIn(name + '/', self.client.read('sys/auth'))
        self.assertFalse(any(request['method'] == 'DELETE' for request in client.requests))

    def test_ldap_personal_policy_by_login_for_group_and_export_import(self):
        name = 'personal-login'
        mount = 'directory/' + name
        administrator_policy = (ROOT / 'roles/vault-configuration/files/bootstrap-policy.hcl').read_text()
        self.client.request('POST', 'sys/policies/acl/personal-login-automation', {'policy': administrator_policy})
        automation_response = self.client.request('POST', 'auth/token/create', {
            'policies': ['personal-login-automation'], 'no_default_policy': True, 'ttl': '5m'})
        automation_token = automation_response['auth']['client_token']
        configuration = self.config(name)
        configuration['mounts'] = ['users']
        ldap = self.integration(name)
        ldap[0]['auth_mount'] = mount
        group_dn = 'cn=personal-dep1,ou=groups,dc=example,dc=test'
        ldap_admin = ['docker', 'exec', '-i', self.container, 'ldapadd', '-x', '-H', 'ldap://127.0.0.1',
                      '-D', 'cn=admin,dc=example,dc=test', '-w', 'fixture-admin']
        group_ldif = ('dn: ' + group_dn + '\nobjectClass: groupOfNames\ncn: personal-dep1\n'
                      'member: uid=alice,ou=people,dc=example,dc=test\n'
                      'member: uid=bob,ou=people,dc=example,dc=test\n')
        subprocess.run(ldap_admin, input=group_ldif, text=True, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        personal = {'enabled': True, 'identity_source': 'ldap_login', 'auth_mount': mount,
                    'mount': 'users', 'path_prefix': 'dep1', 'permissions': ['read', 'list'],
                    'subjects': [{'kind': 'group', 'id': 'department'}]}
        sections = {'ldap': ldap, 'groups': [{'id': 'department', 'name': name + '-department', 'type': 'external',
                                            'alias': {'auth_mount': mount, 'name': 'personal-dep1'}}],
                    'personal_access': personal}
        for mode, check_mode in [('dry', False), ('apply', True)]:
            client = Client(self.server.connection, automation_token)
            planned = run(dict(configuration, mode=mode), sections, automation_token,
                          ldap_passwords={name: 'fixture-admin'}, client=client, check_mode=check_mode)
            self.assertTrue(any(operation['key'] == 'policy:personal' for operation in planned['plan']['operations']))
            self.assertTrue(all(request['method'] in {'GET', 'LIST'} for request in client.requests))
            self.assertNotIn(mount + '/', self.client.read('sys/auth'))
        configuration['expected_plan_digest'] = planned['plan']['digest']
        self.assertTrue(run(configuration, sections, automation_token, ldap_passwords={name: 'fixture-admin'})['changed'])
        configuration.pop('expected_plan_digest')
        self.assertFalse(run(configuration, sections, automation_token)['changed'])
        source_accessor = self.client.read('sys/auth')[mount + '/']['accessor']
        generated_name = policy_name(configuration['management']['policy_prefix'], 'personal')
        policy = self.client.read('sys/policies/acl/' + generated_name)['policy']
        self.assertIn('{{identity.entity.aliases.' + source_accessor + '.name}}', policy)
        self.client.request('POST', 'users/data/dep1/alice/key', {'data': {'value': 'alice-private'}})
        alice_login = self.client.request('POST', 'auth/' + mount + '/login/alice', {'password': 'fixture-alice'})
        alice = Client(self.server.connection, alice_login['auth']['client_token'])
        self.assertEqual(alice.read('users/data/dep1/alice/key')['data']['value'], 'alice-private')
        with self.assertRaises(VaultHTTPError):
            alice.request('POST', 'users/data/dep1/alice/key', {'data': {'value': 'not-yet-allowed'}})

        # Existing entity/alias and a new first login use one policy; no users inventory is needed.
        personal['permissions'].append('write')
        self.assertTrue(run(configuration, sections, automation_token)['changed'])
        self.assertFalse(run(configuration, sections, automation_token)['changed'])
        repeated_login = self.client.request('POST', 'auth/' + mount + '/login/alice', {'password': 'fixture-alice'})
        self.assertEqual(repeated_login['auth']['entity_id'], alice_login['auth']['entity_id'])
        alice.request('POST', 'users/data/dep1/alice/key', {'data': {'value': 'alice-updated'}})
        bob_login = self.client.request('POST', 'auth/' + mount + '/login/bob', {'password': 'fixture-bob'})
        bob = Client(self.server.connection, bob_login['auth']['client_token'])
        bob.request('POST', 'users/data/dep1/bob/key', {'data': {'value': 'bob-private'}})
        self.assertEqual(bob.list('users/metadata/dep1/bob'), ['key'])
        for client, api in [(alice, 'users/data/dep1/bob/key'), (bob, 'users/data/dep1/alice/key'),
                            (alice, 'users/data/dep2/alice/key'), (alice, 'users/metadata/dep1')]:
            with self.assertRaises(VaultHTTPError):
                client.request('LIST' if '/metadata/' in api else 'GET', api)
        for client, api in [(alice, 'users/data/dep1/bob/forbidden'), (bob, 'users/data/dep1/alice/forbidden')]:
            with self.assertRaises(VaultHTTPError):
                client.request('POST', api, {'data': {'value': 'forbidden'}})
        token_response = self.client.request('POST', 'auth/token/create', {'policies': [generated_name],
                                             'no_default_policy': True})
        without_alias = Client(self.server.connection, token_response['auth']['client_token'])
        with self.assertRaises(VaultHTTPError):
            without_alias.read('users/data/dep1/alice/key')

        charlie_ldif = ('dn: uid=charlie,ou=people,dc=example,dc=test\nobjectClass: inetOrgPerson\n'
                        'cn: Charlie\nsn: Charlie\nuid: charlie\nuserPassword: fixture-charlie\n')
        subprocess.run(ldap_admin, input=charlie_ldif, text=True, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        membership = 'dn: ' + group_dn + '\nchangetype: modify\nadd: member\nmember: uid=charlie,ou=people,dc=example,dc=test\n'
        ldap_modify = list(ldap_admin)
        ldap_modify[4] = 'ldapmodify'
        subprocess.run(ldap_modify, input=membership, text=True, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        charlie_login = self.client.request('POST', 'auth/' + mount + '/login/charlie', {'password': 'fixture-charlie'})
        charlie = Client(self.server.connection, charlie_login['auth']['client_token'])
        charlie.request('POST', 'users/data/dep1/charlie/key', {'data': {'value': 'charlie-private'}})
        with self.assertRaises(VaultHTTPError):
            charlie.read('users/data/dep1/alice/key')
        exported = self.directory / name / 'export.yml'
        result = run(dict(configuration, mode='export'), {}, automation_token)
        exported.parent.mkdir(parents=True, exist_ok=True)
        export_text = yaml.safe_dump(result['_export_variables'], allow_unicode=True, sort_keys=True)
        exported.write_text(export_text)
        variables = yaml.safe_load(export_text)
        exported_personal = variables['vault_configuration_personal_access']
        self.assertEqual(exported_personal['auth_mount'], mount)
        self.assertEqual(exported_personal['identity_source'], 'ldap_login')
        self.assertEqual(exported_personal['path_prefix'], 'dep1')
        self.assertNotIn(source_accessor, export_text)

        target_directory = self.directory / 'personal-target'
        target_directory.mkdir()
        target = Server(target_directory)
        try:
            target_vars = {'vault_configuration_config_mode': 'apply',
                           'vault_configuration_api_scheme': 'http',
                           'vault_configuration_api_port': target.port,
                           'vault_configuration_config_mounts': ['users'],
                           'vault_configuration_config_management_owner': 'personal-import',
                           'vault_configuration_config_management_policy_prefix': 'vam-personal-import-',
                           'vault_configuration_token': target.token,
                           'vault_configuration_ldap_passwords': {entry['id']: 'fixture-admin' for entry in variables['vault_configuration_ldap']}}
            target_file = target_directory / 'target-vars.json'
            target_vars_json = json.dumps(target_vars)
            target_file.write_text(target_vars_json)
            target_file.chmod(0o600)
            playbook = target_directory / 'playbook.json'
            plays = [{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                      'vars_files': [str(exported), str(target_file)], 'roles': ['vault-configuration']}]
            playbook_json = json.dumps(plays)
            playbook.write_text(playbook_json)
            environment = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / 'ansible.cfg'), ANSIBLE_ROLES_PATH=str(ROOT / 'roles'))
            for attempt in range(2):
                response = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(playbook)], env=environment,
                                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                self.assertEqual(response.returncode, 0, response.stdout)
                self.assertNotIn('fixture-admin', response.stdout)
                self.assertNotIn(target.token, response.stdout)
            self.assertIn('changed=0', response.stdout)
            target_accessor = target.client.read('sys/auth')[mount + '/']['accessor']
            self.assertNotEqual(source_accessor, target_accessor)
            target_policy_name = policy_name('vam-personal-import-', 'personal')
            target_policy = target.client.read('sys/policies/acl/' + target_policy_name)['policy']
            self.assertIn(target_accessor, target_policy)
            self.assertNotIn(source_accessor, target_policy)
            for username, password in [('alice', 'fixture-alice'), ('bob', 'fixture-bob'), ('charlie', 'fixture-charlie')]:
                login = target.client.request('POST', 'auth/' + mount + '/login/' + username, {'password': password})
                ordinary = Client(target.connection, login['auth']['client_token'])
                ordinary.request('POST', 'users/data/dep1/' + username + '/key', {'data': {'value': username}})
        finally:
            target.close()
        sections['personal_access'] = {'enabled': False}
        self.assertTrue(run(configuration, sections, automation_token)['changed'])
        with self.assertRaises(VaultHTTPError):
            alice.read('users/data/dep1/alice/key')

    def test_ldap_personal_uuid_group_preserves_external_metadata_and_membership(self):
        name = 'personal-uuid-group'
        configuration = self.config(name)
        configuration['mounts'] = ['users']
        ldap = self.integration(name)
        run(configuration, {'ldap': ldap}, self.server.token, ldap_passwords={name: 'fixture-admin'})
        group = self.client.request('POST', 'identity/group', {
            'name': name, 'type': 'external', 'metadata': {'origin': 'existing-directory'}})
        group_uuid = group['data']['id']
        auth_accessor = self.client.read('sys/auth')[name + '/']['accessor']
        self.client.request('POST', 'identity/group-alias', {
            'name': 'developers', 'canonical_id': group_uuid, 'mount_accessor': auth_accessor})
        personal = {'enabled': True, 'identity_source': 'ldap_login', 'auth_mount': name,
                    'mount': 'users', 'path_prefix': 'uuid-dep', 'permissions': ['read', 'write', 'list'],
                    'subjects': [{'kind': 'group', 'uuid': group_uuid}]}
        sections = {'personal_access': personal}
        self.assertTrue(run(configuration, sections, self.server.token)['changed'])
        self.assertFalse(run(configuration, sections, self.server.token)['changed'])
        login = self.client.request('POST', 'auth/' + name + '/login/alice', {'password': 'fixture-alice'})
        alice = Client(self.server.connection, login['auth']['client_token'])
        alice.request('POST', 'users/data/uuid-dep/alice/key', {'data': {'value': 'private'}})
        before = self.client.read('identity/group/id/' + group_uuid)
        self.assertIn(login['auth']['entity_id'], before['member_entity_ids'])
        self.assertEqual(before['metadata'], {'origin': 'existing-directory'})
        run(configuration, {'personal_access': {'enabled': False}}, self.server.token)
        after = self.client.read('identity/group/id/' + group_uuid)
        self.assertEqual(after['member_entity_ids'], before['member_entity_ids'])
        self.assertEqual(after['metadata'], before['metadata'])
        with self.assertRaises(VaultHTTPError):
            alice.read('users/data/uuid-dep/alice/key')

    def test_existing_kv_v1_is_rejected_without_mutations(self):
        name = 'kv-v1-conflict'
        self.client.request('POST', 'sys/mounts/' + name, {'type': 'kv', 'options': {'version': '1'}})
        client = Client(self.server.connection, self.server.token)
        with self.assertRaises(ConfigurationError):
            run(self.config(name), {}, self.server.token, client=client)
        self.assertTrue(all(request['method'] in {'GET', 'LIST'} for request in client.requests))

    def test_single_admin_token_can_create_mounts_ldap_and_group_grants(self):
        name = 'limited-ldap'
        configuration = self.config(name)
        policy = (ROOT / 'roles/vault-configuration/files/bootstrap-policy.hcl').read_text()
        self.client.request('POST', 'sys/policies/acl/limited-ldap-automation', {'policy': policy})
        token = self.client.request('POST', 'auth/token/create', {'policies':['limited-ldap-automation'],
                                    'no_default_policy':True, 'ttl':'5m'})['auth']['client_token']
        entries = self.integration(name)
        entries[0]['auth_mount'] = 'corporate/directory'
        sections = {'ldap': entries, 'groups': [
            {'id': 'developers', 'name': name + '-developers', 'type': 'external',
             'alias': {'auth_mount': 'corporate/directory', 'name': 'developers'}}],
            'grants': [{'id': 'read', 'subjects': [{'kind': 'group', 'id': 'developers'}],
                        'paths': [{'mount': name, 'path': 'prod', 'scope': 'subtree', 'permissions': ['read']}]}]}
        self.assertTrue(run(configuration, sections, token, ldap_passwords={name:'fixture-admin'})['changed'])
        self.assertFalse(run(configuration, sections, token)['changed'])
        self.client.request('POST', name + '/data/prod/key', {'data': {'value': 'fixture'}})
        login = self.client.request('POST', 'auth/corporate/directory/login/alice', {'password': 'fixture-alice'})
        ordinary = Client(self.server.connection, login['auth']['client_token'])
        self.assertEqual(ordinary.read(name + '/data/prod/key')['data']['value'], 'fixture')
        restricted = Client(self.server.connection, token)
        for api in ['sys/mounts/' + name, 'sys/auth/corporate/directory']:
            with self.assertRaises(ConfigurationError):
                restricted.request('DELETE', api)

    def test_missing_bind_secret_fails_before_creating_any_mount(self):
        name = 'ldap-secret-missing'
        with self.assertRaises(ConfigurationError):
            run(self.config(name), {'ldap': self.integration(name)}, self.server.token)
        self.assertNotIn(name + '/', self.client.read('sys/mounts'))
        self.assertNotIn(name + '/', self.client.read('sys/auth'))

    def test_multiple_personal_mounts_by_ldap_groups_and_export_import(self):
        name = 'multiple-personal'
        configuration = self.config(name)
        configuration['mounts'] = ['users', 'users-xz']
        configuration['safety']['allow_destructive_grants'] = True
        ldap = self.integration(name)
        group_users = [('opensource-admins', 'alice'), ('db-admins', 'bob'),
                       ('linux-admins', 'carol'), ('xz-admins', 'dave')]
        ldif = ''
        for login in ('carol', 'dave'):
            ldif += ('dn: uid=' + login + ',ou=people,dc=example,dc=test\nobjectClass: inetOrgPerson\n'
                     'cn: ' + login + '\nsn: ' + login + '\nuid: ' + login + '\nuserPassword: fixture-' + login + '\n\n')
        for group, login in group_users:
            ldif += ('dn: cn=' + group + ',ou=groups,dc=example,dc=test\nobjectClass: groupOfNames\n'
                     'cn: ' + group + '\nmember: uid=' + login + ',ou=people,dc=example,dc=test\n\n')
        subprocess.run(['docker', 'exec', '-i', self.container, 'ldapadd', '-x', '-H', 'ldap://127.0.0.1',
                        '-D', 'cn=admin,dc=example,dc=test', '-w', 'fixture-admin'],
                       input=ldif, text=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        sections = {'ldap': ldap, 'groups': [
            {'id': group, 'name': name + '-' + group, 'type': 'external',
             'alias': {'auth_mount': name, 'name': group}} for group, _ in group_users],
            'personal_access': [
                {'id': 'standard-home', 'enabled': True, 'identity_source': 'ldap_login', 'auth_mount': name,
                 'mount': 'users', 'path_prefix': '', 'permissions': 'all',
                 'subjects': [{'kind': 'group', 'id': group} for group in ('opensource-admins', 'db-admins')]},
                {'id': 'xz-home', 'enabled': True, 'identity_source': 'ldap_login', 'auth_mount': name,
                 'mount': 'users-xz', 'path_prefix': '', 'permissions': 'all',
                 'subjects': [{'kind': 'group', 'id': 'xz-admins'}]}]}
        self.assertTrue(run(configuration, sections, self.server.token, ldap_passwords={name: 'fixture-admin'})['changed'])
        self.assertFalse(run(configuration, sections, self.server.token)['changed'])
        self.assertIn('users-xz/', self.client.read('sys/mounts'))
        for login, allowed in [('alice', 'users'), ('bob', 'users'), ('carol', None), ('dave', 'users-xz')]:
            auth = self.client.request('POST', 'auth/' + name + '/login/' + login, {'password': 'fixture-' + login})['auth']
            ordinary = Client(self.server.connection, auth['client_token'])
            for mount in ('users', 'users-xz'):
                own_path = mount + '/data/' + login + '/mail'
                if mount == allowed:
                    ordinary.request('POST', own_path, {'data': {'value': login}})
                    self.assertEqual(ordinary.read(own_path)['data']['value'], login)
                    ordinary.request('DELETE', mount + '/metadata/' + login + '/mail')
                else:
                    with self.assertRaises(VaultHTTPError): ordinary.request('POST', own_path, {'data': {'value': login}})
                with self.assertRaises(VaultHTTPError): ordinary.request('POST', mount + '/data/someone-else/mail', {'data': {'value': login}})
        exported = run(dict(configuration, mode='export'), {}, self.server.token)['_export_variables']
        self.assertIsInstance(exported['vault_configuration_personal_access'], list)
        self.assertEqual([entry['id'] for entry in exported['vault_configuration_personal_access']], ['standard-home', 'xz-home'])
        # grants is independent and must not detach named personal assignments.
        self.assertFalse(run(configuration, {'grants': []}, self.server.token)['changed'])
        target_directory = self.directory / 'multiple-personal-target'
        target_directory.mkdir()
        target = Server(target_directory)
        try:
            from ansible.template import Templar
            from ansible.parsing.dataloader import DataLoader
            # Export escapes Go templates for Ansible vars_files; render that layer before direct runner use.
            rendered_export = Templar(loader=DataLoader(), variables={}).template(exported)
            imported = {key: rendered_export.get('vault_configuration_' + key) for key in
                        ('users', 'groups', 'grants', 'personal_access', 'ldap', 'auth_roles')}
            target_config = dict(configuration, connection=target.connection)
            bind_passwords = {entry['id']: 'fixture-admin' for entry in imported['ldap']}
            import_result = run(target_config, imported, target.token, ldap_passwords=bind_passwords)
            self.assertTrue(import_result['changed'])
            self.assertFalse(run(target_config, imported, target.token)['changed'])
            auth = target.client.request('POST', 'auth/' + name + '/login/dave', {'password': 'fixture-dave'})['auth']
            ordinary = Client(target.connection, auth['client_token'])
            ordinary.request('POST', 'users-xz/data/dave/imported', {'data': {'value': 'ok'}})
            with self.assertRaises(VaultHTTPError): ordinary.request('POST', 'users/data/dave/imported', {'data': {'value': 'no'}})
        finally:
            target.close()
        sections['personal_access'] = sections['personal_access'][:1]
        self.assertTrue(run(configuration, sections, self.server.token)['changed'])
        self.assertFalse(self.client.read('identity/group/name/' + name + '-xz-admins')['policies'])
        self.assertIn('users-xz/', self.client.read('sys/mounts'))
