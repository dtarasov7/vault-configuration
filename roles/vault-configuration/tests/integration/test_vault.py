"""Real Vault tests. Starts isolated dev servers; never uses VAULT_ADDR/VAULT_TOKEN.

Run from the workspace root:
python3 -m unittest discover -s roles/vault-configuration/tests/integration -v
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import yaml
from urllib.request import Request
from urllib.error import HTTPError
from http.server import BaseHTTPRequestHandler, HTTPServer

ROLE = Path(__file__).resolve().parents[2]
ROOT = ROLE.parents[1]
(ROOT / '.work').mkdir(exist_ok=True)
sys.path.insert(0, str(ROLE / 'module_utils'))
from vault_configuration.client import Client, VaultHTTPError
from vault_configuration.common import ConfigurationError, digest
from vault_configuration.runner import run
from vault_configuration.validation import DEFAULTS
from vault_configuration.compiler import policy_name, compile_grant
from vault_configuration.reader import snapshot
from vault_configuration.executor import PartialApply


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


class Server:
    def __init__(self, directory, prepare_mounts=True):
        self.directory = Path(directory)
        self.port = free_port()
        self.connection = dict(DEFAULTS['connection'], address='http://127.0.0.1:' + str(self.port), allow_insecure_http=True)
        self.token = 'test-only-' + os.urandom(16).hex()
        environment = dict(os.environ, VAULT_DEV_ROOT_TOKEN_ID=self.token)
        self.log = open(self.directory / 'vault.log', 'w')
        self.process = subprocess.Popen(['vault', 'server', '-dev', '-dev-listen-address=127.0.0.1:' + str(self.port)],
                                        env=environment, stdout=self.log, stderr=subprocess.STDOUT)
        self.client = Client(self.connection, self.token)
        try:
            for attempt in range(100):
                try:
                    self.client.request('GET', 'sys/health')
                    break
                except ConfigurationError:
                    check_exit = self.process.poll()
                    if check_exit is not None:
                        raise RuntimeError('Test Vault failed to start; inspect workspace test logs')
                    time.sleep(0.05)
            else:
                raise RuntimeError('Test Vault startup timed out')
            if prepare_mounts:
                for mount in DEFAULTS['mounts']:
                    self.client.request('POST', 'sys/mounts/' + mount, {'type': 'kv', 'options': {'version': '2'}})
                for mount, kind in [('userpass', 'userpass'), ('approle', 'approle'), ('jwt', 'jwt'), ('oidc', 'oidc'), ('kubernetes', 'kubernetes')]:
                    self.client.request('POST', 'sys/auth/' + mount, {'type': kind})
        except Exception:
            self.close()
            raise

    def close(self):
        self.process.terminate()
        self.process.wait(timeout=15)
        self.log.close()


class VaultIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('vault'):
            raise unittest.SkipTest('Vault binary is unavailable')
        (ROOT / '.work').mkdir(exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(prefix='vault-integration-', dir=str(ROOT / '.work'))
        cls.directory = Path(cls.temporary.name)
        cls.first_dir = cls.directory / 'first'
        cls.second_dir = cls.directory / 'second'
        cls.first_dir.mkdir()
        cls.second_dir.mkdir()
        cls.server = Server(cls.first_dir)
        cls.second = Server(cls.second_dir)
        cls.client = cls.server.client
        cls.key = cls.directory / 'jwt.key'
        cls.pub = cls.directory / 'jwt.pub'
        subprocess.run(['openssl', 'genrsa', '-out', str(cls.key), '2048'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['openssl', 'rsa', '-in', str(cls.key), '-pubout', '-out', str(cls.pub)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for server in (cls.server, cls.second):
            for mount in ('jwt', 'oidc'):
                server.client.request('POST', 'auth/' + mount + '/config', {'jwt_validation_pubkeys': [cls.pub.read_text()], 'bound_issuer': 'integration'})
        class TokenReview(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length']))
                request = json.loads(body)
                claims = json.loads(base64.urlsafe_b64decode(request['spec']['token'].split('.')[1] + '=='))
                response = {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenReview',
                            'status': {'authenticated': claims.get('sub') == 'system:serviceaccount:prod:backend',
                                       'audiences': ['vault'], 'user': {'username': 'system:serviceaccount:prod:backend',
                                        'uid': 'backend-uid', 'groups': ['system:serviceaccounts:prod']}}}
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
            def log_message(self, *args):
                return
        cls.reviewer = HTTPServer(('127.0.0.1', 0), TokenReview)
        cls.reviewer_thread = threading.Thread(target=cls.reviewer.serve_forever, daemon=True)
        cls.reviewer_thread.start()
        cls.client.request('POST', 'auth/kubernetes/config', {
            'kubernetes_host': 'http://127.0.0.1:' + str(cls.reviewer.server_port),
            'pem_keys': [cls.pub.read_text()], 'disable_local_ca_jwt': True,
            'disable_iss_validation': True,
        })

    @classmethod
    def tearDownClass(cls):
        cls.reviewer.shutdown()
        cls.reviewer.server_close()
        cls.reviewer_thread.join(timeout=5)
        cls.server.close()
        cls.second.close()
        cls.temporary.cleanup()

    def setUp(self):
        self.name = self._testMethodName.replace('test_', '')
        self.work = self.directory / self.name
        self.work.mkdir()
        self.config = copy.deepcopy(DEFAULTS)
        self.config.update(mode='apply', compatibility_profile='community-candidate', connection=self.server.connection)
        self.config['management'].update(owner=self.name, policy_prefix='vam-' + self.name + '-', state_file=str(self.work / 'state.json'))
        self.sections = {'users': [{'id': self.name, 'name': self.name, 'source': 'userpass', 'auth_mount': 'userpass',
                                   'login': self.name, 'password_revision': 'r1', 'password_policy': 'on_revision'}]}
        self.password = 'test-pw-' + self.name

    def apply(self, sections=None, config=None, **kwargs):
        return run(config or self.config, sections or self.sections, self.server.token,
                   passwords={self.name: self.password}, **kwargs)

    def login(self, login=None, password=None):
        response = self.client.request('POST', 'auth/userpass/login/' + (login or self.name), {'password': password or self.password})
        return Client(self.server.connection, response['auth']['client_token']), response['auth']['entity_id']

    def grant(self, identifier='access', permissions=None, logical='payments/prod', scope='subtree', kind='user', subject=None):
        return {'id': identifier, 'subjects': [{'kind': kind, 'id': subject or self.name}],
                'paths': [{'mount': 'apps', 'path': logical, 'scope': scope, 'permissions': permissions or ['read']}]}

    def jwt(self, claims):
        def encode(value):
            return base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).rstrip(b'=')
        claims = dict({'iss': 'integration', 'sub': self.name, 'aud': ['vault'], 'exp': int(time.time()) + 300, 'nbf': int(time.time()) - 60, 'iat': int(time.time()) - 60}, **claims)
        signing = encode({'alg': 'RS256', 'typ': 'JWT'}) + b'.' + encode(claims)
        signature = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(self.key)], input=signing,
                                   check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
        return (signing + b'.' + base64.urlsafe_b64encode(signature).rstrip(b'=')).decode()

    def test_acl_idempotence_and_isolation(self):
        self.sections['grants'] = [self.grant(permissions=['read', 'list'])]
        self.assertTrue(self.apply()['changed'])
        self.assertFalse(self.apply()['changed'])
        paths = ['payments/prod/backend', 'payments/dev/backend', 'other/prod/backend', 'payments/production/backend']
        for logical in paths:
            self.client.request('POST', 'apps/data/' + logical, {'data': {'value': 'fixture'}})
        ordinary, uuid = self.login()
        self.assertEqual(ordinary.read('apps/data/' + paths[0])['data']['value'], 'fixture')
        for logical in paths[1:]:
            with self.assertRaises(VaultHTTPError):
                ordinary.read('apps/data/' + logical)
        self.assertEqual(ordinary.list('apps/metadata/payments/prod'), ['backend'])
        for method, api, payload in [('POST', 'apps/data/' + paths[0], {'data': {'value': 'bad'}}),
                                     ('DELETE', 'apps/data/' + paths[0], None),
                                     ('GET', 'infra/data/' + paths[0], None),
                                     ('LIST', 'apps/metadata/payments', None)]:
            with self.assertRaises(VaultHTTPError):
                ordinary.request(method, api, payload)

    def test_exact_discovery_and_both_orders(self):
        self.sections['grants'] = [self.grant(logical='prod/payments/key', scope='exact'),
                                  self.grant('tree', logical='payments/prod', permissions=['write'])]
        self.sections['grants'][0]['discovery_paths'] = [{'mount': 'apps', 'path': 'prod'}]
        self.assertTrue(self.apply()['changed'])
        self.client.request('POST', 'apps/data/prod/payments/key', {'data': {'x': 1}})
        self.client.request('POST', 'apps/data/prod/other/key', {'data': {'x': 1}})
        ordinary, _ = self.login()
        ordinary.read('apps/data/prod/payments/key')
        with self.assertRaises(VaultHTTPError):
            ordinary.read('apps/data/prod/payments/key/child')
        self.assertIn('other/', ordinary.list('apps/metadata/prod'))
        ordinary.request('POST', 'apps/data/payments/prod/key', {'data': {'x': 1}})
        with self.assertRaises(VaultHTTPError):
            ordinary.request('POST', 'apps/destroy/payments/prod/key', {'versions': [1]})

    def test_personal_rename_and_offboarding(self):
        second_id = self.name + '-other'
        self.sections['users'].append({'id': second_id, 'name': second_id, 'source': 'userpass', 'auth_mount': 'userpass',
                                      'login': second_id, 'password': 'other-test-password', 'password_revision': 'r1'})
        self.sections['personal_access'] = {'enabled': True, 'mount': 'users', 'permissions': ['read', 'write', 'list'],
                                          'subjects': [{'kind': 'user', 'id': self.name}, {'kind': 'user', 'id': second_id}]}
        self.apply()
        ordinary, uuid = self.login()
        other, other_uuid = self.login(second_id, 'other-test-password')
        ordinary.request('POST', 'users/data/' + uuid + '/personal/key', {'data': {'x': 1}})
        other.request('POST', 'users/data/' + other_uuid + '/personal/key', {'data': {'x': 2}})
        with self.assertRaises(VaultHTTPError):
            ordinary.read('users/data/' + other_uuid + '/personal/key')
        self.sections['users'][0]['name'] += '-renamed'
        self.apply()
        self.assertEqual(self.login()[1], uuid)
        self.assertEqual(ordinary.read('users/data/' + uuid + '/personal/key')['data']['x'], 1)
        token = self.client.request('POST', 'auth/token/create', {'policies': [policy_name(self.config['management']['policy_prefix'], 'personal')], 'no_parent': True})
        no_entity = Client(self.server.connection, token['auth']['client_token'])
        with self.assertRaises(VaultHTTPError):
            no_entity.read('users/data/' + uuid + '/personal/key')
        # Deleting a login does not revoke an already issued token or erase KV data.
        self.client.request('DELETE', 'auth/userpass/users/' + self.name)
        self.assertEqual(ordinary.read('users/data/' + uuid + '/personal/key')['data']['x'], 1)
        self.assertEqual(self.client.read('users/data/' + uuid + '/personal/key')['data']['x'], 1)
        self.client.request('DELETE', 'identity/entity/id/' + uuid)
        self.client.request('POST', 'auth/userpass/users/' + self.name, {'password': self.password})
        replacement, replacement_uuid = self.login()
        self.assertNotEqual(replacement_uuid, uuid)
        self.client.request('POST', 'identity/entity/id/' + replacement_uuid,
                            {'policies': [policy_name(self.config['management']['policy_prefix'], 'personal')]})
        replacement, _ = self.login()
        with self.assertRaises(VaultHTTPError):
            replacement.read('users/data/' + uuid + '/personal/key')
        replacement.request('POST', 'users/data/' + replacement_uuid + '/personal/key', {'data': {'x': 3}})

    def test_nested_groups_and_external_jwt_group(self):
        external = self.name + '-external'
        parent = self.name + '-parent'
        child = self.name + '-child'
        self.sections['users'][0]['aliases'] = [{'auth_mount': 'jwt', 'name': self.name}]
        self.sections['groups'] = [
            {'id': child, 'name': child, 'type': 'internal', 'members': [self.name]},
            {'id': parent, 'name': parent, 'type': 'internal', 'member_groups': [child]},
            {'id': external, 'name': external, 'type': 'external', 'alias': {'auth_mount': 'jwt', 'name': external}},
        ]
        self.sections['grants'] = [self.grant('internal', kind='group', subject=parent, logical=self.name + '/internal'),
                                  self.grant('external', kind='group', subject=external, logical=self.name + '/external')]
        self.client.request('POST', 'auth/jwt/role/' + self.name, {'role_type': 'jwt', 'user_claim': 'sub',
                            'groups_claim': 'groups', 'bound_audiences': ['vault'], 'bound_subject': self.name})
        self.apply()
        self.assertFalse(self.apply()['changed'])
        for kind in ('internal', 'external'):
            self.client.request('POST', 'apps/data/' + self.name + '/' + kind, {'data': {'x': kind}})
        ordinary, _ = self.login()
        ordinary.read('apps/data/' + self.name + '/internal')
        with self.assertRaises(VaultHTTPError):
            ordinary.read('apps/data/' + self.name + '/external')
        response = self.client.request('POST', 'auth/jwt/login', {'role': self.name, 'jwt': self.jwt({'groups': [external]})})
        external_client = Client(self.server.connection, response['auth']['client_token'])
        self.assertEqual(external_client.read('apps/data/' + self.name + '/external')['data']['x'], 'external')

    def test_auth_role_adapters_and_new_tokens(self):
        fixture_roles = {
            'approle': {'bind_secret_id': True, 'secret_id_ttl': 300, 'secret_id_num_uses': 2, 'token_ttl': 120},
            'jwt': {'role_type': 'jwt', 'user_claim': 'sub', 'bound_audiences': ['vault'], 'bound_subject': self.name, 'bound_claims': {'project': 'payments'}, 'token_ttl': 120},
            'kubernetes': {'bound_service_account_names': ['backend'], 'bound_service_account_namespaces': ['prod'], 'audience': 'vault', 'token_ttl': 120},
        }
        self.sections['auth_roles'] = []
        self.sections['grants'] = []
        old = {}
        for kind, fixture in fixture_roles.items():
            self.client.request('POST', 'auth/' + kind + '/role/' + self.name, fixture)
            old[kind] = self.client.read('auth/' + kind + '/role/' + self.name)
            self.sections['auth_roles'].append({'id': kind, 'type': kind, 'auth_mount': kind, 'name': self.name})
            self.sections['grants'].append(self.grant(kind, kind='auth_role', subject=kind, logical=self.name + '/' + kind))
        prior_jwt = self.client.request('POST', 'auth/jwt/login', {'role': self.name, 'jwt': self.jwt({'project': 'payments'})})
        self.apply()
        self.assertFalse(self.apply()['changed'])
        for kind in fixture_roles:
            actual = self.client.read('auth/' + kind + '/role/' + self.name)
            for key, value in old[kind].items():
                if key not in {'policies', 'token_policies'}:
                    self.assertEqual(actual[key], value, (kind, key))
        jwt_login = self.client.request('POST', 'auth/jwt/login', {'role': self.name, 'jwt': self.jwt({'project': 'payments'})})
        self.assertNotEqual(prior_jwt['auth']['policies'], jwt_login['auth']['policies'])
        with self.assertRaises(VaultHTTPError):
            self.client.request('POST', 'auth/jwt/login', {'role': self.name, 'jwt': self.jwt({'project': 'wrong'})})
        role_id = self.client.read('auth/approle/role/' + self.name + '/role-id')['role_id']
        secret_id = self.client.request('POST', 'auth/approle/role/' + self.name + '/secret-id')['data']['secret_id']
        approle_login = self.client.request('POST', 'auth/approle/login', {'role_id': role_id, 'secret_id': secret_id})
        kube_jwt = self.jwt({'sub': 'system:serviceaccount:prod:backend',
                            'kubernetes.io/serviceaccount/namespace': 'prod',
                            'kubernetes.io/serviceaccount/service-account.name': 'backend',
                            'kubernetes.io/serviceaccount/service-account.uid': 'backend-uid'})
        kube_login = self.client.request('POST', 'auth/kubernetes/login', {'role': self.name, 'jwt': kube_jwt})
        for kind, login in [('jwt', jwt_login), ('approle', approle_login), ('kubernetes', kube_login)]:
            self.assertIn(policy_name(self.config['management']['policy_prefix'], kind), login['auth']['policies'])

    def test_oidc_role_preserves_redirects_and_claims(self):
        self.client.request('POST', 'auth/oidc/role/' + self.name,
                            {'role_type': 'oidc', 'user_claim': 'sub', 'groups_claim': 'groups',
                             'allowed_redirect_uris': ['https://client.example.org/callback'],
                             'oidc_scopes': ['openid', 'profile'], 'bound_claims': {'department': 'sre'}, 'token_ttl': 600})
        before = self.client.read('auth/oidc/role/' + self.name)
        self.sections['auth_roles'] = [{'id':'oidc','type':'oidc','auth_mount':'oidc','name':self.name}]
        self.sections['grants'] = [self.grant(kind='auth_role',subject='oidc')]
        self.apply()
        self.assertFalse(self.apply()['changed'])
        actual = self.client.read('auth/oidc/role/' + self.name)
        for key, value in before.items():
            if key not in {'policies','token_policies'}:
                self.assertEqual(actual[key],value,key)

    def test_expand_three_mounts_to_five_without_recreating_existing(self):
        directory = self.work / 'fresh-vault'
        directory.mkdir()
        server = Server(directory, prepare_mounts=False)
        try:
            for mount in ['apps', 'infra', 'users']:
                server.client.request('POST', 'sys/mounts/' + mount, {'type': 'kv', 'options': {'version': '2'}})
            before = server.client.read('sys/mounts')
            configuration = copy.deepcopy(self.config)
            configuration['connection'] = server.connection
            result = run(configuration, {}, server.token)
            self.assertEqual({item['key'] for item in result['confirmed']}, {'mount:certs', 'mount:cicd'})
            after = server.client.read('sys/mounts')
            for mount in ['certs', 'infra', 'apps', 'cicd', 'users']:
                self.assertEqual(after[mount + '/']['type'], 'kv')
                self.assertEqual(after[mount + '/']['options']['version'], '2')
            for mount in ['apps/', 'infra/', 'users/']:
                self.assertEqual(after[mount], before[mount])
            self.assertFalse(run(configuration, {}, server.token)['changed'])
        finally:
            server.close()

    def test_dry_reports_only_changes_and_preserves_plan_digest(self):
        self.sections['grants'] = [self.grant()]
        self.apply()
        full_plan = self.apply(check_mode=True)['plan']
        self.assertTrue(any(operation['action'] == 'noop' for operation in full_plan['operations']))
        destination = self.work / 'changes-only.yml'
        configuration = dict(self.config, mode='dry', report_destination=str(destination))
        empty = run(configuration, self.sections, self.server.token)
        self.assertEqual(empty['plan']['operations'], [])
        self.assertEqual(empty['plan']['digest'], full_plan['digest'])
        self.assertTrue(all(summary['count'] == 0 for summary in empty['summary'].values()))
        empty_yaml = destination.read_text()
        self.assertEqual(yaml.safe_load(empty_yaml)['plan']['operations'], [])
        self.assertNotIn('action: noop', empty_yaml)

        self.sections['users'][0]['disabled'] = True
        complete = self.apply(check_mode=True)['plan']
        dry = run(configuration, self.sections, self.server.token, diff=True)
        changes = dry['plan']['operations']
        self.assertEqual([(operation['key'], operation['action']) for operation in changes],
                         [('entity:' + self.name, 'update')])
        self.assertEqual(dry['plan']['digest'], complete['digest'])
        self.assertEqual(dry['summary']['Планируем изменить']['count'], 1)
        report_yaml = destination.read_text()
        report = yaml.safe_load(report_yaml)
        self.assertEqual(report['plan'], dry['plan'])
        self.assertNotIn('action: noop', report_yaml)
        actual_entity = self.client.read(changes[0]['path'])
        self.assertFalse(actual_entity['disabled'])

    def test_dry_check_export_and_transfer(self):
        self.sections['grants'] = [self.grant(permissions=['read', 'write'])]
        dry_config = copy.deepcopy(self.config)
        dry_config['mode'] = 'dry'
        dry_client = Client(self.server.connection, self.server.token)
        result = run(dry_config, self.sections, self.server.token, passwords={self.name: self.password}, client=dry_client)
        self.assertFalse(result['changed'])
        self.assertEqual(len(result['summary']), 3)
        self.assertTrue(all(request['method'] in {'GET', 'LIST'} for request in dry_client.requests))
        self.assertFalse(Path(self.config['management']['state_file']).exists())
        report_path = self.work / 'reports' / 'inventory-selected-name.yml'
        dry_config['report_destination'] = str(report_path)
        checked = run(dry_config, self.sections, self.server.token, passwords={self.name: self.password}, check_mode=True)
        self.assertTrue(checked['changed'])
        self.assertFalse(report_path.exists())
        saved = run(dry_config, self.sections, self.server.token, passwords={self.name: self.password})
        self.assertTrue(saved['changed'])
        report_text = report_path.read_text()
        report = yaml.safe_load(report_text)
        self.assertFalse(report_text.lstrip().startswith('{'))
        self.assertEqual(report['mode'], 'dry')
        self.assertEqual(report['plan'], saved['plan'])
        self.assertEqual(report['summary'], saved['summary'])
        self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)
        for secret in [self.server.token, self.password]:
            self.assertNotIn(secret, report_text)
        self.assertFalse(run(dry_config, self.sections, self.server.token, passwords={self.name: self.password})['changed'])
        self.assertFalse(Path(self.config['management']['state_file']).exists())
        collision = dict(dry_config, report_destination=self.config['management']['state_file'])
        with self.assertRaises(ConfigurationError):
            run(collision, self.sections, self.server.token, passwords={self.name: self.password})
        check_result = self.apply(check_mode=True, diff=True)
        self.assertTrue(check_result['changed'])
        self.assertTrue(check_result['diff'])
        self.assertNotIn(self.password, json.dumps(check_result))
        self.apply()
        # Reverse a manual ACL change, instead of exporting cached desired state.
        name = policy_name(self.config['management']['policy_prefix'], 'access')
        modified = self.grant(permissions=['read'], logical='manual/' + self.name)
        self.client.request('POST', 'sys/policies/acl/' + name, {'policy': compile_grant(modified)})
        export_config = copy.deepcopy(self.config)
        export_config['mode'] = 'export'
        destination = self.work / 'export.yml'
        options = {'destination': str(destination)}
        result = self.apply(config=export_config, export=options, check_mode=True)
        self.assertTrue(result['changed'])
        self.assertFalse(destination.exists())
        export_client = Client(self.server.connection, self.server.token)
        run(export_config, {}, self.server.token, export=options, client=export_client)
        self.assertTrue(all(request['method'] in {'GET', 'LIST'} for request in export_client.requests))
        self.assertFalse(any('/data/' in request['path'] or '/metadata/' in request['path'] for request in export_client.requests))
        export_text = destination.read_text()
        variables = yaml.safe_load(export_text)
        self.assertFalse(export_text.lstrip().startswith('{'))
        self.assertEqual(variables['vault_configuration_grants'][0]['paths'][0]['path'], 'manual/' + self.name)
        imported = {key.removeprefix('vault_configuration_') if hasattr(key, 'removeprefix') else key[len('vault_configuration_'):]: value for key, value in variables.items()}
        for user in imported['users']:
            user.pop('password', None)
        second_config = copy.deepcopy(self.config)
        second_config['connection'] = self.second.connection
        second_config['management']['state_file'] = str(self.work / 'target' / 'state.json')
        result = run(second_config, imported, self.second.token, passwords={self.name: self.password})
        self.assertTrue(result['changed'])
        self.assertFalse(run(second_config, imported, self.second.token, passwords={self.name: self.password})['changed'])
        self.assertNotIn(self.password, destination.read_text())
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.apply(config=export_config, export=options)['changed'])

    def test_password_revisions_and_existing_on_create(self):
        self.apply()
        self.sections['users'][0]['password_policy'] = 'on_create'
        result = run(self.config, self.sections, self.server.token)
        self.assertEqual(result['confirmed'], [])
        self.assertFalse(run(self.config, self.sections, self.server.token)['changed'])
        self.sections['users'][0]['password_policy'] = 'on_revision'
        self.password = 'explicitly-rotated-test-password'
        self.sections['users'][0]['password_revision'] = 'r2'
        self.assertTrue(self.apply()['changed'])
        self.login()
        self.assertFalse(self.apply()['changed'])
        registry = Path(self.config['management']['state_file']).read_text()
        self.assertNotIn(self.password, registry)
        self.assertNotIn(hashlib.sha256(self.password.encode()).hexdigest(), registry)

    def test_adoption_registry_loss_protected_and_prune(self):
        self.sections['grants'] = [self.grant()]
        self.apply()
        registry_file = Path(self.config['management']['state_file'])
        registry = json.loads(registry_file.read_text())
        entity_record = registry['resources']['entity:' + self.name]
        registry_file.rename(registry_file.with_suffix('.saved'))
        with self.assertRaises(ConfigurationError):
            self.apply()
        registry_file.with_suffix('.saved').rename(registry_file)
        protected = copy.deepcopy(self.config)
        protected['safety']['protected_entities'] = [entity_record['uuid']]
        with self.assertRaises(ConfigurationError):
            self.apply(config=protected)
        # Prune grant: detach links first, then delete only the owned policy.
        self.sections['grants'] = []
        self.config['management']['prune'] = True
        self.config['safety']['allow_empty_desired'] = True
        name = policy_name(self.config['management']['policy_prefix'], 'access')
        current_policy = {'policy': self.client.read('sys/policies/acl/' + name)['policy']}
        self.config['management']['deletion_approvals'] = [{'kind': 'policy', 'id': 'access', 'hash': digest(current_policy), 'dependencies_cleared': True}]
        self.assertTrue(self.apply()['changed'])
        self.assertIsNone(self.client.read('sys/policies/acl/' + name, missing=True))
        self.assertFalse(self.apply()['changed'])

    def test_partial_failure_recovery_and_drift(self):
        self.sections['grants'] = [self.grant()]
        class FailAfterWrite(Client):
            failed = False
            def request(inner, method, api_path, payload=None, missing=False):
                response = super(FailAfterWrite, inner).request(method, api_path, payload, missing)
                if method == 'POST' and api_path == 'identity/entity' and not inner.failed:
                    inner.failed = True
                    raise VaultHTTPError(method, 'transport', True)
                return response
        failing = FailAfterWrite(self.server.connection, self.server.token)
        with self.assertRaises(PartialApply) as raised:
            self.apply(client=failing)
        self.assertTrue(raised.exception.confirmed)
        registry = json.loads(Path(self.config['management']['state_file']).read_text())
        self.assertNotIn(self.password, json.dumps(registry))
        self.config['management']['recovery'] = {'digest': registry['pending']['digest'], 'outcome': 'applied'}
        self.assertTrue(self.apply()['changed'])
        self.assertFalse(self.apply()['changed'])
        # A read failure is never absence.
        self.client.request('POST', 'sys/policies/acl/limited', {'policy': 'path "sys/health" { capabilities = ["read"] }'})
        limited = self.client.request('POST', 'auth/token/create', {'policies': ['limited'], 'no_default_policy': True})
        with self.assertRaises(ConfigurationError):
            run(self.config, self.sections, limited['auth']['client_token'])

    def test_ansible_import_vars_files_check_diff(self):
        self.sections['grants'] = [self.grant()]
        self.sections['personal_access'] = {'enabled': True, 'mount': 'users',
                                          'subjects': [{'kind': 'user', 'id': self.name}], 'permissions': ['read', 'write']}
        self.apply()
        exported = self.work / 'export.yml'
        self.apply(config=dict(self.config, mode='export'), export={'destination': str(exported)})
        target = copy.deepcopy(self.config)
        target['connection'] = self.second.connection
        target['management']['state_file'] = str(self.work / 'target' / 'state.json')
        def flat_config(value, prefix='vault_configuration_config'):
            variables = {}
            for key, item in value.items():
                variable_name = prefix + '_' + key
                if isinstance(item, dict):
                    variables.update(flat_config(item, variable_name))
                else:
                    variables[variable_name] = item
            return variables
        values = flat_config(target)
        # Inventory overrides individual settings; the role must retain the other defaults.
        for variable in ('vault_configuration_config_schema_version',
                         'vault_configuration_config_connection_validate_tls',
                         'vault_configuration_config_connection_timeout_seconds',
                         'vault_configuration_config_safety_max_deletions'):
            values.pop(variable)
        values.update(vault_configuration_token=self.second.token,
                      vault_configuration_passwords={self.name: self.password})
        values_file = self.work / 'target-vars.yml'
        values_file.write_text(json.dumps(values))
        values_file.chmod(0o600)
        playbook = self.work / 'playbook.yml'
        playbook.write_text(json.dumps([{'name':'Import the actual exported variables', 'hosts':'localhost',
                                        'connection':'local', 'gather_facts':False,
                                        'vars_files':[str(exported), str(values_file)], 'roles':['vault-configuration']}]))
        command = ['ansible-playbook', '-i', 'localhost,', str(playbook)]
        environment = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / 'ansible.cfg'), ANSIBLE_ROLES_PATH=str(ROOT / 'roles'))
        for options in [['--check', '--diff'], [], []]:
            response = subprocess.run(command + options, env=environment, cwd=str(ROOT),
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.assertEqual(response.returncode, 0, response.stdout)
            self.assertIn('Планируем добавить', response.stdout)
            self.assertIn('Планируем изменить', response.stdout)
            self.assertIn('Планируем удалить', response.stdout)
            self.assertIn('"mode": "apply"', response.stdout)
            self.assertNotIn(self.second.token, response.stdout)
            self.assertNotIn(self.password, response.stdout)
            if options:
                self.assertFalse(Path(target['management']['state_file']).exists())
                self.assertIn('--- before', response.stdout)
        self.assertIn('changed=0', response.stdout)
        for extra in ({'vault_configuration_config': {}}, {'vault_configuration_config_unknown': True}):
            rejected = subprocess.run(command + ['--tags', 'pre-req', '-e', json.dumps(extra)],
                                      env=environment, cwd=str(ROOT), stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('Require flat configuration variables', rejected.stdout)
        dry = subprocess.run(command + ['-e', 'vault_configuration_config_mode=dry'],
                             env=environment, cwd=str(ROOT), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
        self.assertEqual(dry.returncode, 0, dry.stdout)
        self.assertIn('changed=1', dry.stdout)
        default_report_path = self.work / 'vault-configuration-localhost-dry.yml'
        default_report_text = default_report_path.read_text()
        default_report = yaml.safe_load(default_report_text)
        self.assertEqual(default_report['mode'], 'dry')
        self.assertEqual(default_report['plan']['operations'], [])
        self.assertNotIn('"action": "noop"', dry.stdout)
        self.assertNotIn(self.second.token, default_report_text)
        self.assertNotIn(self.password, default_report_text)
        dry_again = subprocess.run(command + ['-e', 'vault_configuration_config_mode=dry'],
                                   env=environment, cwd=str(ROOT), stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)
        self.assertEqual(dry_again.returncode, 0, dry_again.stdout)
        self.assertIn('changed=0', dry_again.stdout)
        role_export = self.work / 'role-export.yml'
        values['vault_configuration_config_mode'] = 'export'
        values['vault_configuration_export'] = {'destination': str(role_export)}
        values.pop('vault_configuration_passwords')
        values_file.write_text(json.dumps(values))
        for options in (['--check'], []):
            exported_result = subprocess.run(command + options, env=environment, cwd=str(ROOT),
                                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.assertEqual(exported_result.returncode, 0, exported_result.stdout)
            self.assertEqual(role_export.exists(), not bool(options))
        # Reusing the exported file on its source is also idempotent after importing current API values.
        self.assertFalse(self.apply()['changed'])

    def test_bootstrap_policy_works_without_root_token(self):
        policy = (ROLE / 'files/bootstrap-policy.hcl').read_text()
        policy_name = self.name + '-automation'
        self.client.request('POST', 'sys/policies/acl/' + policy_name, {'policy': policy})
        token = self.client.request('POST', 'auth/token/create',
                                    {'policies':[policy_name], 'no_default_policy':True, 'no_parent':True,
                                     'ttl':'5m', 'explicit_max_ttl':'5m', 'renewable':False})['auth']['client_token']
        administrator = Client(self.server.connection, token)
        self.assertEqual(administrator.read('auth/token/lookup-self')['policies'], [policy_name])
        # Arbitrary nested auth paths and a different policy prefix need no ACL regeneration.
        userpass_mount = 'company/staff'
        approle_mount = 'company/services'
        kv_mount = 'company-apps'
        self.assertNotIn(userpass_mount + '/', administrator.read('sys/auth'))
        administrator.request('POST', 'sys/auth/' + approle_mount, {'type': 'approle'})
        administrator.request('POST', 'auth/' + approle_mount + '/role/ansible', {'token_ttl': 300})
        self.config['mounts'] = [kv_mount]
        self.config['management']['policy_prefix'] = 'access-company-'
        self.sections['users'][0]['auth_mount'] = userpass_mount
        self.sections['auth_roles'] = [{'id': 'automation', 'type': 'approle',
                                        'auth_mount': approle_mount, 'name': 'ansible'}]
        access = self.grant()
        access['paths'][0]['mount'] = kv_mount
        access['subjects'].append({'kind': 'auth_role', 'id': 'automation'})
        self.sections['grants'] = [access]
        result = run(self.config, self.sections, token, passwords={self.name:self.password})
        self.assertTrue(result['changed'])
        self.assertEqual(administrator.read('sys/auth')[userpass_mount + '/']['type'], 'userpass')
        self.assertFalse(run(self.config, self.sections, token, passwords={self.name:self.password})['changed'])
        assigned = administrator.read('auth/' + approle_mount + '/role/ansible')['token_policies']
        self.assertTrue(any(name.startswith('access-company-') for name in assigned))
        # The same token can update ACLs and export, but has no direct KV data access.
        self.sections['grants'][0]['paths'][0]['permissions'] = ['read', 'write']
        self.assertTrue(run(self.config, self.sections, token)['changed'])
        export_path = self.work / 'export.yml'
        run(dict(self.config, mode='export'), {}, token, export={'destination': str(export_path)})
        self.assertTrue(export_path.is_file())
        with self.assertRaises(VaultHTTPError):
            administrator.request('POST', kv_mount + '/data/fixture', {'data': {'value': 'test'}})
        # Bypass the client guard to prove Vault ACLs also refuse mount deletion.
        for api in ['sys/mounts/' + kv_mount, 'sys/auth/' + userpass_mount]:
            request = Request(administrator.address + '/v1/' + api,
                              headers={'X-Vault-Token': token}, method='DELETE')
            with self.assertRaises(HTTPError) as error:
                administrator.opener.open(request)
            self.assertEqual(error.exception.code, 403)
            error.exception.close()
        managed_acl = next(name for name in assigned if name.startswith('access-company-'))
        current_policy = {'policy': administrator.read('sys/policies/acl/' + managed_acl)['policy']}
        self.config['management'].update(prune=True, deletion_approvals=[
            {'kind': 'policy', 'id': 'access', 'hash': digest(current_policy), 'dependencies_cleared': True}])
        self.config['safety']['allow_empty_desired'] = True
        self.assertTrue(run(self.config, dict(self.sections, grants=[]), token)['changed'])
        self.assertIn(kv_mount + '/', administrator.read('sys/mounts'))

    def test_z_sealed_vault_refuses_all_changes(self):
        self.second.client.request('POST', 'sys/seal')
        target = copy.deepcopy(self.config)
        target['connection'] = self.second.connection
        with self.assertRaises(ConfigurationError):
            run(target, self.sections, self.second.token)

    def test_historical_read_and_patch(self):
        logical = self.name + '/key'
        self.client.request('POST', 'apps/data/' + logical, {'data': {'version': 1}})
        self.client.request('POST', 'apps/data/' + logical, {'data': {'version': 2}})
        self.sections['grants'] = [self.grant(logical=logical, scope='exact')]
        self.apply()
        ordinary, _ = self.login()
        request = Request(ordinary.address + '/v1/apps/data/' + logical + '?version=1',
                          headers={'X-Vault-Token': ordinary.token}, method='GET')
        with ordinary.opener.open(request) as response:
            self.assertEqual(json.load(response)['data']['data']['version'], 1)
        self.sections['grants'] = [self.grant(permissions=['patch'], logical=logical, scope='exact')]
        self.apply()
        ordinary, _ = self.login()
        request = Request(ordinary.address + '/v1/apps/data/' + logical,
                          data=json.dumps({'data': {'patched': True}}).encode(), method='PATCH',
                          headers={'X-Vault-Token': ordinary.token, 'Content-Type': 'application/merge-patch+json'})
        with ordinary.opener.open(request) as response:
            self.assertEqual(response.status, 200)
        self.assertTrue(self.client.read('apps/data/' + logical)['data']['patched'])
        with self.assertRaises(VaultHTTPError):
            ordinary.read('apps/data/' + logical)

    def test_each_version_operation_is_separate(self):
        self.config['safety']['allow_destructive_grants'] = True
        operations = {
            'delete_latest': ('DELETE', 'data', None),
            'delete_versions': ('POST', 'delete', {'versions': [1]}),
            'undelete_versions': ('POST', 'undelete', {'versions': [1]}),
            'destroy_versions': ('POST', 'destroy', {'versions': [1]}),
            'delete_metadata': ('DELETE', 'metadata', None),
            'update_metadata': ('POST', 'metadata', {'max_versions': 3}),
            'read_metadata': ('GET', 'metadata', None),
        }
        for permission, (method, api, payload) in operations.items():
            logical = self.name + '/' + permission
            for version in range(2):
                self.client.request('POST', 'apps/data/' + logical, {'data': {'version': version}})
            if permission == 'undelete_versions':
                self.client.request('POST', 'apps/delete/' + logical, {'versions': [1]})
            self.sections['grants'] = [self.grant(permissions=[permission], logical=logical, scope='exact')]
            self.apply()
            ordinary, _ = self.login()
            ordinary.request(method, 'apps/' + api + '/' + logical, payload)
            if permission != 'destroy_versions':
                with self.assertRaises(VaultHTTPError):
                    ordinary.request('POST', 'apps/destroy/' + logical, {'versions': [2]})
            if permission not in {'read_metadata'}:
                with self.assertRaises(VaultHTTPError):
                    ordinary.read('apps/data/' + logical)

    def test_preserve_foreign_bindings_and_effective_cycle(self):
        child = self.name + '-child'
        self.sections['groups'] = [{'id': child, 'name': child, 'type': 'internal', 'members': [self.name]}]
        self.sections['grants'] = [self.grant(kind='group', subject=child)]
        self.apply()
        registry = json.loads(Path(self.config['management']['state_file']).read_text())
        group_uuid = registry['resources']['group:' + child]['uuid']
        foreign_policy = self.name + '-foreign'
        self.client.request('POST', 'sys/policies/acl/' + foreign_policy, {'policy': 'path "infra/data/fixture" { capabilities = ["read"] }'})
        current = self.client.read('identity/group/id/' + group_uuid)
        self.client.request('POST', 'identity/group/id/' + group_uuid,
                            {'policies': current['policies'] + [foreign_policy]})
        self.sections['grants'] = []
        self.apply()
        self.assertEqual(self.client.read('identity/group/id/' + group_uuid)['policies'], [foreign_policy])
        # The role must consider cycles through unmanaged groups too.
        foreign = self.client.request('POST', 'identity/group', {'name': self.name + '-foreign-group', 'type': 'internal',
                                       'member_group_ids': [group_uuid]})['data']['id']
        self.sections['groups'][0]['member_groups'] = [{'uuid': foreign}]
        with self.assertRaises(ConfigurationError):
            self.apply()

    def test_drift_wrong_cluster_and_corrupt_registry(self):
        self.apply()
        outer = self
        class Drift(Client):
            reads = 0
            def request(inner, method, api_path, payload=None, missing=False):
                if method == 'GET' and api_path == 'sys/health':
                    inner.reads += 1
                    if inner.reads == 2:
                        registry = json.loads(Path(outer.config['management']['state_file']).read_text())
                        uuid = registry['resources']['entity:' + outer.name]['uuid']
                        outer.client.request('POST', 'identity/entity/id/' + uuid, {'metadata': {'foreign': 'changed'}})
                return super(Drift, inner).request(method, api_path, payload, missing)
        with self.assertRaises(ConfigurationError):
            self.apply(client=Drift(self.server.connection, self.server.token))
        wrong = copy.deepcopy(self.config)
        wrong['connection'] = self.second.connection
        with self.assertRaises(ConfigurationError):
            run(wrong, self.sections, self.second.token)
        Path(self.config['management']['state_file']).write_text('{broken')
        with self.assertRaises(ConfigurationError):
            self.apply()

    def test_password_response_loss_needs_operator_decision(self):
        self.apply()
        self.sections['users'][0]['password_revision'] = 'r2'
        self.password += '-rotated'
        class LosePasswordResponse(Client):
            def request(inner, method, api_path, payload=None, missing=False):
                response = super(LosePasswordResponse, inner).request(method, api_path, payload, missing)
                if method == 'POST' and api_path.startswith('auth/userpass/users/') and payload and 'password' in payload:
                    raise VaultHTTPError(method, 'transport', True)
                return response
        with self.assertRaises(PartialApply):
            self.apply(client=LosePasswordResponse(self.server.connection, self.server.token))
        with self.assertRaises(ConfigurationError):
            self.apply()
        self.login()  # Operator fixture verifies the new password without putting it in a report.
        registry = json.loads(Path(self.config['management']['state_file']).read_text())
        self.config['management']['recovery'] = {'digest': registry['pending']['digest'], 'outcome': 'applied'}
        result = self.apply()
        self.assertEqual(result['confirmed'], [])
        self.assertNotIn(self.password, json.dumps(result))

    def test_scoped_export_and_unsupported(self):
        self.apply()
        name = self.name + '-custom'
        self.client.request('POST', 'sys/policies/acl/' + name, {'policy': 'path "apps/data/*" { capabilities = ["deny"] }'})
        entity = self.login()[1]
        data = self.client.read('identity/entity/id/' + entity)
        self.client.request('POST', 'identity/entity/id/' + entity, {'policies': [name]})
        export_config = dict(self.config, mode='export')
        destination = self.work / 'scoped.yml'
        options = {'scope': 'scoped', 'entities': [entity], 'policies': [name], 'destination': str(destination)}
        with self.assertRaises(ConfigurationError):
            run(export_config, {}, self.server.token, export=options)
        self.assertFalse(destination.exists())
        options['allow_partial'] = True
        self.assertTrue(run(export_config, {}, self.server.token, export=options)['partial'])
        export_text = destination.read_text()
        exported = yaml.safe_load(export_text)
        self.assertNotIn('vault_configuration_grants', exported)


if __name__ == '__main__':
    unittest.main()
