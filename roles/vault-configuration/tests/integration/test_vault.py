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
        self.config.update(mode='apply', connection=self.server.connection)
        self.config['management'].update(owner=self.name, policy_prefix='vam-' + self.name + '-')
        self.sections = {'users': [{'id': self.name, 'name': self.name, 'source': 'userpass', 'auth_mount': 'userpass',
                                   'login': self.name, 'password_policy': 'on_create'}]}
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
                                      'login': second_id, 'password': 'other-test-password', })
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
        result = run(export_config, {}, self.server.token, export=options)
        self.assertTrue(result['partial'])
        exported = result['_export_variables']
        self.assertNotIn('vault_configuration_grants', exported)


if __name__ == '__main__':
    unittest.main()
