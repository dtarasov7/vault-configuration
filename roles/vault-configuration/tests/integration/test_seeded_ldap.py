"""Run the seeder against a real isolated LDAP and use its output with Vault."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

import yaml

from test_vault import ROOT, Server, free_port
from vault_configuration.client import Client, VaultHTTPError
from vault_configuration.runner import run
from vault_configuration.validation import DEFAULTS

IMAGE = 'osixia/openldap:1.5.0@sha256:18742e9c449c9c1afe129d3f2f3ee15fb34cc43e5f940a20f3399728f41d7c28'
IMPORT = """import importlib.util,json,os,tempfile
from pathlib import Path
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location('seed','/seed-scripts/seed-test-ldap-redos8.py')
seed=importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed)
"""


class LDAPSeederIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='seed-ldap-', dir=str(ROOT / '.work'))
        cls.directory = Path(cls.temporary.name)
        cls.port = free_port()
        cls.container = 'vault-ldap-seeder-' + str(cls.port)
        subprocess.run(['docker', 'run', '--rm', '-d', '--name', cls.container,
                        '-p', '127.0.0.1:' + str(cls.port) + ':389',
                        '-e', 'LDAP_DOMAIN=fixture.invalid', '-e', 'LDAP_ORGANISATION=Fixture',
                        '-e', 'LDAP_ADMIN_PASSWORD=fixture-only-password', '-e', 'LDAP_TLS=false',
                        '-v', str(ROOT / 'scripts') + ':/seed-scripts:ro',
                        '-v', str(cls.directory) + ':/seed-work', IMAGE], check=True, stdout=subprocess.DEVNULL)
        for attempt in range(100):
            logs = subprocess.run(['docker', 'logs', cls.container], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            if 'Running /container/run/process/slapd/run' in logs.stdout:
                break
            time.sleep(0.1)
        else:
            cls.tearDownClass()
            raise RuntimeError('OpenLDAP fixture startup timed out')

    @classmethod
    def tearDownClass(cls):
        # Only the root-owned private fixture directories inside our workspace mount.
        subprocess.run(['docker', 'exec', cls.container, 'python3', '-c',
                        "import shutil; shutil.rmtree('/seed-work/state',ignore_errors=True); shutil.rmtree('/seed-work/recovery-state',ignore_errors=True); shutil.rmtree('/seed-work/example-state',ignore_errors=True)"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['docker', 'rm', '-f', cls.container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.temporary.cleanup()

    def execute(self, code):
        response = subprocess.run(['docker', 'exec', '-i', self.container, 'python3', '-'], input=IMPORT + code,
                                  text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(response.returncode, 0, response.stderr)
        return response.stdout

    def test_redos8_example_inventory_and_playbooks(self):
        self.execute("""
args=SimpleNamespace(domain='example-lab.test',hostname='redos8',state_dir=Path('/seed-work/example-state'),data_dir=Path('/var/lib/ldap/example-lab'),schema_dir=Path('/etc/ldap/schema'),check=False)
seed.seed(args,seed.LDAP(args.state_dir),account='openldap')
""")
        credentials_json = self.execute("print(Path('/seed-work/example-state/ldap-secrets.json').read_text())")
        credentials = json.loads(credentials_json)
        accounts_json = self.execute("print(Path('/seed-work/example-state/test-accounts.json').read_text())")
        accounts = json.loads(accounts_json)
        example = ROOT / 'examples/redos8-lab'
        work = self.directory / 'example-controller'
        work.mkdir(mode=0o700)
        state_dir = work / 'private'
        port = free_port()
        cluster_port = free_port()
        connection = dict(DEFAULTS['connection'], address='http://127.0.0.1:' + str(port), allow_insecure_http=True)
        server_config = {'disable_mlock': True, 'api_addr': connection['address'],
                         'listener': {'tcp': {'address': '127.0.0.1:' + str(port),
                                             'cluster_address': '127.0.0.1:' + str(cluster_port), 'tls_disable': True}},
                         'storage': {'file': {'path': str(work / 'data')}}}
        server_config_json = json.dumps(server_config)
        server_config_file = work / 'vault.json'
        server_config_file.write_text(server_config_json)
        log = (work / 'vault.log').open('w')
        process = subprocess.Popen(['vault', 'server', '-config=' + str(server_config_file)],
                                   stdout=log, stderr=subprocess.STDOUT)
        try:
            probe = Client(connection, 'uninitialized-test-probe')
            for attempt in range(100):
                try:
                    probe.request('GET', 'sys/init')
                    break
                except VaultHTTPError:
                    if process.poll() is not None:
                        self.fail('Isolated Vault failed to start')
                    time.sleep(0.05)
            else:
                self.fail('Isolated Vault startup timed out')
            overrides = {'ansible_connection': 'local', 'ansible_become': False,
                         'ansible_python_interpreter': sys.executable,
                         'vault_lab_server_address': '127.0.0.1', 'hashicorp_vault_api_port': port,
                         'vault_lab_state_dir': str(state_dir), 'vault_lab_ldap_base_dn': accounts['base_dn'],
                         'vault_lab_ldap_url': 'ldap://127.0.0.1:' + str(self.port),
                         'vault_configuration_token': "{{ (lookup('ansible.builtin.file', vault_lab_init_file) | from_json).root_token }}",
                         'vault_configuration_passwords': {'local-alice': 'example-fixture-alice',
                                                           'local-bob': 'example-fixture-bob'},
                         'vault_configuration_ldap_passwords': credentials['vault_configuration_ldap_passwords']}
            overrides_file = work / 'overrides.json'
            overrides_json = json.dumps(overrides)
            overrides_file.write_text(overrides_json)
            overrides_file.chmod(0o600)
            for filename, role in [('01-install.yml', 'hashicorp-vault'), ('02-configure.yml', 'vault-configuration')]:
                playbook_text = (example / filename).read_text()
                plays = yaml.safe_load(playbook_text)
                self.assertEqual(len(plays), 1)
                self.assertEqual(plays[0]['roles'], [{'role': role}])
                self.assertFalse({'tasks', 'pre_tasks', 'post_tasks', 'handlers'} & set(plays[0]))
            self.assertFalse((example / 'roles').exists())
            environment = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / 'ansible.cfg'),
                               ANSIBLE_ROLES_PATH=str(ROOT / 'roles'))
            command = ['ansible-playbook', '-i', str(example / 'hosts.ini'), '-e', '@' + str(overrides_file)]
            outputs = []
            init_file = state_dir / 'vault-init.json'
            # Run the real init/unseal tasks; only RPM/systemd deployment is replaced by the fixture.
            for attempt in range(2):
                response = subprocess.run(command + [str(example / '01-install.yml'), '--tags', 'init'],
                                          env=environment, cwd=str(ROOT), stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT, text=True)
                self.assertEqual(response.returncode, 0, response.stdout)
                outputs.append(response.stdout)
                initialization_json = init_file.read_text()
                initialization = json.loads(initialization_json)
                if attempt == 0:
                    initial_material = initialization
                else:
                    self.assertEqual(initialization, initial_material)
            self.assertEqual(state_dir.stat().st_mode & 0o777, 0o700)
            self.assertEqual(init_file.stat().st_mode & 0o777, 0o600)
            admin = Client(connection, initialization['root_token'])
            self.assertFalse(admin.request('GET', 'sys/health')['sealed'])
            self.assertNotIn('userpass/', admin.read('sys/auth'))
            local_passwords = overrides['vault_configuration_passwords']

            report_path = state_dir / 'dry-result.yml'
            modes = (['-e', 'vault_configuration_config_mode=dry', '--check'],
                     ['-e', 'vault_configuration_config_mode=dry'],
                     ['-e', 'vault_configuration_config_mode=dry'], ['--check', '--diff'], [], [])
            for index, options in enumerate(modes):
                response = subprocess.run(command + [str(example / '02-configure.yml')] + options,
                                          env=environment, cwd=str(ROOT), stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT, text=True)
                self.assertEqual(response.returncode, 0, response.stdout)
                outputs.append(response.stdout)
                if index == 0:
                    self.assertFalse(report_path.exists())
                elif index in [1, 2]:
                    report_text = report_path.read_text()
                    report = yaml.safe_load(report_text)
                    self.assertEqual(report['mode'], 'dry')
                    self.assertTrue(report['plan']['operations'])
                    self.assertIn('Планируем добавить', report['summary'])
                    self.assertFalse(report_text.lstrip().startswith('{'))
                    self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)
                    if index == 2:
                        self.assertIn('changed=0', response.stdout)
                if options:
                    self.assertNotIn('userpass/', admin.read('sys/auth'))
                    self.assertNotIn('ldap/', admin.read('sys/auth'))
                    self.assertNotIn('apps/', admin.read('sys/mounts'))
            self.assertIn('changed=0', response.stdout)
            actual_mounts = admin.read('sys/mounts')
            for mount in ['certs', 'infra', 'apps', 'cicd', 'users']:
                self.assertEqual(actual_mounts[mount + '/']['type'], 'kv')
                self.assertEqual(actual_mounts[mount + '/']['options']['version'], '2')
            secret_values = [initialization['root_token']] + initialization['keys_base64']
            secret_values.extend(local_passwords.values())
            secret_values.extend(credentials['vault_configuration_ldap_passwords'].values())
            for output in outputs:
                for secret in secret_values:
                    self.assertNotIn(secret, output)
            for secret in secret_values:
                self.assertNotIn(secret, report_path.read_text())

            admin.request('POST', 'apps/data/payments/dev/key', {'data': {'value': 'apps-fixture'}})
            admin.request('POST', 'infra/data/prod/key', {'data': {'value': 'infra-fixture'}})
            logins = [('userpass', name, password, {'developers'} if name == 'local-alice' else {'operators'})
                      for name, password in local_passwords.items()]
            logins.extend(('ldap', name, account['password'], set(account['initial_groups']))
                          for name, account in accounts['users'].items())
            for auth_mount, username, password, groups in logins:
                login = admin.request('POST', 'auth/' + auth_mount + '/login/' + username, {'password': password})
                ordinary = Client(connection, login['auth']['client_token'])
                for group, api in [('developers', 'apps/data/payments/dev/key'), ('operators', 'infra/data/prod/key')]:
                    if group in groups:
                        self.assertIn('data', ordinary.read(api))
                    else:
                        with self.assertRaises(VaultHTTPError):
                            ordinary.read(api)
        finally:
            process.terminate()
            process.wait(timeout=15)
            log.close()

    def test_seed_acl_passwords_and_vault_group_access(self):
        output = self.execute("""
args=SimpleNamespace(domain='example.org',hostname='ldap-test.example.org',state_dir=Path('/seed-work/state'),data_dir=Path('/var/lib/ldap/seed-test'),schema_dir=Path('/etc/ldap/schema'),check=True)
ldap=seed.LDAP(args.state_dir)
plan=seed.seed(args,ldap,account='openldap')
assert len(plan['add_entries'])==11
assert not args.state_dir.exists()
args.check=False
seed.seed(args,ldap,account='openldap')
passwords=json.loads((args.state_dir/'state.json').read_text())['passwords']
second=seed.seed(args,ldap,account='openldap')
assert not second['add_entries'] and not second['create_database']
assert json.loads((args.state_dir/'state.json').read_text())['passwords']==passwords
assert all((file.stat().st_mode & 0o777)==0o600 for file in args.state_dir.iterdir() if file.is_file())
# The read-only Vault bind account must not be able to write a user entry.
fd,filename=tempfile.mkstemp(dir=str(args.state_dir))
try:
    os.fchmod(fd,0o600)
    with os.fdopen(fd,'w') as stream: stream.write(passwords['vault'])
    mutation='dn: uid=alice,ou=people,dc=example,dc=org\\nchangetype: modify\\nreplace: sn\\nsn: forbidden\\n'
    ldap.execute('ldapmodify',['-x','-H','ldapi:///','-D','cn=vault,ou=service,dc=example,dc=org','-y',filename],mutation,accepted=(50,))
finally:
    os.unlink(filename)
""")
        credentials = json.loads(self.execute("print((Path('/seed-work/state/ldap-secrets.json')).read_text())"))
        accounts = json.loads(self.execute("print((Path('/seed-work/state/test-accounts.json')).read_text())"))
        variables = json.loads(self.execute("print((Path('/seed-work/state/ldap-vars.json')).read_text())"))
        for value in credentials['vault_configuration_ldap_passwords'].values():
            self.assertNotIn(value, output)
        for account in accounts['users'].values():
            self.assertNotIn(account['password'], output)
        self.assertTrue(variables['vault_configuration_ldap'][0]['allow_insecure_ldap'])
        variables['vault_configuration_ldap'][0]['config']['url'] = 'ldap://127.0.0.1:' + str(self.port)
        # Ansible normally evaluates this literal-preserving expression in vars_files.
        variables['vault_configuration_ldap'][0]['config']['groupfilter'] = '(&(objectClass=groupOfNames)(member={{.UserDN}}))'
        directory = self.directory / 'vault'
        directory.mkdir()
        server = Server(directory)
        try:
            configuration = copy.deepcopy(DEFAULTS)
            configuration.update(mode='apply', compatibility_profile='community-validated', connection=server.connection)
            configuration['management'].update(owner='seeded-ldap', policy_prefix='vam-seeded-', state_file=str(directory / 'registry' / 'state.json'))
            sections = {key[len('vault_configuration_'):]: value for key, value in variables.items()}
            result = run(configuration, sections, server.token, ldap_passwords=credentials['vault_configuration_ldap_passwords'])
            self.assertTrue(result['changed'])
            self.assertFalse(run(configuration, sections, server.token)['changed'])
            server.client.request('POST', 'apps/data/payments/dev/backend', {'data': {'value': 'app-fixture'}})
            server.client.request('POST', 'infra/data/prod/dns', {'data': {'value': 'infra-fixture'}})
            for username, account in accounts['users'].items():
                login = server.client.request('POST', 'auth/ldap/login/' + username, {'password': account['password']})
                ordinary = Client(server.connection, login['auth']['client_token'])
                for group, path in [('developers', 'apps/data/payments/dev/backend'), ('operators', 'infra/data/prod/dns')]:
                    if group in account['initial_groups']:
                        self.assertIn('data', ordinary.read(path))
                    else:
                        with self.assertRaises(VaultHTTPError):
                            ordinary.read(path)
            # Rerunning the seeder preserves deliberate membership changes for access tests.
            self.execute("""
args=SimpleNamespace(domain='example.org',hostname='ldap-test.example.org',state_dir=Path('/seed-work/state'),data_dir=Path('/var/lib/ldap/seed-test'),schema_dir=Path('/etc/ldap/schema'),check=False)
ldap=seed.LDAP(args.state_dir)
ldap.execute('ldapmodify',['-Q','-Y','EXTERNAL','-H','ldapi:///'], 'dn: cn=developers,ou=groups,dc=example,dc=org\\nchangetype: modify\\ndelete: member\\nmember: uid=alice,ou=people,dc=example,dc=org\\n')
seed.seed(args,ldap,account='openldap')
group=ldap.search('cn=developers,ou=groups,dc=example,dc=org',scope='base',attributes=['member'])[0]
assert 'uid=alice,ou=people,dc=example,dc=org' not in group['member']
""")
        finally:
            server.close()

    def test_resume_after_successful_ldap_add_with_lost_response(self):
        output = self.execute("""
args=SimpleNamespace(domain='recovery.test',hostname='ldap-test.example.org',state_dir=Path('/seed-work/recovery-state'),data_dir=Path('/var/lib/ldap/seed-recovery'),schema_dir=Path('/etc/ldap/schema'),check=False)
class Interrupted(seed.LDAP):
    def add(self,dn,attributes):
        super().add(dn,attributes)
        if dn.startswith('uid=bob,'): raise seed.SeedError('Simulated lost response')
try:
    seed.seed(args,Interrupted(args.state_dir),account='openldap')
except seed.SeedError as error:
    assert str(error)=='Simulated lost response'
else:
    raise AssertionError('Failure injection did not run')
before=json.loads((args.state_dir/'state.json').read_text())
assert before['pending_dn'].startswith('uid=bob,')
seed.seed(args,seed.LDAP(args.state_dir),account='openldap')
after=json.loads((args.state_dir/'state.json').read_text())
assert after['passwords']==before['passwords']
assert after['pending_dn'] is None
assert len(after['entries'])==11
seed.seed(args,seed.LDAP(args.state_dir),account='openldap')
""")
        self.assertIn('LDAP users/groups are ready', output)
