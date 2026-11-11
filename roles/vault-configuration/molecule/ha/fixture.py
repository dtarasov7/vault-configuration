"""Test-only bootstrap/failover helper; credentials never travel through process arguments."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROLE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROLE / 'module_utils'))
from vault_configuration.client import Client
from vault_configuration.common import ConfigurationError, check
sys.path.insert(0, str(ROLE / 'action_plugins'))
from vault_configuration_report import atomic_write
from vault_configuration.validation import DEFAULTS


def active_client(clients, attempts=300):
    for attempt in range(attempts):
        for client in clients:
            try:
                health = client.request('GET', 'sys/health')
                if not health['standby']:
                    return client
            except ConfigurationError:
                continue
        time.sleep(0.1)
    raise ConfigurationError('No active test Vault found')


def main():
    phase, directory = sys.argv[1:]
    credential_file = Path(directory) / 'private.json'
    connections = [dict(DEFAULTS['connection'], address='http://127.0.0.1:' + str(18210+number), allow_insecure_http=True) for number in range(1,4)]
    if phase == 'prepare':
        clients = [Client(connection, 'bootstrap-placeholder') for connection in connections]
        for client in clients:
            for attempt in range(100):
                try:
                    client.request('GET', 'sys/init')
                    break
                except ConfigurationError:
                    time.sleep(0.1)
        initialized = clients[0].request('POST','sys/init', {'secret_shares':1,'secret_threshold':1})
        credentials = {'token':initialized['root_token'], 'key':initialized['keys_base64'][0]}
        atomic_write(str(credential_file), json.dumps(credentials))
        for client in clients:
            client.token = credentials['token']
        clients[0].request('POST','sys/unseal', {'key':credentials['key']})
        active_client([clients[0]])
        for client in clients[1:]:
            client.request('POST','sys/storage/raft/join', {'leader_api_addr':'http://vault-configuration-ha-1:8200'})
            client.request('POST','sys/unseal', {'key':credentials['key']})
        for attempt in range(300):
            servers = clients[0].read('sys/storage/raft/configuration')['config']['servers']
            if len(servers) == 3 and all(server['voter'] for server in servers):
                break
            time.sleep(0.1)
        check(len(servers) == 3 and all(server['voter'] for server in servers), 'HA fixture did not reach three voters')
        for mount in DEFAULTS['mounts']:
            clients[0].request('POST', 'sys/mounts/' + mount, {'type':'kv','options':{'version':'2'}})
        clients[0].request('POST','sys/auth/userpass', {'type':'userpass'})
    elif phase == 'failover':
        credentials = json.loads(credential_file.read_text())
        clients = [Client(connection, credentials['token']) for connection in connections]
        subprocess.run(['docker','stop','vault-configuration-ha-1'], check=True, stdout=subprocess.DEVNULL)
        active = active_client(clients[1:])
        atomic_write(str(Path(directory) / 'active.json'), json.dumps({'address':active.address}))
        print('Two surviving Vault nodes elected a new active node')
    else:
        raise ConfigurationError('Unknown fixture phase')


if __name__ == '__main__':
    main()
