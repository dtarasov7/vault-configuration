"""Three-node integrated-storage failover; real Vault, no production addresses."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from test_vault import free_port, ROOT
from vault_configuration.client import Client
from vault_configuration.common import ConfigurationError
from vault_configuration.runner import run
from vault_configuration.validation import DEFAULTS


class RaftFailover(unittest.TestCase):
    def test_three_nodes_change_active_without_recreating_identities(self):
        if not shutil.which('vault'):
            self.skipTest('Vault binary is unavailable')
        with tempfile.TemporaryDirectory(prefix='vault-ha-', dir=str(ROOT / '.work')) as directory:
            processes, streams, clients = [], [], []
            ports = [free_port() for _ in range(6)]
            try:
                for index in range(3):
                    node = Path(directory) / str(index)
                    node.mkdir()
                    config = {'disable_mlock': True, 'ui': False,
                              'api_addr': 'http://127.0.0.1:' + str(ports[index]),
                              'cluster_addr': 'https://127.0.0.1:' + str(ports[index + 3]),
                              'listener': {'tcp': {'address': '127.0.0.1:' + str(ports[index]),
                                                  'cluster_address': '127.0.0.1:' + str(ports[index + 3]), 'tls_disable': True}},
                              'storage': {'raft': {'path': str(node), 'node_id': 'node-' + str(index)}}}
                    filename = node / 'config.json'
                    filename.write_text(json.dumps(config), encoding='utf-8')
                    stream = open(node / 'server.log', 'w')
                    streams.append(stream)
                    processes.append(subprocess.Popen(['vault', 'server', '-config=' + str(filename)], stdout=stream, stderr=subprocess.STDOUT))
                    connection = dict(DEFAULTS['connection'], address=config['api_addr'], allow_insecure_http=True)
                    clients.append(Client(connection, 'bootstrap-placeholder'))
                for client in clients:
                    for attempt in range(100):
                        try:
                            client.request('GET', 'sys/init')
                            break
                        except ConfigurationError:
                            time.sleep(0.05)
                    else:
                        self.fail('HA Vault startup timed out')
                initialization = clients[0].request('POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
                key = initialization['keys_base64'][0]
                for client in clients:
                    client.token = initialization['root_token']
                clients[0].request('POST', 'sys/unseal', {'key': key})
                for attempt in range(100):
                    try:
                        clients[0].request('GET', 'sys/health')
                        break
                    except ConfigurationError:
                        time.sleep(0.1)
                for client in clients[1:]:
                    client.request('POST', 'sys/storage/raft/join', {'leader_api_addr': clients[0].address})
                    client.request('POST', 'sys/unseal', {'key': key})
                peers = []
                for attempt in range(300):
                    try:
                        peers = clients[0].read('sys/storage/raft/configuration')['config']['servers']
                        if len(peers) == 3 and all(peer['voter'] for peer in peers):
                            break
                    except ConfigurationError:
                        peers = []
                    time.sleep(0.1)
                self.assertEqual(len(peers), 3)
                self.assertTrue(all(peer['voter'] for peer in peers), 'Raft followers were not promoted to voters')
                for mount in DEFAULTS['mounts']:
                    clients[0].request('POST', 'sys/mounts/' + mount, {'type': 'kv', 'options': {'version': '2'}})
                config = copy.deepcopy(DEFAULTS)
                config.update(mode='apply')
                config['connection']['address'] = clients[0].address
                config['connection']['allow_insecure_http'] = True
                config['management'].update(owner='ha', policy_prefix='vam-ha-')
                sections = {'users': [{'id': 'alice', 'name': 'alice', 'source': 'external'}]}
                self.assertTrue(run(config, sections, clients[0].token)['changed'])
                processes[0].terminate()
                processes[0].wait(timeout=15)
                active = None
                for attempt in range(300):
                    for client in clients[1:]:
                        try:
                            health = client.request('GET', 'sys/health')
                            if not health['standby']:
                                active = client
                                break
                        except ConfigurationError:
                            continue
                    if active:
                        break
                    time.sleep(0.1)
                self.assertIsNotNone(active, 'No new active node elected')
                config['connection']['address'] = active.address
                self.assertFalse(run(config, sections, active.token)['changed'])
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                    process.wait(timeout=15)
                for stream in streams:
                    stream.close()


if __name__ == '__main__':
    unittest.main()
