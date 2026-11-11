"""Discover ownership from live metadata and policy names, never from local files.
RU: Определять владение по метаданным Vault и именам политик без локальных файлов.
"""
from .compiler import policy_name
from .common import check
from .reader import OWNER_KEY, ID_KEY
from .adapters import policies


def live_resources(view, config):
    """Return export descriptors inferred from the current Vault snapshot.
    RU: Вернуть описания для экспорта, полученные только из текущего снимка Vault.

    Args:
        view (dict): Current API objects / текущие объекты API.
        config (dict): Owner and policy prefix / владелец и префикс политик.
    Returns:
        dict: Descriptors keyed by API path / описания по путям API.
    Raises:
        ConfigurationError: Owned inventory IDs are ambiguous / неоднозначные ID владельца.
    """
    owner = config['management']['owner']
    prefix = config['management']['policy_prefix']
    resources = {}
    owned = set()
    for kind, index, section in [('entity', 'entities', 'users'), ('group', 'groups', 'groups')]:
        ids = set()
        for uuid, entry in view[index].items():
            metadata = entry['data'].get('metadata', {})
            if metadata.get(OWNER_KEY) != owner or not metadata.get(ID_KEY):
                continue
            identifier = metadata[ID_KEY]
            check(identifier not in ids, 'Duplicate owner/inventory ID metadata in Vault')
            ids.add(identifier)
            owned.add(uuid)
            resources[entry['path']] = {'id': identifier, 'kind': kind, 'path': entry['path'], 'section': section}
    for name, entry in view['policies'].items():
        if not name.startswith(prefix):
            continue
        identifier = name[len(prefix):-13]
        check(identifier and policy_name(prefix, identifier) == name, 'Policy prefix contains an unsupported policy name')
        resources[entry['path']] = {'id': identifier, 'kind': 'policy', 'path': entry['path'], 'section': 'grants'}
    accessors = {item['accessor']: mount.rstrip('/') for mount, item in view['auth'].items()}
    for alias in view['aliases'].values():
        data = alias['data']
        if data['canonical_id'] not in owned:
            continue
        mount = accessors.get(data['mount_accessor'])
        if mount is None:
            continue
        kind = view['auth'][mount + '/']['type']
        if kind == 'ldap':
            path = 'auth/' + mount + '/config'
            resources[path] = {'id': mount.replace('/', '-'), 'kind': 'ldap_config', 'path': path,
                               'auth_mount': mount, 'section': 'ldap'}
        elif kind == 'userpass' and mount + '/' + data['name'] in view['userpass']:
            path = view['userpass'][mount + '/' + data['name']]['path']
            entity = view['entities'][data['canonical_id']]
            resources[path] = {'id': entity['data']['metadata'][ID_KEY], 'kind': 'userpass', 'path': path,
                               'auth_mount': mount, 'login': data['name'], 'section': 'users'}
    for entry in view['roles'].values():
        if any(name.startswith(prefix) for name in policies(entry['data'])):
            resources[entry['path']] = {'id': entry['name'], 'kind': 'auth_role', 'path': entry['path'], 'section': 'auth_roles'}
    return resources
