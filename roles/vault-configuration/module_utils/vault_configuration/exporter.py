"""Export current API values, with explicit loss detection and a separate audit."""
import copy

from .common import ConfigurationError, check, digest
from .compiler import reverse
from .reader import OWNER_KEY, ID_KEY
from .adapters import policies, ADAPTERS
from .validation import TOKEN_FIELDS


def export_configuration(view, state, config, options):
    """Reconstruct portable inventory variables and a separate audit.
    RU: Восстановить переносимые переменные инвентаря и отдельный аудит.

    Args:
        view (dict): Vault snapshot / снимок состояния Vault.
        state (dict): Owner registry and pending journal / реестр владельца и журнал незавершённой операции.
        config (dict): Role configuration / настройки роли.
        options (dict): Export scope and loss handling / область экспорта и обработка потери смысла.

    Returns:
        tuple[dict, dict]: Variables and audit; credentials are omitted / переменные и аудит; учётные секреты исключены.

    Raises:
        ConfigurationError: Unsupported ACL, protected dependency or identity collision / неподдерживаемый ACL, защищённая зависимость или коллизия идентификаторов.
    """
    partial = options.get('allow_partial', False)
    scoped = options.get('scope', 'managed') == 'scoped'
    owner = config['management']['owner']
    mounts = options.get('mounts') or config['mounts']
    allowed_auth = options.get('auth_mounts') or [mount.rstrip('/') for mount in view['auth']]
    audit = {'cluster_id': view['cluster_id'], 'owner': owner, 'unsupported': [], 'dependencies': [],
             'objects': [], 'partial': False}
    selected = {'entity': {}, 'group': {}, 'auth_role': {}}
    resources = state['resources']
    records_by_path = {record['path']: record for record in resources.values()}
    accessors = {details['accessor']: mount.rstrip('/') for mount, details in view['auth'].items()}

    def unsupported(kind, identifier, reason):
        audit['unsupported'].append({'kind': kind, 'id': identifier, 'reason': reason})
        check(partial, 'Export would lose meaning: ' + reason + '; no output was written')
        audit['partial'] = True

    def select(kind, entry):
        record = records_by_path.get(entry['path'])
        identifier = record['id'] if record and not record.get('shared') else entry['data'].get('metadata', {}).get(ID_KEY, entry['data']['name'])
        if identifier.startswith('uuid-'):
            identifier = entry['data']['name']
        check(not any(item['id'] == identifier and uuid != entry['uuid']
                      for uuid, item in selected[kind].items()), 'Export inventory ID collision')
        protected = config['safety']['protected_entities' if kind == 'entity' else 'protected_groups']
        if entry['data']['name'] in protected or entry['uuid'] in protected or entry['uuid'] == view.get('automation_entity'):
            check(False, 'Export depends on a protected/automation identity; narrow the scope')
        selected[kind][entry['uuid']] = {'id': identifier, 'entry': entry}

    for kind, index, option in [('entity', 'entities', 'entities'), ('group', 'groups', 'groups')]:
        for uuid, entry in sorted(view[index].items()):
            targets = options.get(option, [])
            wanted = (uuid in targets or entry['data']['name'] in targets) if scoped else (
                entry['data'].get('metadata', {}).get(OWNER_KEY) == owner or
                (entry['path'] in records_by_path and not records_by_path[entry['path']].get('shared')))
            if wanted and (not targets or uuid in targets or entry['data']['name'] in targets):
                select(kind, entry)
        if scoped:
            found = {uuid for uuid in view[index]} | {entry['data']['name'] for entry in view[index].values()}
            check(set(options.get(option, [])) <= found, 'Export selected identity does not exist')
    selected_accounts = set(options.get('users', [])) if scoped else {
        record['auth_mount'] + '/' + record['login'] for record in resources.values() if record['kind'] == 'userpass'}
    check(selected_accounts <= set(view['userpass']), 'Selected userpass account does not exist')
    for alias in view['aliases'].values():
        data = alias['data']
        mount = accessors.get(data['mount_accessor'])
        if alias['kind'] == 'entity_alias' and mount and mount + '/' + data['name'] in selected_accounts:
            entry = view['entities'].get(data['canonical_id'])
            check(entry is not None, 'Selected local account has an unresolved entity alias')
            select('entity', entry)
    for role_key, entry in sorted(view['roles'].items()):
        record = records_by_path.get(entry['path'])
        wanted = role_key in options.get('auth_roles', []) if scoped else record and record['kind'] == 'auth_role'
        if wanted and entry['mount'] in allowed_auth and (not options.get('auth_roles') or role_key in options['auth_roles']):
            identifier = record['id'] if record else entry['name']
            check(identifier not in selected['auth_role'], 'Export role ID collision')
            selected['auth_role'][identifier] = {'id': identifier, 'entry': entry}
    if scoped:
        check(set(options.get('auth_roles', [])) <= set(view['roles']), 'Export selected auth role does not exist')
    selected_policies = set(options.get('policies', [])) if scoped else {
        record['path'].rsplit('/', 1)[-1] for record in resources.values() if record['kind'] == 'policy'}
    if not scoped and options.get('policies'):
        selected_policies &= set(options['policies'])
    check(not selected_policies & set(config['safety']['protected_policies'] + ['root', 'default']), 'System/protected policies are excluded')
    check(selected_policies <= set(view['policies']), 'Export selected policy does not exist')
    # Selecting an owned policy includes its actual current subjects, including manual bindings.
    # RU: Выбор своей политики включает её текущих субъектов, в том числе ручные привязки.
    for kind, index in [('entity', 'entities'), ('group', 'groups')]:
        for uuid, entry in sorted(view[index].items()):
            if set(entry['data'].get('policies', [])) & selected_policies:
                select(kind, entry)
    for role_key, entry in sorted(view['roles'].items()):
        if set(policies(entry['data'])) & selected_policies:
            if entry['mount'] not in allowed_auth:
                unsupported('auth_role', role_key, 'A policy depends on an unselected auth mount')
                continue
            record = records_by_path.get(entry['path'])
            identifier = record['id'] if record else entry['name']
            selected['auth_role'][identifier] = {'id': identifier, 'entry': entry}
    # Include independent identities and every group dependency, never substitute [] for unselected scopes.
    # RU: Включаем отдельные сущности и зависимости групп; не заменяем невыбранные области пустыми списками.
    changed = True
    while changed:
        changed = False
        for item in list(selected['group'].values()):
            group = item['entry']['data']
            for field, kind, index in [('member_entity_ids', 'entity', 'entities'), ('member_group_ids', 'group', 'groups')]:
                for uuid in group.get(field, []):
                    if uuid not in selected[kind]:
                        check(uuid in view[index], 'Export dependency UUID cannot be resolved')
                        select(kind, view[index][uuid])
                        changed = True
    output = {}
    users, groups, roles = [], [], []
    for uuid, item in sorted(selected['entity'].items(), key=lambda pair: pair[1]['id']):
        entry = item['entry']
        if set(entry['data'].get('metadata', {})) - {OWNER_KEY, ID_KEY}:
            unsupported('entity', item['id'], 'Custom entity metadata is not representable')
        user = {'id': item['id'], 'name': entry['data']['name'], 'source': 'external', 'disabled': entry['data'].get('disabled', False)}
        aliases = []
        for alias in sorted(view['aliases'].values(), key=lambda entry: (entry['data']['mount_accessor'], entry['data']['name'])):
            data = alias['data']
            if alias['kind'] != 'entity_alias' or data['canonical_id'] != uuid:
                continue
            if data.get('custom_metadata'):
                unsupported('entity_alias', item['id'], 'Custom alias metadata is not representable')
            mount = accessors.get(data['mount_accessor'])
            if not mount or mount not in allowed_auth:
                unsupported('entity_alias', item['id'], 'Alias auth mount is missing or excluded')
                continue
            local = view['userpass'].get(mount + '/' + data['name'])
            if local is not None:
                if user['source'] == 'userpass':
                    unsupported('userpass', item['id'], 'Multiple local logins per entity are not representable')
                    continue
                if local['data'].get('alias_metadata'):
                    unsupported('userpass', item['id'], 'Userpass alias_metadata is not representable')
                record = records_by_path.get(local['path'], {})
                user.update(source='userpass', auth_mount=mount, login=data['name'],
                            password="{{ vault_configuration_passwords.get(%r, '') }}" % item['id'],
                            password_revision=record.get('password_revision') or 'export-1',
                            password_policy=record.get('password_policy', 'on_create'),
                            token_parameters={key: value for key, value in local['data'].items() if key in TOKEN_FIELDS})
                if local['data'].get('token_policies'):
                    unsupported('userpass', item['id'], 'Direct userpass token policies cannot be represented by entity grants')
            else:
                aliases.append({'auth_mount': mount, 'name': data['name']})
        if aliases:
            user['aliases'] = aliases
        users.append(user)
        audit['objects'].append({'kind': 'entity', 'id': item['id'], 'uuid': uuid, 'hash': digest(entry['data']),
                                 'metadata': copy.deepcopy(entry['data'].get('metadata', {}))})
    for uuid, item in sorted(selected['group'].items(), key=lambda pair: pair[1]['id']):
        data = item['entry']['data']
        if set(data.get('metadata', {})) - {OWNER_KEY, ID_KEY}:
            unsupported('group', item['id'], 'Custom group metadata is not representable')
        group = {'id': item['id'], 'name': data['name'], 'type': data['type']}
        if data['type'] == 'internal':
            group['members'] = sorted(selected['entity'][uuid]['id'] for uuid in data.get('member_entity_ids', []))
            group['member_groups'] = sorted(selected['group'][uuid]['id'] for uuid in data.get('member_group_ids', []))
        aliases = [entry for entry in view['aliases'].values() if entry['kind'] == 'group_alias' and entry['data']['canonical_id'] == uuid]
        if aliases:
            check(len(aliases) == 1 and data['type'] == 'external', 'Unsupported group aliases')
            alias_data = aliases[0]['data']
            if alias_data.get('custom_metadata'):
                unsupported('group_alias', item['id'], 'Custom group alias metadata is not representable')
            mount = accessors.get(alias_data['mount_accessor'])
            if mount not in allowed_auth:
                unsupported('group_alias', item['id'], 'Group alias auth mount is missing or excluded')
            else:
                group['alias'] = {'auth_mount': mount, 'name': alias_data['name']}
        groups.append(group)
        audit['objects'].append({'kind': 'group', 'id': item['id'], 'uuid': uuid, 'hash': digest(data),
                                 'metadata': copy.deepcopy(data.get('metadata', {}))})
    for item in sorted(selected['auth_role'].values(), key=lambda item: item['id']):
        entry = item['entry']
        try:
            ADAPTERS[entry['type']].payload(entry['data'], policies(entry['data']))
        except ConfigurationError as error:
            unsupported('auth_role', item['id'], str(error))
            continue
        roles.append({'id': item['id'], 'type': entry['type'], 'auth_mount': entry['mount'], 'name': entry['name']})
        audit['dependencies'].append({'kind': 'existing_auth_role', 'auth_mount': entry['mount'], 'name': entry['name'],
                                      'hash': digest(entry['data'])})
    linked_accounts = {user['auth_mount'] + '/' + user['login'] for user in users if user['source'] == 'userpass'}
    selected_accounts = set(options.get('users', [])) if scoped else {
        record['auth_mount'] + '/' + record['login'] for record in resources.values() if record['kind'] == 'userpass'}
    check(selected_accounts <= set(view['userpass']), 'Selected userpass account does not exist')
    for account in sorted(selected_accounts - linked_accounts):
        local = view['userpass'][account]
        mount, login = account.rsplit('/', 1)
        if mount not in allowed_auth:
            unsupported('userpass', account, 'Selected userpass auth mount is excluded')
            continue
        record = records_by_path.get(local['path'], {})
        identifier = record.get('id', login)
        check(not any(user['id'] == identifier for user in users), 'Standalone userpass inventory ID collision')
        # Unlogged-in local users do not yet have an entity: create one declaratively at import.
        # RU: У ещё не входивших локальных пользователей нет сущности; объявляем её создание при импорте.
        if local['data'].get('token_policies'):
            unsupported('userpass', account, 'Direct userpass token policies are not representable by entity grants')
            continue
        users.append({'id': identifier, 'name': login, 'source': 'userpass', 'auth_mount': mount, 'login': login,
                      'password': "{{ vault_configuration_passwords.get(%r, '') }}" % identifier,
                      'password_revision': record.get('password_revision') or 'export-1',
                      'password_policy': record.get('password_policy', 'on_create'),
                      'token_parameters': {key: value for key, value in local['data'].items() if key in TOKEN_FIELDS}})
    if users:
        output['vault_configuration_users'] = sorted(users, key=lambda user: user['id'])
    if groups:
        output['vault_configuration_groups'] = groups
    if roles:
        output['vault_configuration_auth_roles'] = roles
    policy_subjects = {}
    for kind, values in selected.items():
        for item in values.values():
            names = policies(item['entry']['data']) if kind == 'auth_role' else item['entry']['data'].get('policies', [])
            subject = {'kind': {'entity': 'user', 'group': 'group', 'auth_role': 'auth_role'}[kind], 'id': item['id']}
            for name in names:
                if name not in {'root', 'default'} and name not in config['safety']['protected_policies']:
                    policy_subjects.setdefault(name, []).append(subject)
                elif name != 'default':
                    unsupported('policy', name, 'Protected policy binding cannot be exported')
    grants = []
    for name in sorted(set(policy_subjects) | selected_policies):
        subjects = sorted(policy_subjects.get(name, []), key=lambda subject: (subject['kind'], subject['id']))
        if not subjects:
            unsupported('policy', name, 'Unbound policy cannot be represented as a grant')
            continue
        if name not in selected_policies:
            # Foreign policies are dependencies; do not claim or reverse them automatically.
            # RU: Чужие политики считаются зависимостями без автоматического принятия под управление или разбора.
            grants.append({'id': 'existing-' + digest(name)[:16], 'subjects': subjects, 'existing_policies': [name]})
            audit['dependencies'].append({'kind': 'existing_policy', 'name': name})
            continue
        try:
            converted = reverse(view['policies'][name]['data']['policy'], mounts)
        except ConfigurationError as error:
            unsupported('policy', name, str(error))
            continue
        if 'personal' in converted:
            personal = converted['personal']
            allowed_subjects = {'user', 'group'} if personal.get('identity_source') == 'ldap_login' else {'user'}
            if 'vault_configuration_personal_access' in output or any(subject['kind'] not in allowed_subjects for subject in subjects):
                unsupported('policy', name, 'Multiple personal policies or incompatible subjects are unsupported')
                continue
            if personal.get('identity_source') == 'ldap_login':
                source_accessor = personal.pop('auth_accessor')
                mount = accessors.get(source_accessor)
                if not mount or mount not in allowed_auth or view['auth'][mount + '/']['type'] != 'ldap':
                    unsupported('policy', name, 'Personal policy LDAP accessor cannot be resolved in the selected scope')
                    continue
                ldap_configuration = view['objects'].get('auth/' + mount + '/config', {})
                if not ldap_configuration.get('username_as_alias'):
                    unsupported('policy', name, 'Personal policy requires LDAP username_as_alias=true')
                    continue
                personal['auth_mount'] = mount
            output['vault_configuration_personal_access'] = dict(personal, subjects=subjects)
        else:
            record = records_by_path.get(view['policies'][name]['path'])
            identifier = record['id'] if record else 'policy-' + digest(name)[:16]
            grants.append(dict(converted, id=identifier, subjects=subjects))
        audit['objects'].append({'kind': 'policy', 'name': name, 'hash': digest(view['policies'][name]['data'])})
    if grants:
        output['vault_configuration_grants'] = grants
    audit['accessors'] = {mount: view['auth'][mount + '/']['accessor'] for mount in sorted(allowed_auth) if mount + '/' in view['auth']}
    ldap_integrations = []
    ldap_records = {record['auth_mount']: record for record in resources.values() if record['kind'] == 'ldap_config'}
    ldap_mounts = set(options.get('ldap', [])) if scoped else set(ldap_records)
    for mount in sorted(ldap_mounts):
        details = view['auth'].get(mount + '/')
        check(details is not None and details['type'] == 'ldap', 'Selected LDAP auth mount does not exist')
        if mount not in allowed_auth:
            unsupported('ldap', mount, 'LDAP auth mount is excluded')
            continue
        data = view['objects'].get('auth/' + mount + '/config')
        check(data is not None, 'LDAP configuration is unavailable')
        if view.get('ldap_external_policies', {}).get(mount):
            unsupported('ldap', mount, 'Direct LDAP token policies cannot be represented by Identity group grants')
        record = ldap_records.get(mount, {})
        identifier = record.get('id', mount.replace('/', '-'))
        configuration = copy.deepcopy(data)
        # Protect Go templates when the exported variables are loaded through Ansible vars_files.
        # RU: Экранируем Go-шаблоны для последующей загрузки переменных через Ansible vars_files.
        for field, value in configuration.items():
            if isinstance(value, str) and ('{{' in value or '{%' in value):
                configuration[field] = '{{ ' + repr(value) + ' }}'
        item = {'id': identifier, 'auth_mount': mount, 'config': configuration}
        if data.get('binddn'):
            item['bind_password_revision'] = record.get('password_revision') or 'export-1'
        if any(url.strip().startswith('ldap://') for url in data.get('url', '').split(',')) and not data.get('starttls'):
            item['allow_insecure_ldap'] = True
        ldap_integrations.append(item)
        audit['dependencies'].append({'kind': 'ldap_directory', 'auth_mount': mount, 'url': data.get('url'),
                                       'bind_password_required': bool(data.get('binddn'))})
    if ldap_integrations:
        output['vault_configuration_ldap'] = ldap_integrations
    # Explicit empty managed sections remain empty only when their entire selected scope is known empty.
    # RU: Явно пустой управляемый раздел сохраняется пустым, только если вся выбранная область пуста.
    if not audit['partial'] and not scoped:
        for section, kind in [('users', 'entity'), ('groups', 'group'), ('auth_roles', 'auth_role')]:
            if not selected[kind] and any(record['section'] == section for record in resources.values()):
                output['vault_configuration_' + section] = []
    return output, audit
