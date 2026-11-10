"""Deterministic planning, ownership checks and preservation of foreign links."""
import copy

from .adapters import ADAPTERS, policies
from .common import ConfigurationError, check, digest, public, sorted_values
from .compiler import compile_grant, compile_personal, policy_name
from .reader import OWNER_KEY, ID_KEY, accessor, fingerprint


def reference(kind, identifier):
    return {'$ref': kind + ':' + identifier}


def resolve(value, identifiers):
    """Resolve resource references and deferred LDAP policy templates.
    RU: Разрешить ссылки на ресурсы и отложенные шаблоны политик LDAP.

    Args:
        value (object): Nested payload with symbolic references / вложенные данные с символическими ссылками.
        identifiers (dict[str, str]): Resource keys mapped to allocated IDs / выделенные идентификаторы по ключам ресурсов.

    Returns:
        object: Recursively resolved value / рекурсивно разрешённое значение.

    Raises:
        ConfigurationError: Missing resource ID or invalid LDAP accessor / отсутствует ID ресурса либо неверен accessor LDAP.
    """
    if isinstance(value, dict):
        # Wait for the auth accessor before rendering the native Vault template.
        # RU: Рендерим собственный шаблон Vault только после получения accessor аутентификации.
        if set(value) == {'$ldap_personal_policy'}:
            specification = value['$ldap_personal_policy']
            auth_accessor = resolve(specification['accessor'], identifiers)
            return compile_personal(specification['settings'], auth_accessor)
        if set(value) == {'$ref'}:
            check(value['$ref'] in identifiers, 'Unresolved planned identity reference')
            return identifiers[value['$ref']]
        return {key: resolve(item, identifiers) for key, item in value.items()}
    if isinstance(value, list):
        values = [resolve(item, identifiers) for item in value]
        return sorted_values(values)
    return value


def merged_links(current, previous, desired):
    """Replace only relationships owned by this registry.
    RU: Заменить только связи, принадлежащие этому реестру.

    Args:
        current (list): Live relationships / текущие связи.
        previous (list): Previously owned relationships / ранее управляемые связи.
        desired (list): Desired owned relationships / желаемые управляемые связи.

    Returns:
        list: Sorted final relationships / отсортированные итоговые связи.
    """
    return sorted_values((set(current or []) - set(previous or [])) | set(desired))


class Planner:
    """Build an ownership-aware plan without mutating Vault.
    RU: Строить план с учётом владения без изменения Vault.
    """
    def __init__(self, config, sections, view, state, peers=(), passwords=None, ldap_passwords=None):
        self.config, self.sections, self.state = config, sections, state
        self.original_view = view
        self.view = copy.deepcopy(view)
        self.ldap_passwords = ldap_passwords or {}
        self.management = config['management']
        self.safety = config['safety']
        self.owner = self.management['owner']
        self.peers = peers
        self.passwords = passwords or {}
        self.models = {}
        self.operations = []
        self.warnings = []
        self.identifiers = {key: record['uuid'] for key, record in state['resources'].items() if record.get('uuid')}
        self.links = {}
        self.alias_bindings = set()
        self.active_sections = {key for key, value in sections.items() if value is not None}

    def protected(self, kind, identifier, entry):
        if kind == 'policy':
            values = set(self.safety['protected_policies']) | {'root', 'default'}
        elif kind in {'entity', 'group'}:
            values = set(self.safety['protected_entities' if kind == 'entity' else 'protected_groups'])
            if kind == 'entity' and self.view.get('automation_entity'):
                values.add(self.view['automation_entity'])
        else:
            return
        check(identifier not in values and (entry or {}).get('uuid') not in values and
              (entry or {}).get('data', {}).get('name') not in values, 'Protected object cannot be managed')

    def claim(self, kind, identifier, entry, shared=False):
        """Validate ownership, adoption and stable resource identity.
        RU: Проверить владение, принятие под управление и постоянство идентификатора.

        Args:
            kind (str): Resource type / тип ресурса.
            identifier (str): Inventory resource ID / идентификатор ресурса в инвентаре.
            entry (dict | None): Existing snapshot entry / существующий объект снимка.
            shared (bool): Manage owned links on a shared object / управлять своими связями общего объекта.

        Returns:
            dict | None: Previous registry record / предыдущая запись реестра.

        Raises:
            ConfigurationError: Protection, ownership, adoption or migration conflict / конфликт защиты, владения, принятия под управление или миграции.
        """
        key = kind + ':' + identifier
        previous = self.state['resources'].get(key)
        self.protected(kind, identifier, entry)
        if entry:
            current_owner = entry['data'].get('metadata', {}).get(OWNER_KEY)
            check(shared or not current_owner or current_owner == self.owner, 'Object belongs to another owner')
            if previous:
                check(not previous.get('uuid') or previous['uuid'] == entry.get('uuid'), 'Managed UUID changed; migration required')
                check(previous['path'] == entry['path'], 'Managed object address changed; explicit migration required')
            elif not shared and not (kind == 'ldap_config' and entry.get('initial_configuration')):
                expected = next((item for item in self.management['adoption']
                                 if item['kind'] == kind and item['id'] == identifier), None)
                actual_hash = digest(entry['data'])
                check(expected is not None,
                      'Explicit adoption required for %s/%s: hash=%s uuid=%s' %
                      (kind, identifier, actual_hash, entry.get('uuid', '')))
                check(('hash' in expected and expected['hash'] == actual_hash) or
                      ('uuid' in expected and expected['uuid'] == entry.get('uuid')), 'Adoption fingerprint mismatch')
        elif previous and previous.get('uuid'):
            check(False, 'Managed identity disappeared; explicit registry recovery is required')
        for peer in self.peers:
            for record in peer['resources'].values():
                if entry and record['path'] == entry['path']:
                    check(shared and record.get('shared'), 'Object claimed in another owner registry')
        return previous

    def add_model(self, kind, identifier, entry, payload, section, links=None, phase=20,
                  shared=False, revision=None, password=None):
        key = kind + ':' + identifier
        check(key not in self.models, 'Duplicate resource binding')
        previous = self.claim(kind, identifier, entry, shared=shared)
        if kind == 'policy' and previous:
            expected_path = 'sys/policies/acl/' + policy_name(self.management['policy_prefix'], identifier)
            check(previous['path'] == expected_path, 'Policy prefix/name changed; explicit migration required')
        if entry and entry.get('uuid'):
            self.identifiers[key] = entry['uuid']
        model = {'key': key, 'kind': kind, 'id': identifier, 'entry': entry,
                 'payload': copy.deepcopy(payload), 'section': section, 'links': links or {},
                 'phase': phase, 'shared': shared, 'previous': previous,
                 'password_revision': revision, 'password': password}
        if kind == 'group' and model['payload'].get('type') == 'external':
            # Membership of existing external UUID subjects is maintained by the auth method.
            # RU: Членством существующих внешних групп по UUID управляет метод аутентификации.
            model['payload'].pop('member_entity_ids', None)
            model['payload'].pop('member_group_ids', None)
        self.models[key] = model
        return model

    def identity(self, kind, item):
        """Add an entity or group model while preserving foreign fields.
        RU: Добавить модель сущности или группы с сохранением чужих полей.

        Args:
            kind (str): Resource type / тип ресурса.
            item (dict): Validated desired identity / проверенная желаемая сущность.

        Returns:
            dict: Registered resource model / зарегистрированная модель ресурса.

        Raises:
            ConfigurationError: Identity collision or ownership conflict / коллизия идентификатора или конфликт владения.
        """
        key = kind + ':' + item['id']
        previous = self.state['resources'].get(key)
        entries = self.view['entities' if kind == 'entity' else 'groups']
        if previous and previous.get('uuid'):
            entry = entries.get(previous['uuid'])
        else:
            entry = next((entry for entry in entries.values() if entry['data']['name'] == item['name']), None)
        # Prevent rename from colliding with another object even when UUID is stable.
        # RU: Переименование не должно конфликтовать с другим объектом даже при неизменном UUID.
        check(not any(other['data']['name'] == item['name'] and other is not entry for other in entries.values()),
              'Identity name collides with another UUID')
        payload = copy.deepcopy(entry['data']) if entry else {'policies': []}
        payload['name'] = item['name']
        metadata = payload.setdefault('metadata', {})
        metadata[OWNER_KEY], metadata[ID_KEY] = self.owner, item['id']
        if kind == 'entity':
            payload['disabled'] = item['disabled']
        else:
            check(not entry or entry['data']['type'] == item['type'], 'Identity group type migration is prohibited')
            payload['type'] = item['type']
            if item['type'] == 'external':
                payload.pop('member_entity_ids', None)
                payload.pop('member_group_ids', None)
            if item['type'] == 'internal':
                payload.setdefault('member_entity_ids', [])
                payload.setdefault('member_group_ids', [])
        model = self.add_model(kind, item['id'], entry, payload, 'users' if kind == 'entity' else 'groups')
        return model

    def alias_model(self, kind, parent_id, item, ordinal):
        """Plan an alias bound to a stable canonical identity.
        RU: Запланировать алиас, связанный с постоянной канонической сущностью.

        Args:
            kind (str): Resource type / тип ресурса.
            parent_id (str): Canonical inventory identity ID / ID канонической сущности в инвентаре.
            item (dict): Validated alias settings / проверенные настройки алиаса.
            ordinal (int): Alias index within the identity / номер алиаса внутри сущности.

        Returns:
            None.

        Raises:
            ConfigurationError: Alias move, merge or accessor mismatch / перенос, слияние алиаса или несовпадение accessor.
        """
        item = copy.deepcopy(item)
        mount = item['auth_mount']
        if kind == 'group_alias' and self.view['auth'].get(mount + '/', {}).get('type') == 'ldap':
            configuration = self.view['objects'].get('auth/' + mount + '/config', {})
            for model in self.models.values():
                if model['kind'] == 'ldap_config' and model['auth_mount'] == mount:
                    configuration = model['payload']
            if not configuration.get('case_sensitive_names', False):
                item['name'] = item['name'].lower()
        binding = (kind, mount, item['name'])
        check(binding not in self.alias_bindings, 'Duplicate alias after LDAP name normalization')
        self.alias_bindings.add(binding)
        mount_accessor = accessor(self.view, item['auth_mount'])
        parent_kind = 'entity' if kind == 'entity_alias' else 'group'
        identifier = parent_id + '/' + str(ordinal)
        previous = self.state['resources'].get(kind + ':' + identifier)
        if previous:
            check(previous.get('accessor') == mount_accessor, 'Auth accessor changed; explicit alias migration required')
        parent = self.identifiers.get(parent_kind + ':' + parent_id)
        matches = [entry for entry in self.view['aliases'].values()
                   if entry['kind'] == kind and entry['data']['name'] == item['name'] and
                   entry['data']['mount_accessor'] == mount_accessor]
        check(len(matches) <= 1, 'Ambiguous existing alias')
        entry = matches[0] if matches else None
        if entry:
            check(parent == entry['data']['canonical_id'], 'Alias belongs to a different identity; moving/merging is prohibited')
        if previous and previous.get('uuid'):
            existing = self.view['aliases'].get(previous['uuid'])
            check(existing is not None and (not entry or entry['uuid'] == existing['uuid']), 'Alias identity changed')
            entry = existing
            check(entry['data']['canonical_id'] == parent, 'Managed alias canonical identity changed')
        payload = copy.deepcopy(entry['data']) if entry else {}
        payload.update(name=item['name'], mount_accessor=mount_accessor, canonical_id=reference(parent_kind, parent_id))
        model = self.add_model(kind, identifier, entry, payload,
                               'users' if parent_kind == 'entity' else 'groups', phase=30)
        model['accessor'] = mount_accessor
        model['auth_mount'] = item['auth_mount']

    def subject_key(self, subject):
        kind = {'user': 'entity', 'group': 'group', 'auth_role': 'auth_role'}[subject['kind']]
        if 'id' in subject:
            return kind + ':' + subject['id']
        uuid = subject['uuid']
        key = kind + ':uuid-' + uuid
        if key not in self.models:
            entry = self.view['entities' if kind == 'entity' else 'groups'].get(uuid)
            check(entry is not None, 'Referenced external UUID does not exist')
            self.add_model(kind, 'uuid-' + uuid, entry, entry['data'], 'grants', shared=True)
        return key

    def attach(self, subject, names):
        key = self.subject_key(subject)
        self.links.setdefault(key, {}).setdefault('policies', set()).update(names)

    def build(self):
        """Build and validate the complete ordered reconciliation plan.
        RU: Построить и проверить полный упорядоченный план согласования.

        Returns:
            dict: Operations, digest and warnings / операции, контрольная сумма и предупреждения.

        Raises:
            ConfigurationError: Unsafe changes, stale digest or unresolved configuration / небезопасные изменения, устаревшая сумма или неразрешимая конфигурация.
        """
        from .ldap import plan_infrastructure
        plan_infrastructure(self, self.ldap_passwords)
        for item in sorted(self.sections.get('users') or [], key=lambda item: item['id']):
            self.identity('entity', item)
        for item in sorted(self.sections.get('groups') or [], key=lambda item: item['id']):
            self.identity('group', item)
        for item in sorted(self.sections.get('auth_roles') or [], key=lambda item: item['id']):
            accessor(self.view, item['auth_mount'], item['type'])
            entry = self.view['roles'].get(item['auth_mount'] + '/' + item['name'])
            check(entry is not None, 'Auth role does not exist; creating roles is prohibited')
            # Exact built-in plugin versions are gated by the server profile. External plugins are rejected.
            details = self.view['auth'][item['auth_mount'] + '/']
            plugin_version = details.get('running_plugin_version', '')
            check(not plugin_version or plugin_version.startswith('v' + self.view['version'] + '+builtin'),
                  'Unsupported external auth plugin version')
            payload = ADAPTERS[item['type']].payload(entry['data'], policies(entry['data']))
            model = self.add_model('auth_role', item['id'], entry, payload, 'auth_roles', phase=40, shared=True)
            model['role_type'] = item['type']
            model['auth_mount'] = item['auth_mount']
            model['name'] = item['name']
        for item in sorted(self.sections.get('users') or [], key=lambda item: item['id']):
            aliases = list(item['aliases'])
            if item['source'] == 'userpass':
                mount_accessor = accessor(self.view, item['auth_mount'], 'userpass')
                aliases.insert(0, {'auth_mount': item['auth_mount'], 'name': item['login']})
                entry = self.view['userpass'].get(item['auth_mount'] + '/' + item['login'])
                old = self.state['resources'].get('userpass:' + item['id'], {})
                if old:
                    check(old['path'] == 'auth/' + item['auth_mount'] + '/users/' + item['login'],
                          'Userpass login/mount changed; explicit migration required')
                    check(old.get('accessor') == mount_accessor, 'Userpass auth accessor changed; migration required')
                rotate = not entry or (item['password_policy'] == 'on_revision' and
                                       old.get('password_revision') != item['password_revision'])
                password = item.get('password') or self.passwords.get(item['id'])
                check(not rotate or (isinstance(password, str) and password), 'Required userpass password is missing')
                check(not rotate or len(password.encode('utf-8')) <= 72, 'Userpass bcrypt passwords must not exceed 72 UTF-8 bytes')
                payload = copy.deepcopy(entry['data']) if entry else {}
                payload.update(item['token_parameters'])
                model = self.add_model('userpass', item['id'], entry, payload, 'users', phase=25,
                                       revision=item['password_revision'] if rotate else old.get('password_revision'),
                                       password=password if rotate else None)
                model['path'] = 'auth/' + item['auth_mount'] + '/users/' + item['login']
                model['accessor'] = mount_accessor
                model['auth_mount'], model['login'] = item['auth_mount'], item['login']
                model['password_policy'] = item['password_policy']
            seen = set()
            for ordinal, entry in enumerate(aliases):
                identity = (entry['auth_mount'], entry['name'])
                check(identity not in seen, 'Duplicate user alias')
                seen.add(identity)
                self.alias_model('entity_alias', item['id'], entry, ordinal)
        for item in self.sections.get('groups') or []:
            if 'alias' in item:
                self.alias_model('group_alias', item['id'], item['alias'], 0)
            if item['type'] == 'internal':
                key = 'group:' + item['id']
                links = self.links.setdefault(key, {})
                for field, members, kind in [('member_entity_ids', item['members'], 'entity'),
                                              ('member_group_ids', item['member_groups'], 'group')]:
                    links[field] = []
                    for member in members:
                        if isinstance(member, str):
                            links[field].append(reference(kind, member))
                        else:
                            check(member['uuid'] in self.view['entities' if kind == 'entity' else 'groups'],
                                  'External membership UUID does not exist')
                            links[field].append(member['uuid'])
        for grant in sorted(self.sections.get('grants') or [], key=lambda grant: grant['id']):
            if 'paths' in grant:
                name = policy_name(self.management['policy_prefix'], grant['id'])
                self.add_model('policy', grant['id'], self.view['policies'].get(name),
                               {'policy': compile_grant(grant)}, 'grants', phase=10)['path'] = 'sys/policies/acl/' + name
                names = [name]
                for entry in grant.get('discovery_paths', []):
                    self.warnings.append({'kind': 'discovery', 'grant': grant['id'], **entry,
                                          'reason': 'LIST reveals all immediate child names, including inaccessible secrets'})
            else:
                names = grant['existing_policies']
                check(all(name in self.view['policies'] for name in names), 'Existing ACL policy is missing')
            for subject in grant['subjects']:
                self.attach(subject, names)
        personal = self.sections.get('personal_access')
        if personal and personal['enabled']:
            name = policy_name(self.management['policy_prefix'], 'personal')
            check('policy:personal' not in self.models, 'Grant id personal is reserved when personal access is enabled')
            auth_accessor = None
            if personal['identity_source'] == 'ldap_login':
                mount = personal['auth_mount']
                auth_accessor = accessor(self.view, mount, 'ldap')
                configuration = self.view['objects'].get('auth/' + mount + '/config', {})
                for model in self.models.values():
                    if model['kind'] == 'ldap_config' and model['auth_mount'] == mount:
                        configuration = model['payload']
                check(configuration.get('username_as_alias') is True,
                      'LDAP personal access requires username_as_alias=true')
                details = self.view['auth'][mount + '/']
                version = details.get('running_plugin_version', '')
                check(not version or version.startswith('v' + self.view['version'] + '+builtin'),
                      'Unsupported external LDAP plugin version')
                previous = self.state['resources'].get('policy:personal', {})
                check(not previous.get('accessor') or
                      (previous['accessor'] == auth_accessor and previous.get('auth_mount') == mount),
                      'LDAP personal auth accessor changed; explicit migration required')
            if isinstance(auth_accessor, dict):
                settings = {key: personal[key] for key in ('mount', 'permissions', 'identity_source', 'path_prefix')}
                policy = {'$ldap_personal_policy': {'settings': settings, 'accessor': auth_accessor}}
            else:
                policy = compile_personal(personal, auth_accessor)
            model = self.add_model('policy', 'personal', self.view['policies'].get(name),
                                   {'policy': policy}, 'personal_access', phase=10)
            model['path'] = 'sys/policies/acl/' + name
            if auth_accessor is not None:
                model.update(accessor=auth_accessor, auth_mount=personal['auth_mount'])
            for subject in personal['subjects']:
                self.attach(subject, [name])
        # Omitted policy/member sections keep their old managed edges intact.
        # RU: Пропущенные разделы политик и участников сохраняют прежние управляемые связи.
        self.prepare_models()
        self.prune()
        self.operations.sort(key=lambda operation: (operation['phase'], operation['key'], operation['action']))
        deletes = [operation for operation in self.operations if operation['action'] == 'delete']
        check(len(deletes) <= self.safety['max_deletions'], 'Deletion limit exceeded')
        self.check_membership_cycles()
        plan = {'operations': [public(operation) for operation in self.operations], 'warnings': self.warnings}
        # Hash the full plan so dry/apply share the same approval digest.
        # RU: Хешируем полный план, чтобы dry и apply использовали одну сумму согласования.
        plan['digest'] = digest({'desired': public(self.sections), 'config': public(self.config_for_digest()),
                                 'snapshot': fingerprint(self.original_view), 'plan': plan,
                                 'resources': self.state['resources']})
        expected = self.config.get('expected_plan_digest')
        check(not expected or expected == plan['digest'], 'Saved plan is stale; review a new plan')
        return plan

    def config_for_digest(self):
        """Exclude execution-only settings from the desired-state digest.
        RU: Исключить параметры выполнения из суммы желаемого состояния.

        Returns:
            dict: Digest input shared by dry and apply / данные для суммы, общие для dry и apply.
        """
        config = copy.deepcopy(self.config)
        for key in ('mode', 'report_destination', 'expected_plan_digest'):
            config.pop(key, None)
        return config

    def prepare_models(self):
        """Merge owned links and classify create, update and noop operations.
        RU: Объединить свои связи и определить операции create, update и noop.

        Returns:
            None: Populates planned operations / заполняет планируемые операции.

        Raises:
            ConfigurationError: Unsafe or inconsistent model / небезопасная или несогласованная модель.
        """
        for key, model in sorted(self.models.items()):
            previous = model['previous'] or {}
            entry = model['entry']
            current = entry['data'] if entry else {}
            desired_links = self.links.get(key, {})
            old_links = previous.get('links', {})
            fields = set(desired_links) | set(old_links)
            links = {}
            payload = model['payload']
            for field in fields:
                # Existing policy links belong to grants/personal scopes, not the user/group declaration.
                # RU: Связями политик управляют разделы grants/personal, а не объявление пользователя или группы.
                if field == 'policies':
                    managed_sections = previous.get('policy_links', {})
                    kept = set()
                    for section, names in managed_sections.items():
                        if section not in self.active_sections:
                            kept.update(names)
                    desired = list(desired_links.get(field, [])) + list(kept)
                    if not managed_sections and not ({'grants', 'personal_access'} & self.active_sections):
                        desired += old_links.get(field, [])
                else:
                    desired = desired_links.get(field, old_links.get(field, []))
                # Symbolic UUIDs cannot be put in sets yet.
                # RU: Символические UUID пока нельзя помещать в множества.
                resolved = [self.identifiers.get(value['$ref'], value) if isinstance(value, dict) else value for value in desired]
                desired = sorted({digest(value): value for value in resolved}.values(), key=lambda value: str(value))
                api_field = 'token_policies' if model['kind'] == 'auth_role' and field == 'policies' else field
                current_values = policies(current) if api_field == 'token_policies' else current.get(api_field, [])
                old = set(old_links.get(field, []))
                foreign = set(current_values or []) - old
                # Pre-existing foreign bindings are preserved and never silently claimed.
                # RU: Существующие чужие привязки сохраняются без неявного принятия под управление.
                for peer in self.peers:
                    for record in peer['resources'].values():
                        if entry and record['path'] == entry['path']:
                            overlap = {value for value in desired if isinstance(value, str)} & set(record['links'].get(field, []))
                            check(not overlap, 'Managed relationship is claimed by another owner')
                links[field] = [value for value in desired if not isinstance(value, str) or value not in foreign or value in old]
                payload[api_field] = sorted(foreign, key=str) + links[field]
                payload[api_field] = sorted({digest(value): value for value in payload[api_field]}.values(), key=str)
            model['links'] = links
            # Keep per-section policy provenance to distinguish omitted and empty sections.
            # RU: Храним раздел-источник политики, чтобы различать пропущенный и пустой разделы.
            policy_links = copy.deepcopy(previous.get('policy_links', {}))
            for section in ('grants', 'personal_access'):
                if section in self.active_sections:
                    names = set()
                    if section == 'grants':
                        for grant in self.sections.get('grants') or []:
                            if any(self.subject_key(subject) == key for subject in grant['subjects']):
                                names.update(grant.get('existing_policies', [policy_name(self.management['policy_prefix'], grant['id'])]))
                    elif self.sections.get('personal_access', {}).get('enabled'):
                        if any(self.subject_key(subject) == key for subject in self.sections['personal_access']['subjects']):
                            names.add(policy_name(self.management['policy_prefix'], 'personal'))
                    policy_links[section] = sorted(names & set(value for value in links.get('policies', []) if isinstance(value, str)))
            model['policy_links'] = policy_links
            try:
                comparable = resolve(payload, self.identifiers)
            except ConfigurationError:
                # References to identities created in this plan resolve during execution.
                # RU: Ссылки на создаваемые сущности разрешаются при выполнении плана.
                comparable = payload
            # Full role payload excludes deprecated fields; compare via its own adapter.
            before = current
            if model['kind'] == 'group' and current.get('type') == 'external':
                before = {field: value for field, value in current.items() if field not in {'member_entity_ids', 'member_group_ids'}}
            if model['kind'] == 'auth_role':
                before = ADAPTERS[model['role_type']].payload(current, policies(current))
            if model.get('compare_subset'):
                before = {field: current.get(field) for field in comparable}
            needs_write = comparable != before or bool(model.get('password'))
            path = entry['path'] if entry else model.get('path', 'identity/' + model['kind'].replace('_', '-') )
            model['path'] = path
            operation = {'key': key, 'kind': model['kind'], 'id': model['id'], 'name': payload.get('name', model.get('name', model['id'])),
                         'path': path, 'action': 'create' if not entry else 'update' if needs_write else 'noop',
                         'phase': model['phase'], 'reason': 'object absent' if not entry else 'managed fields differ' if needs_write else 'already converged',
                         'before': public(current), 'after': public(payload)}
            if model.get('password'):
                operation['password_revision'] = model['password_revision']
                operation['reason'] = ('LDAP bind credential creation or explicit revision' if model.get('secret_field') == 'bindpass'
                                       else 'create account or explicit password revision')
            self.operations.append(operation)
        # Relationships on previously managed targets omitted from users/groups still need detach.
        # RU: Связи ранее управляемых объектов требуют отсоединения даже при их отсутствии в users/groups.
        if {'grants', 'personal_access'} & self.active_sections:
            for key, record in sorted(self.state['resources'].items()):
                if key in self.models or not record.get('policy_links'):
                    continue
                entry_data = self.view['objects'].get(record['path'])
                if entry_data is None:
                    continue
                remove = set()
                keep = set()
                for section, names in record['policy_links'].items():
                    (remove if section in self.active_sections else keep).update(names)
                remove -= keep
                if not remove:
                    continue
                payload = copy.deepcopy(entry_data)
                api_field = 'token_policies' if record['kind'] == 'auth_role' else 'policies'
                payload[api_field] = sorted(set(policies(entry_data) if api_field == 'token_policies' else entry_data.get('policies', [])) - remove)
                if record['kind'] == 'auth_role':
                    payload = ADAPTERS[record['role_type']].payload(entry_data, payload[api_field])
                entry = {'path': record['path'], 'data': entry_data, 'uuid': record.get('uuid', '')}
                model = self.add_model(record['kind'], record['id'], entry, payload, record['section'], phase=40,
                                       shared=record.get('shared', False))
                model['path'] = record['path']
                model['detach_only'] = True
                model['links'] = copy.deepcopy(record['links'])
                model['links']['policies'] = sorted(set(record['links'].get('policies', [])) - remove)
                model['policy_links'] = {section: names for section, names in record['policy_links'].items()
                                         if section not in self.active_sections}
                for field in ('role_type', 'auth_mount', 'name', 'accessor'):
                    if field in record:
                        model[field] = record[field]
                self.operations.append({'key': key, 'kind': record['kind'], 'id': record['id'], 'name': record['id'],
                                        'path': record['path'], 'action': 'detach', 'phase': 40,
                                        'reason': 'remove only previously owned policy links',
                                        'before': public(entry_data), 'after': public(model['payload'])})

    def prune(self):
        """Plan approved removals only within explicitly managed sections.
        RU: Запланировать разрешённые удаления только в явно управляемых разделах.

        Returns:
            None: Adds detach, delete or forget operations / добавляет операции detach, delete или forget.

        Raises:
            ConfigurationError: Unapproved deletion or dependency conflict / несогласованное удаление или конфликт зависимостей.
        """
        if not self.management['prune']:
            return
        for key, record in sorted(self.state['resources'].items()):
            desired_ids = {item['id'] for item in self.sections.get(record['section']) or []} if record['section'] in {'users', 'groups', 'auth_roles', 'grants'} else set()
            if record['section'] not in self.active_sections:
                continue
            model = self.models.get(key)
            if model is not None and not (model.get('detach_only') and record['id'] not in desired_ids):
                continue
            if record['kind'] in {'auth_role', 'mount', 'auth_mount', 'ldap_config'} or record.get('shared'):
                # Existing roles/external UUID references are never deleted.
                # RU: Существующие роли и внешние объекты по UUID никогда не удаляются.
                continue
            if record['kind'] != 'policy' and not self.management['prune_identities']:
                continue
            data = self.view['objects'].get(record['path'])
            if data is None:
                self.operations.append({'key': key, 'kind': record['kind'], 'id': record['id'], 'name': record['id'],
                                        'path': record['path'], 'action': 'forget', 'phase': 99,
                                        'reason': 'owned object already absent', 'before': {}, 'after': {}})
                continue
            entry = {'data': data, 'uuid': record.get('uuid')}
            self.protected(record['kind'], record['id'], entry)
            check(not data.get('metadata', {}).get(OWNER_KEY) or data['metadata'][OWNER_KEY] == self.owner,
                  'Prune object belongs to another owner')
            if record['kind'] in {'policy', 'entity', 'group'}:
                approval = next((item for item in self.management['deletion_approvals']
                                 if item['kind'] == record['kind'] and item['id'] == record['id']), None)
                check(approval and approval['hash'] == digest(data),
                      'Deletion requires current hash and explicit external-dependency clearance for ' + key)
            self.operations.append({'key': key, 'kind': record['kind'], 'id': record['id'], 'name': data.get('name', record['id']),
                                    'path': record['path'], 'action': 'delete',
                                    'phase': 70 if record['kind'].endswith('_alias') else 80 if record['kind'] == 'userpass' else 90,
                                    'reason': 'owned object absent from an explicitly managed section',
                                    'before': public(data), 'after': {}})
        deleted = {operation['path'] for operation in self.operations if operation['action'] == 'delete'}
        final = copy.deepcopy(self.view['objects'])
        for operation in self.operations:
            if operation['action'] in {'update', 'detach', 'create'}:
                final[operation['path']] = operation['after']
        for operation in self.operations:
            if operation['action'] != 'delete':
                continue
            kind = operation['kind']
            record = self.state['resources'][operation['key']]
            for api, data in final.items():
                if api in deleted:
                    continue
                if kind == 'policy':
                    name = operation['path'].rsplit('/', 1)[-1]
                    check(name not in data.get('policies', []) and name not in data.get('token_policies', []),
                          'Policy still has external bindings; remove them before prune')
                elif kind in {'entity', 'group'}:
                    uuid = record['uuid']
                    field = 'member_entity_ids' if kind == 'entity' else 'member_group_ids'
                    check(uuid not in data.get(field, []) and data.get('canonical_id') != uuid,
                          'Identity still has external membership or aliases')

    def check_membership_cycles(self):
        """Reject cycles across final managed and foreign group links.
        RU: Отклонить циклы итоговых управляемых и чужих связей групп.

        Returns:
            None.

        Raises:
            ConfigurationError: Group membership contains a cycle / членство групп содержит цикл.
        """
        edges = {uuid: set(entry['data'].get('member_group_ids', [])) for uuid, entry in self.view['groups'].items()}
        for model in self.models.values():
            if model['kind'] != 'group':
                continue
            uuid = self.identifiers.get(model['key'], model['key'])
            members = model['payload'].get('member_group_ids', [])
            edges[uuid] = {self.identifiers.get(value['$ref'], value['$ref']) if isinstance(value, dict) else value for value in members}
        def visit(node, active, done):
            check(node not in active, 'Effective membership including foreign links contains a cycle')
            if node in done:
                return
            active.add(node)
            for child in edges.get(node, []):
                visit(child, active, done)
            active.remove(node)
            done.add(node)
        done = set()
        for node in edges:
            visit(node, set(), done)
