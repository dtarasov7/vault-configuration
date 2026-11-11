"""Deterministic planning, ownership checks and preservation of foreign links."""
import copy

from .adapters import ADAPTERS, policies
from .common import ConfigurationError, check, digest, public, sorted_values
from .compiler import compile_grant, compile_personal, policy_name, personal_entries, personal_identifier
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




class Planner:
    """Build an ownership-aware plan without mutating Vault.
    RU: Строить план с учётом владения без изменения Vault.
    """
    def __init__(self, config, sections, view, passwords=None, ldap_passwords=None):
        self.config, self.sections = config, sections
        self.original_view = view
        self.view = copy.deepcopy(view)
        self.ldap_passwords = ldap_passwords or {}
        self.management = config['management']
        self.safety = config['safety']
        self.owner = self.management['owner']
        self.passwords = passwords or {}
        self.models = {}
        self.operations = []
        self.warnings = copy.deepcopy(view.get('warnings', []))
        self.identifiers = {}
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
        """Check live ownership or explicit adoption; no local history is required.
        RU: Проверить владельца в Vault либо явное принятие объекта без локальной истории.

        Args:
            kind (str): Resource type / тип ресурса.
            identifier (str): Inventory ID / ID инвентаря.
            entry (dict | None): Existing API object / существующий объект API.
            shared (bool): Manage links only / управлять только назначениями.
        Returns:
            None.
        Raises:
            ConfigurationError: Ownership, protection or adoption conflict / конфликт владения, защиты или принятия.
        """
        self.protected(kind, identifier, entry)
        if not entry or shared or kind not in {'entity', 'group'}:
            return
        metadata = entry['data'].get('metadata', {})
        owner = metadata.get(OWNER_KEY)
        check(not owner or owner == self.owner, 'Object belongs to another owner')
        if owner == self.owner and metadata.get(ID_KEY) == identifier:
            return
        expected = next((item for item in self.management['adoption']
                         if item['kind'] == kind and item['id'] == identifier), None)
        actual_hash = digest(entry['data'])
        check(expected is not None, 'Explicit adoption required for %s/%s: hash=%s uuid=%s' %
              (kind, identifier, actual_hash, entry.get('uuid', '')))
        check(('hash' in expected and expected['hash'] == actual_hash) or
              ('uuid' in expected and expected['uuid'] == entry.get('uuid')), 'Adoption fingerprint mismatch')

    def add_model(self, kind, identifier, entry, payload, section, links=None, phase=20,
                  shared=False, password=None):
        key = kind + ':' + identifier
        check(key not in self.models, 'Duplicate resource binding')
        self.claim(kind, identifier, entry, shared=shared)
        if entry and entry.get('uuid'):
            self.identifiers[key] = entry['uuid']
        model = {'key': key, 'kind': kind, 'id': identifier, 'entry': entry,
                 'payload': copy.deepcopy(payload), 'section': section, 'links': links or {},
                 'phase': phase, 'shared': shared, 'password': password}
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
        entries = self.view['entities' if kind == 'entity' else 'groups']
        owned = [entry for entry in entries.values()
                 if entry['data'].get('metadata', {}).get(OWNER_KEY) == self.owner
                 and entry['data'].get('metadata', {}).get(ID_KEY) == item['id']]
        check(len(owned) <= 1, 'Duplicate owner/inventory ID metadata in Vault')
        entry = owned[0] if owned else next((entry for entry in entries.values()
                                           if entry['data']['name'] == item['name']), None)
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
        parent = self.identifiers.get(parent_kind + ':' + parent_id)
        matches = [entry for entry in self.view['aliases'].values()
                   if entry['kind'] == kind and entry['data']['name'] == item['name'] and
                   entry['data']['mount_accessor'] == mount_accessor]
        check(len(matches) <= 1, 'Ambiguous existing alias')
        entry = matches[0] if matches else None
        if entry:
            check(parent == entry['data']['canonical_id'], 'Alias belongs to a different identity; moving/merging is prohibited')
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
            # Built-in plugin versions must match this server; external plugins remain unsupported.
            # RU: Версия встроенного плагина должна соответствовать серверу; внешние плагины не поддерживаются.
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
                rotate = not entry or item['password_policy'] == 'always'
                password = item.get('password') or self.passwords.get(item['id'])
                check(not rotate or (isinstance(password, str) and password), 'Required userpass password is missing')
                check(not rotate or len(password.encode('utf-8')) <= 72, 'Userpass bcrypt passwords must not exceed 72 UTF-8 bytes')
                payload = copy.deepcopy(entry['data']) if entry else {}
                payload.update(item['token_parameters'])
                model = self.add_model('userpass', item['id'], entry, payload, 'users', phase=25,
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
        for personal in personal_entries(self.sections.get('personal_access')):
            if not personal['enabled']:
                continue
            identifier = personal_identifier(personal)
            name = policy_name(self.management['policy_prefix'], identifier)
            check('policy:' + identifier not in self.models, 'Personal policy id collides with a grant')
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
            if isinstance(auth_accessor, dict):
                settings = {key: personal[key] for key in ('mount', 'permissions', 'identity_source', 'path_prefix')}
                policy = {'$ldap_personal_policy': {'settings': settings, 'accessor': auth_accessor}}
            else:
                policy = compile_personal(personal, auth_accessor)
            model = self.add_model('policy', identifier, self.view['policies'].get(name),
                                   {'policy': policy}, 'personal_access', phase=10)
            model['path'] = 'sys/policies/acl/' + name
            if auth_accessor is not None:
                model.update(accessor=auth_accessor, auth_mount=personal['auth_mount'])
            for subject in personal['subjects']:
                self.attach(subject, [name])
        # Omitted policy/member sections keep their old managed edges intact.
        # RU: Пропущенные разделы политик и участников сохраняют прежние управляемые связи.
        self.prepare_models()
        self.operations.sort(key=lambda operation: (operation['phase'], operation['key'], operation['action']))
        self.check_membership_cycles()
        plan = {'operations': [public(operation) for operation in self.operations], 'warnings': self.warnings}
        # Hash the full plan so dry/apply share the same approval digest.
        # RU: Хешируем полный план, чтобы dry и apply использовали одну сумму согласования.
        plan['digest'] = digest({'desired': public(self.sections), 'config': public(self.config_for_digest()),
                                 'snapshot': fingerprint(self.original_view), 'plan': plan})
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
        for key in ('mode', 'expected_plan_digest'):
            config.pop(key, None)
        return config

    def prepare_models(self):
        """Reconcile owned policy namespaces and authoritative internal membership.
        RU: Согласовать свои пространства политик и полный состав внутренних групп.

        Returns:
            None: Populates models and operations / заполняет модели и операции.
        Raises:
            ConfigurationError: Protected target or unsupported role / защищённый субъект или неподдерживаемая роль.
        """
        prefix = self.management['policy_prefix']
        personal_name = policy_name(prefix, 'personal')

        def controlled(name):
            if name == personal_name or name.startswith(prefix + 'personal-'):
                return 'personal_access' in self.active_sections
            return name.startswith(prefix) and 'grants' in self.active_sections

        # Find old bindings from Vault itself, including subjects omitted from inventory.
        # RU: Находим прежние назначения в Vault, включая отсутствующих в инвентаре субъектов.
        for kind, index in [('entity', 'entities'), ('group', 'groups'), ('auth_role', 'roles')]:
            for uuid, entry in self.view[index].items():
                assigned = policies(entry['data']) if kind == 'auth_role' else entry['data'].get('policies', [])
                if not any(controlled(name) for name in assigned):
                    continue
                if any(model['entry'] is not None and model['entry']['path'] == entry['path']
                       for model in self.models.values()):
                    continue
                identifier = 'live-' + digest(entry['path'])[:20]
                payload = copy.deepcopy(entry['data'])
                if kind == 'auth_role':
                    payload = ADAPTERS[entry['type']].payload(payload, policies(payload))
                model = self.add_model(kind, identifier, entry, payload, 'grants', shared=True, phase=40)
                if kind == 'auth_role':
                    model.update(role_type=entry['type'], auth_mount=entry['mount'], name=entry['name'])

        for key, model in sorted(self.models.items()):
            entry = model['entry']
            current = entry['data'] if entry else {}
            payload = model['payload']
            desired_links = self.links.get(key, {})
            if model['kind'] in {'entity', 'group', 'auth_role'}:
                field = 'token_policies' if model['kind'] == 'auth_role' else 'policies'
                assigned = policies(current) if field == 'token_policies' else current.get(field, [])
                wanted = desired_links.get('policies', [])
                payload[field] = sorted(set(name for name in assigned if not controlled(name)) | set(wanted))
            for field in ('member_entity_ids', 'member_group_ids'):
                if field in desired_links:
                    payload[field] = desired_links[field]
            model['links'] = desired_links
            try:
                comparable = resolve(payload, self.identifiers)
            except ConfigurationError:
                comparable = payload
            before = current
            if model['kind'] == 'group' and current.get('type') == 'external':
                before = {field: value for field, value in current.items()
                          if field not in {'member_entity_ids', 'member_group_ids'}}
            if model['kind'] == 'auth_role':
                before = ADAPTERS[model['role_type']].payload(current, policies(current))
            if model.get('compare_subset'):
                before = {field: current.get(field) for field in comparable}
            needs_write = comparable != before or bool(model.get('password'))
            model['path'] = entry['path'] if entry else model.get('path', 'identity/' + model['kind'].replace('_', '-'))
            operation = {'key': key, 'kind': model['kind'], 'id': model['id'],
                         'name': payload.get('name', model.get('name', model['id'])),
                         'path': model['path'], 'action': 'create' if not entry else 'update' if needs_write else 'noop',
                         'phase': model['phase'], 'reason': 'object absent' if not entry else 'managed fields differ' if needs_write else 'already converged',
                         'before': public(current), 'after': public(payload)}
            if model.get('password'):
                operation['reason'] = 'credential creation or explicit always password policy'
                operation['password_write'] = True
            self.operations.append(operation)


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
