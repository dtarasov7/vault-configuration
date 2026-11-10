"""Serialized application with drift checks and a durable per-write recovery journal."""
import copy

from .adapters import identity_fields, alias_fields, ADAPTERS, policies, TOKEN
from .common import ConfigurationError, check, digest
from .planner import resolve
from .ldap import ldap_fields, initial_ldap_config
from .reader import fingerprint, snapshot


class PartialApply(ConfigurationError):
    """Report confirmed writes and an uncertain pending outcome.
    RU: Сообщить подтверждённые записи и неопределённый исход операции.
    """
    def __init__(self, message, confirmed, uncertain):
        super().__init__(message)
        self.confirmed = confirmed
        self.uncertain = uncertain


def projected(kind, data):
    """Keep only comparable fields for a resource kind.
    RU: Оставить только сравниваемые поля данного типа ресурса.

    Args:
        kind (str): Resource type / тип ресурса.
        data (dict | None): API object data / данные объекта API.

    Returns:
        dict | None: Comparable API representation / сравниваемое представление API.
    """
    if data is None:
        return None
    if kind == 'ldap_config':
        return ldap_fields(data)
    if kind == 'mount':
        return {'type': data['type'], 'options': data.get('options') or {}}
    if kind == 'auth_mount':
        return {'type': data['type']}
    if kind in {'entity', 'group'}:
        return identity_fields(kind, data)
    if kind.endswith('_alias'):
        return alias_fields(data)
    if kind == 'policy':
        return {'policy': data['policy']}
    if kind == 'userpass':
        result = {key: value for key, value in data.items() if key in TOKEN or (key == 'alias_metadata' and value)}
        result['token_policies'] = policies(result)
        return result
    return data


def read_object(client, kind, api_path):
    """Read a resource and normalize its comparable fields.
    RU: Прочитать ресурс и нормализовать его сравниваемые поля.

    Args:
        client (Client): Authenticated API client / аутентифицированный клиент API.
        kind (str): Resource type / тип ресурса.
        api_path (str): API path without /v1/ / путь API без /v1/.

    Returns:
        dict | None: Current fields, or None when absent / текущие поля либо None при отсутствии.

    Raises:
        VaultHTTPError: API read failed / ошибка чтения API.
    """
    if kind in {'mount', 'auth_mount'}:
        root = 'sys/mounts' if kind == 'mount' else 'sys/auth'
        mount = api_path[len(root) + 1:]
        data = client.read(root).get(mount + '/')
    else:
        data = client.read(api_path, missing=True)
    return projected(kind, data)


def record_for(model, identifiers, data, path, links=True):
    """Build a registry record without storing plaintext passwords.
    RU: Сформировать запись реестра без сохранения открытых паролей.

    Args:
        model (dict): Planned resource model / модель планируемого ресурса.
        identifiers (dict[str, str]): Resource keys mapped to allocated IDs / выделенные идентификаторы по ключам ресурсов.
        data (dict | None): API object data / данные объекта API.
        path (str): Actual resource API path / фактический путь ресурса API.
        links (bool): Include resolved relationships / включать разрешённые связи.

    Returns:
        dict: Resource identity, hash and owned links / идентификатор ресурса, хеш и свои связи.
    """
    record = {'kind': model['kind'], 'id': model['id'], 'path': path,
              'uuid': identifiers.get(model['key'], ''), 'hash': digest(data),
              'links': resolve(model['links'], identifiers) if links else {},
              'section': model['section'], 'shared': model['shared'],
              'policy_links': copy.deepcopy(model.get('policy_links', {})) if links else {}}
    for key in ('accessor', 'auth_mount', 'role_type', 'name', 'login', 'password_policy'):
        if key in model:
            record[key] = resolve(model[key], identifiers)
    if model.get('password_revision') is not None:
        record['password_revision'] = model['password_revision']
    return record


def preflight(client, operations):
    """Check token mutation capabilities before applying a plan.
    RU: Проверить права токена на изменения перед применением плана.

    Args:
        client (Client): Authenticated API client / аутентифицированный клиент API.
        operations (list[dict]): Planned operations / планируемые операции.

    Returns:
        None.

    Raises:
        ConfigurationError: Required capabilities are missing / отсутствуют необходимые capabilities.
        VaultHTTPError: Capability lookup failed / ошибка проверки capabilities.
    """
    paths = sorted(set(operation['path'] for operation in operations
                       if operation['action'] not in {'noop', 'forget'}))
    if not paths:
        return
    response = client.request('POST', 'sys/capabilities-self', {'paths': paths})
    capabilities = response.get('data', response)
    for operation in operations:
        if operation['action'] in {'noop', 'forget'}:
            continue
        allowed = capabilities.get(operation['path'], capabilities.get('capabilities', []))
        need = 'delete' if operation['action'] == 'delete' else 'update'
        check('root' in allowed or (need in allowed and 'deny' not in allowed),
              'Automation token lacks required mutation capabilities')
        if operation['path'].startswith(('sys/mounts/', 'sys/auth/')):
            check('root' in allowed or 'sudo' in allowed, 'Mount creation requires sudo capability')


def recover(state, view, config, store, readonly=False):
    """Validate an explicit recovery decision against the live snapshot.
    RU: Проверить явное решение о восстановлении по текущему снимку.

    Args:
        state (dict): Owner registry and pending journal / реестр владельца и журнал незавершённой операции.
        view (dict): Vault snapshot / снимок состояния Vault.
        config (dict): Role configuration / настройки роли.
        store (StateStore): Registry storage / хранилище реестра.
        readonly (bool): Validate recovery without saving / проверять восстановление без сохранения.

    Returns:
        bool: A pending journal entry was handled / обработана незавершённая запись журнала.

    Raises:
        ConfigurationError: Missing decision, digest mismatch or ambiguous outcome / отсутствует решение, не совпадает сумма или исход неоднозначен.
        OSError: Registry save failed / ошибка сохранения реестра.
    """
    pending = state['pending']
    if not pending:
        return False
    decision = config['management']['recovery']
    check(decision and decision['digest'] == pending['digest'],
          'Unfinished operation requires explicit recovery decision; digest=' + pending['digest'])
    record = copy.deepcopy(pending['record'])
    entry = None
    if record['kind'] in {'entity', 'group'} and not record['uuid']:
        entries = view['entities' if record['kind'] == 'entity' else 'groups']
        entry = next((entry for entry in entries.values()
                      if entry['data']['name'] == pending['desired'].get('name')), None)
    elif record['kind'].endswith('_alias') and not record['uuid']:
        entry = next((entry for entry in view['aliases'].values()
                      if entry['kind'] == record['kind'] and entry['data'] == pending['desired']), None)
    else:
        data = view['objects'].get(record['path'])
        if data is not None:
            entry = {'data': data, 'path': record['path'], 'uuid': record['uuid']}
    if decision['outcome'] == 'applied':
        if pending['action'] == 'delete':
            check(entry is None, 'Recovery says deleted but object still exists')
            state['resources'].pop(pending['key'], None)
        else:
            check(entry is not None, 'Recovery says applied but object is absent')
            expected = pending['desired']
            # Userpass defaults and role deprecated fields may be added by the server.
            # RU: Сервер может добавить значения userpass по умолчанию и устаревшие поля роли.
            check(all(entry['data'].get(key) == value for key, value in expected.items()),
                  'Recovery result does not match the recorded write intent')
            record.update(path=entry['path'], uuid=entry.get('uuid', ''), hash=digest(entry['data']))
            if record['kind'] == 'auth_mount':
                record['uuid'] = view['auth'][record['id'] + '/']['accessor']
            state['resources'][pending['key']] = record
    else:
        before = pending['before']
        check((entry['data'] if entry else None) == before, 'Cannot retry: API no longer matches the pre-write state')
        check(not pending.get('password_write'),
              'A password outcome cannot be verified from reads; resolve it as applied or rotate explicitly after operator reconciliation')
    state['journal'].append({'key': pending['key'], 'action': 'recovery-' + decision['outcome'], 'digest': pending['digest']})
    state['pending'] = None
    if not readonly:
        store.save(state)
    return True


class Executor:
    """Apply ordered mutations with drift checks and journaling.
    RU: Применять изменения по порядку с проверкой дрейфа и журналированием.
    """
    def __init__(self, client, config, planner, store, state):
        self.client, self.config, self.planner, self.store, self.state = client, config, planner, store, state
        self.identifiers = dict(planner.identifiers)
        self.confirmed = []
        self.expected = copy.deepcopy(planner.view['objects'])

    def execute(self, plan):
        """Apply the plan and persist confirmed outcomes after each write.
        RU: Применить план и сохранять подтверждённый результат каждой записи.

        Args:
            plan (dict): Ordered operations and digest / упорядоченные операции и контрольная сумма.

        Returns:
            dict: Change flag and confirmed operation report / признак изменений и отчёт подтверждённых операций.

        Raises:
            ConfigurationError: Drift or capability check failed before execution / дрейф или ошибка проверки прав до выполнения.
            PartialApply: Execution failed after starting the plan / ошибка после начала выполнения плана.
        """
        fresh = snapshot(self.client, self.config)
        check(fingerprint(fresh) == fingerprint(self.planner.original_view), 'Vault drifted after planning; no writes were attempted')
        preflight(self.client, plan['operations'])
        deferred = []
        initial_state = copy.deepcopy(self.state)
        try:
            deferred_done = False
            for operation in plan['operations']:
                if operation['phase'] >= 40 and not deferred_done:
                    self.attach_deferred(deferred)
                    deferred_done = True
                action = operation['action']
                key = operation['key']
                if action == 'forget':
                    self.state['resources'].pop(key, None)
                    continue
                if action == 'delete':
                    self.remove(operation)
                    continue
                model = self.planner.models[key]
                if action == 'noop':
                    data = self.expected[model['path']]
                    self.state['resources'][key] = record_for(model, self.identifiers, data, model['path'])
                    continue
                if action == 'create' and model['kind'] in {'entity', 'group'}:
                    payload = {field: value for field, value in model['payload'].items()
                               if field not in {'policies', 'member_entity_ids', 'member_group_ids'}}
                    self.write(model, payload, operation, links=False)
                    deferred.append((model, operation))
                else:
                    # Ensure every new group UUID is available before applying nested membership.
                    # RU: До назначения вложенного членства должны быть известны UUID всех новых групп.
                    if model['kind'] == 'group' and operation['phase'] < 40:
                        deferred.append((model, operation))
                    else:
                        payload = resolve(model['payload'], self.identifiers)
                        self.write(model, payload, operation)
            if not deferred_done:
                self.attach_deferred(deferred)
            self.state['pending'] = None
            registry_changed = self.state != initial_state
            if registry_changed:
                self.store.save(self.state)
            return {'changed': bool(self.confirmed) or registry_changed, 'confirmed': self.confirmed,
                    'uncertain': None, 'registry_changed': registry_changed}
        except (ConfigurationError, OSError) as error:
            pending = self.state.get('pending')
            raise PartialApply(str(error) if isinstance(error, ConfigurationError) else 'Local registry persistence failed',
                               self.confirmed, {'key': pending['key'], 'digest': pending['digest']} if pending else None) from None

    def attach_deferred(self, deferred):
        """Attach relationships after newly created identities receive UUIDs.
        RU: Назначить связи после получения UUID новыми сущностями.

        Args:
            deferred (list[tuple]): Models and operations awaiting IDs / модели и операции, ожидающие ID.

        Returns:
            None.

        Raises:
            ConfigurationError: Drift, unresolved references or API failure / дрейф, неразрешённые ссылки или ошибка API.
            OSError: Journal write failed / ошибка записи журнала.
        """
        for model, operation in deferred:
            payload = resolve(model['payload'], self.identifiers)
            current = self.expected.get(model['path'])
            if current != payload:
                self.write(model, payload, dict(operation, action='attach'))
            else:
                self.state['resources'][model['key']] = record_for(model, self.identifiers, current, model['path'])

    def reread(self, model):
        """Check that a live resource still matches the expected state.
        RU: Проверить соответствие текущего ресурса ожидаемому состоянию.

        Args:
            model (dict): Planned resource model / модель планируемого ресурса.

        Returns:
            dict | None: Current normalized fields / текущие нормализованные поля.

        Raises:
            ConfigurationError: Resource drift or API failure / дрейф ресурса или ошибка API.
        """
        path = model['path']
        actual = read_object(self.client, model['kind'], path)
        check(actual == self.expected.get(path), 'Affected object drifted immediately before write')
        return actual

    def write(self, model, payload, operation, links=True):
        """Journal intent, write once and verify readable fields.
        RU: Записать намерение в журнал, выполнить запись и проверить читаемые поля.

        Args:
            model (dict): Planned resource model / модель планируемого ресурса.
            payload (dict): API write fields / поля для записи через API.
            operation (dict): Single planned operation / одна планируемая операция.
            links (bool): Include resolved relationships / включать разрешённые связи.

        Returns:
            None.

        Raises:
            ConfigurationError: Drift, collision, API failure or readback mismatch / дрейф, коллизия, ошибка API или несовпадение прочитанных данных.
            OSError: Registry persistence failed / ошибка сохранения реестра.
        """
        creating = operation['action'] == 'create' and model['path'] not in self.expected
        before = None
        if creating:
            if model['kind'] in {'entity', 'group'}:
                check(self.client.read('identity/' + model['kind'] + '/name/' + payload['name'], missing=True) is None,
                      'Identity appeared after planning')
            elif model['kind'].endswith('_alias'):
                # Creation endpoint has no GET. A complete alias re-list checks both mount/name and canonical binding.
                # RU: У endpoint создания нет GET; полный список алиасов позволяет проверить путь, имя и каноническую привязку.
                alias_kind = model['kind'].replace('_', '-')
                for uuid in self.client.list('identity/' + alias_kind + '/id'):
                    existing = self.client.read('identity/' + alias_kind + '/id/' + uuid)
                    check(not (existing['name'] == payload['name'] and existing['mount_accessor'] == payload['mount_accessor']),
                          'Alias appeared after planning')
            elif model['kind'] == 'ldap_config' and model.get('new_auth_mount'):
                before = read_object(self.client, model['kind'], model['path'])
                check(before is None or initial_ldap_config(before), 'LDAP config was changed after auth enable')
                self.expected[model['path']] = before
            else:
                check(read_object(self.client, model['kind'], model['path']) is None, 'Object appeared after planning')
        else:
            before = self.reread(model)
        safe_payload = copy.deepcopy(payload)
        record = record_for(model, self.identifiers, safe_payload, model['path'], links=links)
        intent = {'key': model['key'], 'action': operation['action'], 'before': before,
                  'desired': safe_payload, 'record': record, 'password_write': bool(model.get('password'))}
        intent['digest'] = digest(intent)
        # Persist intent before the request: a lost reply does not prove failure.
        # RU: Сохраняем намерение до запроса: потеря ответа не означает отказ записи.
        self.state['pending'] = intent
        self.store.save(self.state)
        # Keep plaintext secrets out of the journal and attach them only to the request.
        # RU: Открытые секреты добавляем только в запрос, исключая их из журнала.
        outgoing = copy.deepcopy(payload)
        if model.get('password'):
            outgoing[model.get('secret_field', 'password')] = model['password']
        response = self.client.request('POST', model['path'], outgoing)
        if creating and (model['kind'] in {'entity', 'group'} or model['kind'].endswith('_alias')):
            uuid = response.get('data', {}).get('id')
            check(bool(uuid), 'Vault write response did not contain identity UUID; reconcile journal')
            self.identifiers[model['key']] = uuid
            model['path'] = 'identity/' + model['kind'].replace('_', '-') + '/id/' + uuid
        if creating and model['kind'] == 'auth_mount':
            auth = self.client.read('sys/auth')
            self.identifiers[model['key']] = auth[model['id'] + '/']['accessor']
        data = read_object(self.client, model['kind'], model['path'])
        mismatched = [field for field, value in safe_payload.items() if data.get(field) != value]
        check(not mismatched, 'Vault readback differs from write intent in fields: ' + ', '.join(mismatched))
        record = record_for(model, self.identifiers, data, model['path'], links=links)
        self.state['resources'][model['key']] = record
        self.expected[model['path']] = data
        confirmed = {'key': model['key'], 'action': operation['action'], 'hash': digest(data)}
        self.state['journal'].append(confirmed)
        self.state['pending'] = None
        self.confirmed.append(confirmed)
        try:
            self.store.save(self.state)
        except OSError:
            self.state['pending'] = intent
            raise
        # A deferred link update must never submit the password a second time.
        # RU: Отложенное обновление связей не должно повторно отправлять пароль.
        model['password'] = None

    def remove(self, operation):
        """Delete an approved object after checking its current identity.
        RU: Удалить разрешённый объект после проверки его текущего идентификатора.

        Args:
            operation (dict): Single planned operation / одна планируемая операция.

        Returns:
            None.

        Raises:
            ConfigurationError: Forbidden kind, drift or API failure / запрещённый тип, дрейф или ошибка API.
            OSError: Registry persistence failed / ошибка сохранения реестра.
        """
        check(operation['kind'] not in {'mount', 'auth_mount', 'ldap_config'} and
              not operation['path'].startswith(('sys/mounts/', 'sys/auth/')),
              'Deleting secret/auth mounts or LDAP integrations is forbidden')
        record = self.state['resources'][operation['key']]
        model = {'kind': record['kind'], 'path': record['path']}
        before = self.reread(model)
        intent = {'key': operation['key'], 'action': 'delete', 'before': before,
                  'desired': {}, 'record': record, 'password_write': False}
        intent['digest'] = digest(intent)
        # Persist intent before the request: a lost reply does not prove failure.
        # RU: Сохраняем намерение до запроса: потеря ответа не означает отказ записи.
        self.state['pending'] = intent
        self.store.save(self.state)
        self.client.request('DELETE', record['path'])
        check(self.client.read(record['path'], missing=True) is None, 'Deleted object is still present')
        self.state['resources'].pop(operation['key'])
        self.expected.pop(record['path'], None)
        confirmed = {'key': operation['key'], 'action': 'delete'}
        self.state['journal'].append(confirmed)
        self.state['pending'] = None
        self.confirmed.append(confirmed)
        try:
            self.store.save(self.state)
        except OSError:
            self.state['pending'] = intent
            raise
