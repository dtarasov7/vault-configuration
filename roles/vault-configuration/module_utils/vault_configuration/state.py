"""0600 atomic registry, backup, journal and local serialization."""
import copy
import fcntl
import json
import os
import stat
import tempfile

from .common import ConfigurationError, canonical, check, digest


def atomic_write(filename, text, check_mode=False):
    """Atomically replace a private file only when needed.
    RU: Атомарно заменить приватный файл при необходимости.

    Args:
        filename (str): Local file path / путь локального файла.
        text (str): Input text / входной текст.
        check_mode (bool): Predict changes without writing / оценивать изменения без записи.

    Returns:
        bool: Content or mode differs, including in check mode / содержимое или режим доступа отличаются, включая check mode.

    Raises:
        ConfigurationError: Destination is a symlink / назначение является символьной ссылкой.
        OSError: File operation failed / ошибка файловой операции.
    """
    data = text.encode('utf-8')
    if os.path.lexists(filename):
        check(not os.path.islink(filename), 'Refusing a symlink as a managed file')
        with open(filename, 'rb') as stream:
            current = stream.read()
        unchanged = current == data and stat.S_IMODE(os.stat(filename).st_mode) == 0o600
        if unchanged:
            return False
    if check_mode:
        return True
    directory = os.path.dirname(os.path.abspath(filename))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.vault-configuration-', dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, filename)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            # Persist the renamed directory entry as well as the file contents.
            # RU: Сохраняем на диск запись каталога после переименования, а не только содержимое файла.
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def validate_state(value):
    """Validate the registry schema before trusting or saving it.
    RU: Проверить схему реестра перед использованием или сохранением.

    Args:
        value (dict): Registry to validate / проверяемый реестр.

    Returns:
        None.

    Raises:
        ConfigurationError: Invalid registry fields or types / неверные поля или типы реестра.
    """
    check(isinstance(value, dict) and value.get('schema_version') == 1 and
          set(value) == {'schema_version', 'cluster_id', 'owner', 'resources', 'journal', 'pending'},
          'Invalid registry schema; restore a verified backup explicitly')
    check(isinstance(value['cluster_id'], str) and isinstance(value['owner'], str) and
          isinstance(value['resources'], dict) and isinstance(value['journal'], list), 'Invalid registry types')
    for key, record in value['resources'].items():
        check(isinstance(key, str) and isinstance(record, dict) and
              {'kind', 'id', 'path', 'uuid', 'links', 'hash', 'section'} <= set(record), 'Invalid registry resource')
        allowed = {'kind', 'id', 'path', 'uuid', 'links', 'hash', 'section', 'shared', 'policy_links',
                   'accessor', 'auth_mount', 'role_type', 'name', 'login', 'password_policy', 'password_revision'}
        check(not set(record) - allowed, 'Unknown registry resource fields')
        check(isinstance(record['links'], dict) and all(isinstance(items, list) and
              all(isinstance(item, str) for item in items) for items in record['links'].values()), 'Invalid registry links')
    check(value['pending'] is None or isinstance(value['pending'], dict), 'Invalid recovery journal')


class StateStore:
    """Persist owner records and serialize local writers.
    RU: Хранить реестр владельца и сериализовать локальные записи.
    """
    def __init__(self, filename, owner):
        self.filename = filename
        self.owner = owner
        self.lock = None

    def acquire(self):
        """Acquire the shared nonblocking directory lock.
        RU: Захватить общую неблокирующую блокировку каталога.

        Returns:
            None.

        Raises:
            ConfigurationError: Lock cannot be acquired / невозможно захватить блокировку.
        """
        directory = os.path.dirname(self.filename)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
        descriptor = os.open(os.path.join(directory, '.vault-configuration.lock'), flags, 0o600)
        self.lock = os.fdopen(descriptor, 'r+')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.close()
            raise ConfigurationError('Another apply holds the execution-host registry lock') from None

    def close(self):
        if self.lock:
            self.lock.close()
            self.lock = None

    def load(self, cluster_id):
        """Load a private registry or initialize an empty one.
        RU: Загрузить приватный реестр либо создать пустой в памяти.

        Args:
            cluster_id (str): Expected cluster UUID / ожидаемый UUID кластера.

        Returns:
            dict: Validated owner registry / проверенный реестр владельца.

        Raises:
            ConfigurationError: Invalid permissions, schema, owner or cluster / неверные права, схема, владелец или кластер.
            OSError: Registry cannot be read / реестр невозможно прочитать.
        """
        if not os.path.lexists(self.filename):
            return {'schema_version': 1, 'cluster_id': cluster_id, 'owner': self.owner,
                    'resources': {}, 'journal': [], 'pending': None}
        try:
            check(not os.path.islink(self.filename), 'Registry cannot be a symlink')
            check(stat.S_IMODE(os.stat(self.filename).st_mode) == 0o600, 'Registry permissions must be 0600')
            with open(self.filename, encoding='utf-8') as stream:
                value = json.load(stream)
        except (OSError, ValueError, UnicodeError):
            raise ConfigurationError('Cannot read registry; restore a verified .bak explicitly') from None
        validate_state(value)
        check(value['cluster_id'] == cluster_id, 'Registry belongs to another Vault cluster')
        check(value['owner'] == self.owner, 'Registry owner conflict')
        return value

    def save(self, state):
        """Back up the previous registry and atomically save the next.
        RU: Сохранить резервную копию реестра и атомарно записать новый.

        Args:
            state (dict): Owner registry and pending journal / реестр владельца и журнал незавершённой операции.

        Returns:
            None.

        Raises:
            ConfigurationError: Invalid state or unsafe path / неверное состояние или небезопасный путь.
            OSError: Backup or write failed / ошибка резервного копирования или записи.
        """
        validate_state(state)
        if os.path.exists(self.filename):
            with open(self.filename, encoding='utf-8') as stream:
                previous = stream.read()
            atomic_write(self.filename + '.bak', previous)
        atomic_write(self.filename, canonical(state) + '\n')

    def peers(self, cluster_id):
        """Read sibling owner registries for the same cluster.
        RU: Прочитать соседние реестры владельцев того же кластера.

        Args:
            cluster_id (str): Expected cluster UUID / ожидаемый UUID кластера.

        Returns:
            list[dict]: Peer registries / соседние реестры.

        Raises:
            ConfigurationError: Invalid registry or duplicate owner / неверный реестр или дубликат владельца.
        """
        directory = os.path.dirname(self.filename)
        if not os.path.isdir(directory):
            return []
        peers = []
        for name in sorted(os.listdir(directory)):
            filename = os.path.join(directory, name)
            if filename == self.filename or not name.endswith('.json'):
                continue
            try:
                with open(filename, encoding='utf-8') as stream:
                    value = json.load(stream)
            except (OSError, ValueError):
                raise ConfigurationError('Cannot inspect a peer registry; ownership is uncertain') from None
            if isinstance(value, dict) and {'unsupported', 'dependencies', 'objects', 'partial'} <= set(value):
                continue  # A role-generated audit can share the output directory with the registry.
            if isinstance(value, dict) and value and all(key.startswith('vault_configuration_') for key in value):
                continue
            validate_state(value)
            if value['cluster_id'] == cluster_id:
                check(value['owner'] != self.owner, 'Duplicate registry for this owner/cluster')
                peers.append(value)
        return peers
