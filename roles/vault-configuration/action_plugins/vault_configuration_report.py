"""Controller-side context checks and private artifact publishing.
RU: Проверка контекста и запись приватных результатов только на контроллере.
"""
import ipaddress
import json
import os
import re
import stat
import tempfile

from ansible.plugins.action import ActionBase

try:
    import yaml
except ImportError:
    yaml = None


def context(arguments):
    """Validate target/API settings and resolve controller artifact paths.
    RU: Проверить target/API и вычислить пути файлов на контроллере.

    Args:
        arguments (dict): Task arguments / аргументы задачи.
    Returns:
        dict: API endpoint, delegate and absolute paths / адрес API, delegate и абсолютные пути.
    Raises:
        ValueError: Invalid settings or colliding outputs / неверные настройки или совпадающие пути.
    """
    hostname = arguments.get('hostname')
    if not isinstance(hostname, str) or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', hostname):
        raise ValueError('inventory_hostname must be the Vault DNS hostname, not an inventory alias or URL')
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError('Use a DNS hostname as inventory_hostname, not an IP address')
    execution = arguments.get('execution')
    scheme = arguments.get('scheme')
    port = arguments.get('port')
    loopback = arguments.get('loopback')
    # Ansible 2.13 can stringify values obtained through an intermediate Jinja variable.
    # RU: Ansible 2.13 может превратить значение промежуточной Jinja-переменной в строку.
    if isinstance(port, str) and re.fullmatch(r'[0-9]+', port):
        port = int(port)
    if isinstance(loopback, str) and loopback.lower() in {'true', 'false'}:
        loopback = loopback.lower() == 'true'
    if execution not in {'controller', 'target'} or scheme not in {'http', 'https'}:
        raise ValueError('api_execution must be controller/target and api_scheme must be http/https')
    if type(port) is not int or not 1 <= port <= 65535 or type(loopback) is not bool:
        raise ValueError('api_port must be an integer 1..65535 and api_use_loopback must be boolean')
    if loopback and execution != 'target':
        raise ValueError('api_use_loopback is supported only with api_execution: target')
    mode = arguments.get('mode')
    if mode not in {'dry', 'apply', 'export', 'matrix'}:
        raise ValueError('mode must be dry, apply, export or matrix')
    if yaml is None:
        raise ValueError('PyYAML is required on the Ansible controller')
    matrix_source = arguments.get('matrix_source', 'cluster')
    if matrix_source not in {'cluster', 'inventory'}:
        raise ValueError('matrix_source must be cluster or inventory')
    offline = mode == 'matrix' and matrix_source == 'inventory'
    root = arguments['root']
    paths = {}
    for key in ('report_destination', 'destination', 'audit_destination', 'matrix_destination'):
        value = arguments.get(key)
        if value is None or value == '':
            paths[key] = None
            continue
        if not isinstance(value, str):
            raise ValueError('Controller artifact destinations must be paths or null')
        paths[key] = os.path.abspath(os.path.join(root, value))
    if paths['matrix_destination'] is not None:
        paths['matrix_notes_destination'] = paths['matrix_destination'] + '.notes.txt'
    else:
        paths['matrix_notes_destination'] = None
    selected = [paths['report_destination']] if mode == 'dry' else []
    if mode == 'export':
        selected += [paths['destination'], paths['audit_destination']]
    if mode == 'matrix':
        selected += [paths['matrix_destination'], paths['matrix_notes_destination']]
    if mode in {'dry', 'export', 'matrix'} and any(value is None for value in selected):
        raise ValueError('Dry/export/matrix artifacts require nonempty controller destinations')
    outputs = [value for value in paths.values() if value is not None]
    if len(set(os.path.realpath(value) for value in outputs)) != len(outputs):
        raise ValueError('Controller report, export and audit destinations must be distinct')
    for path in outputs:
        if os.path.islink(path) or os.path.exists(path) and not os.path.isfile(path):
            raise ValueError('Artifact destination must be a regular file, not a symlink or directory')
    host = '127.0.0.1' if loopback else hostname
    return dict(paths, mode=mode, matrix_source=matrix_source, address='%s://%s:%s' % (scheme, host, port),
                delegate='localhost' if (execution == 'controller' or offline) else hostname,
                connection='local' if (execution == 'controller' or offline) else arguments.get('target_connection', 'ssh'),
                interpreter=arguments.get('controller_python') if (execution == 'controller' or offline)
                else arguments.get('target_python', 'auto_silent'))


def atomic_write(filename, text, check_mode=False):
    """Atomically write UTF-8/LF with mode 0600; check mode creates nothing.
    RU: Атомарно записать UTF-8/LF с правами 0600; check mode ничего не создаёт.

    Args:
        filename (str): Controller path / путь на контроллере.
        text (str): Serialized content / сериализованное содержимое.
        check_mode (bool): Predict without writing / прогноз без записи.
    Returns:
        bool: File content or permissions changed / изменилось содержимое либо права.
    Raises:
        ValueError: Unsafe destination / небезопасный путь.
        OSError: Filesystem failure / ошибка файловой системы.
    """
    filename = os.path.abspath(filename)
    if os.path.islink(filename):
        raise ValueError('Refusing a symlink artifact destination')
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as stream:
            same = stream.read() == text
        if same and stat.S_IMODE(os.stat(filename).st_mode) == 0o600:
            return False
    if check_mode:
        return True
    parent = os.path.dirname(filename)
    missing = []
    directory = parent
    while not os.path.isdir(directory):
        if os.path.lexists(directory):
            raise ValueError('Artifact parent must be a directory')
        missing.append(directory)
        directory = os.path.dirname(directory)
    for directory in reversed(missing):
        os.mkdir(directory, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix='.vault-configuration-', dir=parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, filename)
        directory = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def inventory_sections(variables, templar):
    """Project raw inventory before templating; password expressions are never evaluated.
    RU: Отобрать поля сырого inventory до шаблонизации; выражения паролей не вычисляются.

    Args:
        variables (dict): Unrendered task variables / исходные переменные задачи.
        templar (Templar): Ansible renderer / шаблонизатор Ansible.
    Returns:
        dict: Public declarations / объявления без секретных полей.
    Raises:
        ValueError: Users are not a literal list/mapping / users не является явным списком словарей.
    """
    users = variables.get('vault_configuration_users')
    if users is not None:
        if not isinstance(users, list) or not all(isinstance(item, dict) for item in users):
            raise ValueError('Offline matrix users must be a literal list of mappings to avoid evaluating password expressions')
        users = [{key: value for key, value in item.items() if key != 'password'} for item in users]
    sections = {'users': users}
    for section in ('groups', 'grants', 'auth_roles', 'personal_access'):
        sections[section] = variables.get('vault_configuration_' + section)
    return templar.template({key: value for key, value in sections.items() if value is not None})


class ActionModule(ActionBase):
    """Run context checks and publish reports without connecting to the target.
    RU: Проверять контекст и публиковать отчёты без соединения с target.
    """
    _supports_check_mode = True

    def run(self, tmp=None, task_vars=None):
        """Validate or publish locally / RU: Проверить либо опубликовать локально.

        Args:
            tmp (str | None): Ansible temporary path / временный путь Ansible.
            task_vars (dict | None): Task variables / переменные задачи.
        Returns:
            dict: Action result with sanitized report / результат с безопасным отчётом.
        """
        result = super().run(tmp, task_vars)
        result['changed'] = False
        try:
            if self._task.args.get('operation') == 'validate':
                result['context'] = context(self._task.args)
                return result
            if self._task.args.get('operation') == 'matrix_inventory':
                result['sections'] = inventory_sections(task_vars or {}, self._templar)
                return result
            settings = self._task.args['context']
            # Strip Ansible unsafe-string subclasses without evaluating embedded templates.
            # RU: Убираем подклассы unsafe-строк Ansible, не вычисляя вложенные шаблоны.
            serialized_report = json.dumps(self._task.args.get('report', {}))
            report = json.loads(serialized_report)
            report.setdefault('mode', str(settings['mode']))
            variables = report.pop('_export_variables', None)
            audit = report.pop('_export_audit', None)
            matrix_csv = report.pop('_matrix_csv', None)
            matrix_notes = report.pop('_matrix_notes', None)
            outputs = []
            if report['mode'] == 'matrix' and not report.get('error'):
                if not isinstance(matrix_csv, str) or not isinstance(matrix_notes, str):
                    raise ValueError('API module returned no matrix payload')
                outputs += [(settings['matrix_destination'], matrix_csv),
                            (settings['matrix_notes_destination'], matrix_notes)]
                report.update(destination=settings['matrix_destination'], notes_destination=settings['matrix_notes_destination'])
            if report['mode'] == 'export' and not report.get('error'):
                if variables is None or audit is None:
                    raise ValueError('API module returned no export payload')
                outputs += [(settings['destination'], yaml.safe_dump(variables, allow_unicode=True, sort_keys=True)),
                            (settings['audit_destination'], json.dumps(audit, ensure_ascii=False, sort_keys=True, indent=2) + '\n')]
                report.update(destination=settings['destination'], audit_destination=settings['audit_destination'])
            destination = settings.get('report_destination')
            if destination:
                content = (yaml.safe_dump(report, allow_unicode=True, sort_keys=True) if report['mode'] == 'dry'
                           else json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
                outputs.append((destination, content))
            # Prepare/check every artifact before the first replacement.
            # RU: Готовим и проверяем все результаты до первой замены файла.
            changes = [atomic_write(path, content, check_mode=True) for path, content in outputs]
            if not self._task.check_mode:
                for path, content in outputs:
                    atomic_write(path, content)
            result['changed'] = bool(report.get('changed')) or any(changes)
            result['warnings'] = report.get('warnings', [])
            result['diff'] = report.get('diff', [])
            result['msg'] = report
            result['_ansible_verbose_always'] = True
        except ValueError as error:
            result.update(failed=True, msg=str(error))
        except (OSError, UnicodeError):
            result.update(failed=True, msg='Cannot publish artifacts on controller; check paths, permissions and free space')
        return result
