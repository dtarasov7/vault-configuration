"""Publish a sanitized result and native Ansible diff after the secret API task."""
from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    """Publish sanitized reports through the default Ansible callback.
    RU: Публиковать безопасные отчёты через стандартный callback Ansible.
    """
    _supports_check_mode = True

    def run(self, tmp=None, task_vars=None):
        """Expose the report, change flag and optional diff to Ansible.
        RU: Передать Ansible отчёт, признак изменений и необязательный diff.

        Args:
            tmp (str | None): Ansible temporary directory / временный каталог Ansible.
            task_vars (dict | None): Ansible task variables / переменные задачи Ansible.

        Returns:
            dict: Callback-ready action result / результат действия для callback.
        """
        result = super().run(tmp, task_vars)
        report = self._task.args.get('report', {})
        # The default callback otherwise hides this action's msg unless -v is used.
        result['_ansible_verbose_always'] = True
        result['changed'] = bool(report.get('changed', False))
        result['diff'] = report.get('diff', [])
        result['msg'] = {key: value for key, value in report.items() if key != 'diff'}
        if report.get('mode') == 'dry' and 'diff' in report:
            result['msg']['diff'] = report['diff']
        return result
