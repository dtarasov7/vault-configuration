# Vault без TLS и LDAP на одном сервере РЕД ОС 8

В примере ровно две роли:

- `01-install.yml` вызывает только `hashicorp-vault`: установка, запуск, init и unseal;
- `02-configure.yml` вызывает только `vault-configuration`: KV mounts, userpass, локальные пользователи и группы, LDAP, aliases и ACL.

Все параметры и пароли задаются в `group_vars/vault/`. Vault API работает по HTTP на TCP/8200; Vault подключается к LDAP на том же `redos8` по TCP/389. HTTP и LDAP без TLS подходят для изолированного тестового стенда: credentials передаются без шифрования.

## Файлы

```text
examples/redos8-lab/
├── hosts.ini
├── group_vars/vault/
│   ├── 00-lab.yml            # Адреса, LDAP suffix, пути состояния
│   ├── 10-install.yml        # Установка Vault без TLS, init/unseal
│   ├── 20-configuration.yml  # Users, groups, LDAP bind DN, grants
│   └── 30-credentials.yml    # Токен, локальные пароли, LDAP bind password
├── 01-install.yml
└── 02-configure.yml
```

## Что заполнить

1. В [hosts.ini](hosts.ini) замените `192.0.2.80` адресом сервера `redos8`; при необходимости измените `ansible_user`. Для установки нужны SSH и root/sudo. На контроллере нужны Ansible и Python, на сервере — Python для штатных модулей Ansible.
2. В репозитории сервера должен быть доступен Vault 2.0.4. Версия задана в `10-install.yml`; подходящий установленный пакет используется повторно и закрепляется versionlock. API-роль проверена на 2.0.0 и 2.0.4.
3. LDAP уже должен быть наполнен [seed-test-ldap-redos8.py](../../scripts/seed-test-ldap-redos8.py) и слушать TCP/389 на адресе `redos8`. При другом `--domain` измените `vault_lab_ldap_base_dn` в `00-lab.yml`.
4. В `20-configuration.yml` задайте `vault_configuration_ldap[].config.binddn`. По умолчанию это `cn=vault,ou=service,dc=example,dc=org`.
5. В `30-credentials.yml` замените `REPLACE_WITH_LDAP_BIND_PASSWORD` фактическим паролем этой bind-учётки. Скрипт наполнения сохранил его на `redos8` в `/root/vault-ldap-test/ldap-secrets.json`, поле `vault_configuration_ldap_passwords.test-ldap`. Если использовали другой `--state-dir`, найдите файл там. Здесь же задайте пароли локальных пользователей вместо демонстрационных значений.

Bind-пароль передаётся обычной переменной inventory:

```yaml
vault_configuration_ldap_passwords:
  test-ldap: "фактический-пароль-bind-учётки"
```

`test-ldap` должен совпадать с `id` интеграции в `20-configuration.yml`. Пароль bind-учётки не является паролем LDAP-пользователя `alice` или локального `local-alice`.

Файл с реальными секретами можно зашифровать на контроллере:

```bash
ansible-vault encrypt examples/redos8-lab/group_vars/vault/30-credentials.yml
```

После этого добавляйте `--ask-vault-pass` к командам playbook. Контроллер должен достигать SSH и TCP/8200 сервера, а Vault — TCP/389 LDAP. Firewall, SELinux и listeners LDAP этим примером не изменяются.

## Запуск

Выполняйте из корня репозитория, где находится `ansible.cfg`:

```bash
ansible-playbook -i examples/redos8-lab/hosts.ini examples/redos8-lab/01-install.yml
ansible-playbook -i examples/redos8-lab/hosts.ini examples/redos8-lab/02-configure.yml
```

При необходимости добавьте `--ask-become-pass` для sudo. Отдельные скрипты установки или подготовки доступа запускать не требуется.

Первая роль создаёт приватный каталог `.state/` на контроллере, устанавливает и запускает постоянный Vault с Raft storage без TLS, выполняет init с пятью долями ключа и порогом две, сохраняет `.state/vault-init.json` с mode 0600 и выполняет unseal. При повторном запуске данные инициализации сохраняются; существующий Vault повторно не инициализируется.

В этом тестовом inventory `vault_configuration_token` читает initial root token из `.state/vault-init.json`. Вторая роль использует этот единственный токен для всех операций. Можно заменить выражение в `30-credentials.yml` готовым административным токеном; его выдача описана в [README роли](../../roles/vault-configuration/README.md#создание-токена-через-root-token).

Вторая роль работает с контроллера через API. Она сама создаёт отсутствующие `userpass` и `ldap` auth mounts, затем пользователей, группы, aliases, KV v2 mounts и права. Секреты берутся из inventory; чтения файлов LDAP-сервера по SSH нет. Реестра владения у API-роли нет: повторные запуски используют metadata и префикс политик в Vault. В `.state/` сохраняются init/unseal-материалы установочной роли и результаты dry/export на контроллере; эти файлы сохраняйте, каталог исключён из Git.

## Пользователи и права

| Метод входа | Пользователь | Группа | Права |
| --- | --- | --- | --- |
| `userpass` | `local-alice` | `local-developers` | `apps/payments/dev`: read, write, list |
| `userpass` | `local-bob` | `local-operators` | `infra/prod`: read, list |
| `ldap` | `alice` | `ldap-developers` | `apps/payments/dev`: read, write, list |
| `ldap` | `bob` | `ldap-operators` | `infra/prod`: read, list |
| `ldap` | `carol` | Обе LDAP-группы | Оба набора прав |
| `ldap` | `dave` | Нет | Вход без прав из этих групп |

LDAP-членство в таблице соответствует начальному наполнению скрипта. Пароли LDAP-пользователей находятся на `redos8` в `/root/vault-ldap-test/test-accounts.json`. Пароли локальных пользователей задаются в `30-credentials.yml`.

UI доступен по `http://<адрес redos8>:8200/ui/`; выбирайте метод и mount path `userpass` или `ldap`. Создаются пять KV v2 mounts: `certs`, `infra`, `apps`, `cicd`, `users`; сами секреты в KV роль не записывает. Mounts не удаляются. Если предыдущая версия inventory уже создала только `apps`, `infra`, `users`, повторный apply с текущим списком добавит `certs` и `cicd`, сохранив существующие mounts.

Повторный запуск второго playbook идемпотентен. Для планирования после первого playbook:

```bash
ansible-playbook -i examples/redos8-lab/hosts.ini examples/redos8-lab/02-configure.yml -e vault_configuration_config_mode=dry
ansible-playbook -i examples/redos8-lab/hosts.ini examples/redos8-lab/02-configure.yml --check --diff
```

Dry/check планируют создание отсутствующих userpass/LDAP mounts, не записывая изменения. `--check` установки свежего сервера первым playbook не поддерживается. Для явной смены пароля локального пользователя задайте `password_policy: always`; для bind-пароля — `bind_password_policy: always`. После смены верните on_create, иначе пароль записывается при каждом apply.

Обычный `dry` сохраняет результат в YAML на контроллере: `examples/redos8-lab/.state/dry-result.yml`. Имя и путь заданы переменной `vault_configuration_config_report_destination` в `group_vars/vault/20-configuration.yml`; измените её для своего inventory. Условие в этом примере включает сохранение только в режиме dry, чтобы apply не перезаписывал план. Отчёт содержит mode, plan с digest/operations и три сводки summary. Токены и пароли в него не включаются; файл имеет права 0600. Повторный dry с тем же планом не меняет файл. При `--check` файл не создаётся и не обновляется.

В dry показываются только операции изменения. Уже настроенные объекты с `action: noop` в YAML и консоль не включаются; если менять нечего, `plan.operations: []` и все три счётчика равны нулю.

## Проверки

Проверены синтаксис обоих playbook, настоящий init/unseal первой ролью на изолированном Vault 2.0.4 и полный второй playbook с OpenLDAP: создание auth mounts, dry/check, идемпотентность и реальные входы всех шести пользователей. Установка RPM/systemd на реальном РЕД ОС 8 не выполнялась; в тесте этот этап заменён временным Vault-сервером.

## Экспорт

```bash
ansible-playbook -i examples/redos8-lab/hosts.ini examples/redos8-lab/02-configure.yml -e vault_configuration_config_mode=export
```

Файл `vault-access-manager-export.yml` содержит обычный YAML с переменными роли, готовый для vars_files. Отдельный `vault-access-manager-export.yml.audit.json` содержит JSON-аудит. Имена меняются через `vault_configuration_export_destination` и `vault_configuration_export_audit_destination`. Повторный export перезапишет прежний JSON-вариант основного файла в YAML, не изменяя Vault.

API-роли нужен DNS target `redos8`, разрешаемый с контроллера (ansible_host определяет только SSH). По умолчанию используются api_execution: controller, api_scheme: http и порт установочной роли. Если API доступен только с самого сервера, задайте vault_configuration_api_execution: target и vault_configuration_api_use_loopback: true. Playbook настройки по-прежнему только вызывает роль и отключает gather_facts.
