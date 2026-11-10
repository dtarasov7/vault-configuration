# vault-configuration

Декларативная Ansible-роль для Vault Community: Identity entities, aliases, внутренние и внешние группы, локальные userpass accounts, ACL KV v2 и назначения policies существующим AppRole/Kubernetes/JWT/OIDC roles. Исполняется на одном execution host через API. Не устанавливает Vault; создаёт отсутствующие KV v2 mounts и userpass/LDAP auth mounts, никогда не удаляет mounts, не читает и не изменяет пользовательские KV data, не выполняет login/renewal и не выпускает токены.

Точная проверенная матрица и результаты находятся в [TEST-REPORT.md](TEST-REPORT.md) и [compatibility.json](compatibility.json). Неизвестные версии и внешние версии auth plugins отклоняются до изменений. `v2` в grants означает KV v2, а не версию сервера.

## Запуск

Execution host: Python 3.8.20 и ansible-core 2.13.13; API-клиент использует стандартную библиотеку Python, YAML-отчёты и экспорт — PyYAML 6.0.2 из `requirements.txt`. Для запуска тестов нужны дополнительные зависимости из `requirements-test.txt` и коллекции `molecule/requirements.yml`. Другие runtime-комбинации не объявлены проверенными. Vault CLI и community.hashi_vault для роли не требуются.

Полный пример установки и настройки одного РЕД ОС 8 без TLS с локальными пользователями и LDAP: [examples/redos8-lab](../../examples/redos8-lab/README.md). Он содержит `hosts.ini`, `group_vars` и два playbook для `hashicorp-vault` и `vault-configuration`.

```sh
ansible-playbook -i localhost, roles/vault-configuration/examples/playbook.yml
ansible-playbook -i localhost, roles/vault-configuration/examples/playbook.yml --check --diff
```

[examples/inventory.yml](examples/inventory.yml) содержит полный пример всех пяти mounts, обоих порядков project/environment, userpass, внешних групп, личных областей, SSI Kubernetes auth, CI JWT и Ansible AppRole. Замените адрес, существующие зависимости, реальные alias claims и защищённые переменные для своей среды. Установите существующую `company-self-service` policy либо уберите соответствующий grant.

Рекомендуемый inventory:

```ini
[vault_access_execution]
localhost ansible_connection=local
```

Playbook должен содержать ровно один host на Vault/owner; `vault_configuration_execution_host` по умолчанию `localhost`. API, CA и client cert/key должны быть доступны именно execution host. Системные пользователи, systemd и logrotate не нужны.

## Публичные переменные

| Переменная | Значение / назначение |
| --- | --- |
| `vault_configuration_config_*` | Отдельные настройки ниже; defaults находятся в `defaults/main.yml` |
| `vault_configuration_token` | Один существующий административный токен для всех API-операций; по умолчанию пустой; выдача описана ниже |
| `vault_configuration_passwords` | Словарь секретов по `users[].id`, по умолчанию `{}` |
| `vault_configuration_users` | Не задано: не управлять пользователями; список деклараций users |
| `vault_configuration_groups` | Не задано: не управлять группами; список declarations groups |
| `vault_configuration_grants` | Не задано: не управлять обычными policy assignments; список grants |
| `vault_configuration_auth_roles` | Не задано: не объявлять auth roles; только существующие roles |
| `vault_configuration_personal_access` | Не задано: не управлять personal policy; объект ниже |
| `vault_configuration_export` | Экспорт: scope `managed`, destination `./vault-access-manager-export.yml`, allow_partial `false` |
| `vault_configuration_execution_host` | Host исполнения модуля, по умолчанию `localhost` |
| `vault_configuration_result` | Зарегистрированный результат; публичные сведения находятся в `.report` |

Настройки `vault_configuration_config_*`:

| Поля | Контракт |
| --- | --- |
| `vault_configuration_config_schema_version`, `vault_configuration_config_mode`, `vault_configuration_config_compatibility_profile` | `1`; `dry` (default), `apply`, `export`; `community-validated` (default), `community-candidate` для разработки профилей |
| `vault_configuration_config_connection_address` | HTTPS origin без credentials, query и `/v1`; замените пример адреса из defaults |
| `vault_configuration_config_connection_validate_tls`, `vault_configuration_config_connection_ca_file` | `true`; необязательный локальный PEM CA-файл |
| `vault_configuration_config_connection_client_cert`, `vault_configuration_config_connection_client_key` | Необязательная пара существующих PEM-файлов для mTLS |
| `vault_configuration_config_connection_timeout_seconds`, `vault_configuration_config_connection_allow_insecure_http` | `30` (1–600); `false`, HTTP включают явно только в тестовых средах |
| `vault_configuration_config_mounts` | `[certs, infra, apps, cicd, users]`; отсутствующие создаются как KV v2; существующие другого типа/версии отклоняются; удаления нет |
| `vault_configuration_config_management_owner`, `vault_configuration_config_management_policy_prefix`, `vault_configuration_config_management_state_file` | Обязательные owner, префикс generated policies и абсолютный путь `.json` реестра; defaults: `platform-team`, `vam-platform-`, `/var/lib/ansible/vault-access/platform-state.json` |
| `vault_configuration_config_management_prune`, `vault_configuration_config_management_prune_identities` | Оба `false`; второй дополнительно разрешает удаление owned identities/accounts/aliases |
| `vault_configuration_config_management_adoption` | `[]`; записи `{kind, id, uuid}` либо `{kind, id, hash}` с текущим UUID или SHA256 canonical managed API fields |
| `vault_configuration_config_management_deletion_approvals` | `[]`; `{kind, id, hash, dependencies_cleared: true}` для удаления policy/entity/group; оператор подтверждает устранение внешних зависимостей, включая старые токены |
| `vault_configuration_config_management_recovery_digest` / `vault_configuration_config_management_recovery_outcome` | Не заданы; digest операции и outcome `applied|not_applied` для незавершённой операции; см. восстановление |
| `vault_configuration_config_safety_max_deletions` | `5`; лимит delete operations, включая accounts и aliases |
| `vault_configuration_config_safety_allow_empty_desired` | `false`; необходим для пустой управляемой секции при включённом prune |
| `vault_configuration_config_safety_allow_mount_root` | `false`; отдельный допуск корневых subtree/discovery grants |
| `vault_configuration_config_safety_allow_destructive_grants` | `false`; допуск `destroy_versions`, `delete_metadata` |
| `vault_configuration_config_safety_protected_policies` | `[root, default]`; root/default нельзя назначать даже после переопределения списка |
| `vault_configuration_config_safety_protected_entities`, `vault_configuration_config_safety_protected_groups` | `[]`; inventory ID, имя или Vault UUID; automation entity защищена автоматически |
| `vault_configuration_config_report_destination` | В `dry`: YAML-отчёт 0600, default `{{ playbook_dir }}/vault-configuration-{{ inventory_hostname }}-dry.yml`; полный путь/имя переопределяются в inventory. В остальных режимах не задан; явный отчёт apply сохраняет JSON-формат |
| `vault_configuration_config_expected_plan_digest` | Не задан; при наличии требуется совпадение digest повторно построенного плана |

Каждая настройка переопределяется независимо; defaults остальных переменных сохраняются. Словарь `vault_configuration_config` больше не используется. Неизвестные поля и неправильные типы отклоняются. Машиночитаемая форма: [schemas/inventory.schema.json](schemas/inventory.schema.json); дополнительные семантические проверки выполняет `validation.py`.

### Users, groups и назначения

* User: обязательные `id`, `name`, `source: userpass|external`; `disabled` по умолчанию false; `aliases: [{auth_mount, name}]`. У userpass обязательны `auth_mount`, lowercase `login`, `password_revision`; `password_policy: on_create|on_revision` (default on_create), необязательный `password` или значение в `vault_configuration_passwords[id]`.
* `token_parameters` userpass: `token_ttl`, `token_max_ttl`, `token_explicit_max_ttl`, `token_period`, `token_num_uses` — неотрицательные секунды/числа; `token_no_default_policy` — boolean; `token_type: service|batch|default`; `token_bound_cidrs` — список строк. Пароли bcrypt ограничены 72 байтами UTF-8 и проверяются до записи. `token_policies` локального account роль не назначает: права приходят через entity/groups.
* Group: `id`, `name`, `type: internal|external`; только internal принимает `members` и `member_groups` (default `[]`); external может иметь один `alias: {auth_mount, name}`. Член — inventory ID или `{uuid: ...}` существующей identity. Циклы проверяются также с учётом сторонних существующих связей.
* Auth role: `id`, `type: approle|kubernetes|jwt|oidc`, `auth_mount`, `name`. Роль уже должна существовать. Раздельные адаптеры сохраняют bindings, claims, аудитории, TTL и другие проверенные поля. Неизвестные поля/версии отклоняются. `local_secret_ids` AppRole не отправляется при update, поскольку это параметр создания.
* Grant: `id`, непустой `subjects: [{kind: user|group|auth_role, id: ...}]`, ровно одно из `paths` и `existing_policies`. Для user/group также разрешено `{kind, uuid}` вместо id. UUID проверяется, автоматическое принятие identity под управление не выполняется; управляются только новые связи.
* Path: `mount`, относительный `path`, `scope: exact|subtree`, непустой `permissions`. Произвольная глубина; сегмент `data` внутри логического пути сохраняется. Без wildcard, encoding, Unicode, абсолютных путей и пустых сегментов; ASCII `[A-Za-z0-9_-][A-Za-z0-9_.-]*`.
* `discovery_paths: [{mount, path}]` — необязательный список конкретных каталогов для LIST; пустой path означает root и требует отдельного допуска. План предупреждает о раскрытии имён всех соседних ключей.
* Personal: `{enabled: true, mount: users, subjects: [...], permissions: [...]}`; `identity_source: entity_id` (default) принимает пользователей, `identity_source: ldap_login` — пользователей и группы и требует `auth_mount`. В LDAP-режиме `path_prefix` задаёт необязательный относительный префикс. `{enabled: false}` снимает только ранее управляемые personal links. ID grant `personal` зарезервирован при включённом personal access.

Пропущенная секция сохраняет свою область. Явный `[]` снимает ранее добавленные этим owner связи; удаление объектов требует prune и остальных защит. Предсуществовавшие сторонние связи сохраняются и не присваиваются этому owner. При первом назначении existing auth role требуется только владение новой связью; саму auth role роль не принимает и никогда не удаляет.

Стабильный `id` сопоставляется Vault UUID. Переименование entity сохраняет личные пути. Смена login/auth mount, UUID или accessor требует отдельной миграции; aliases никогда не переносятся и entities не объединяются.

### Права KV v2

| Permission | API prefix | Capabilities |
| --- | --- | --- |
| read / write / patch | data | read / create+update / patch |
| list / read_metadata / update_metadata | metadata | list / read / create+update |
| delete_latest | data | delete |
| delete_versions / undelete_versions / destroy_versions | delete / undelete / destroy | update |
| delete_metadata | metadata | delete |

Subtree даёт отдельные правила для самого пути и `/*`, поэтому `prod` не захватывает `production`. Exact+list отклоняется. Родительские LIST не выдаются автоматически. `read` допускает исторические версии; write не даёт destroy. `delete_metadata` удаляет все версии; destroy необратим. Роль лишь выдаёт эти права, не выполняет операции над пользовательскими секретами. Vault UI может потребовать дополнительных навигационных прав; гарантируется API-доступ по известному пути.

Personal policy по умолчанию (`identity_source: entity_id`) использует буквальный `{{identity.entity.id}}/*` под data/metadata выбранного mount; корень `<entity-id>` не используется. Режим `identity_source: ldap_login` использует LDAP alias пользователя и необязательный path_prefix, как описано ниже. LIST корня mount не выдаётся. Это ACL-изоляция пользователей, а не криптографическая защита от администратора.

### Именованные личные пути LDAP: users/dep1/alice и users/dep1/bob

Индивидуальные grants уже поддерживают такие пути. В inventory задаются mount `users` и относительный путь `dep1/alice` или `dep1/bob`; разделитель — `/`. Mount `users` должен входить в `vault_configuration_config_mounts`, LDAP auth mount — быть настроен с `username_as_alias: true`.

Пример для LDAP-пользователей, у которых ещё нет entities/aliases в Vault. Объедините эти объявления с остальными users/grants вашего inventory:

```yaml
vault_configuration_users:
  - id: ldap-alice
    name: ldap-alice
    source: external
    aliases: [{auth_mount: ldap, name: alice}]
  - id: ldap-bob
    name: ldap-bob
    source: external
    aliases: [{auth_mount: ldap, name: bob}]

vault_configuration_grants:
  - id: alice-private
    subjects: [{kind: user, id: ldap-alice}]
    paths:
      - {mount: users, path: dep1/alice, scope: subtree, permissions: [read, write, list]}
  - id: bob-private
    subjects: [{kind: user, id: ldap-bob}]
    paths:
      - {mount: users, path: dep1/bob, scope: subtree, permissions: [read, write, list]}
```

Alice получает доступ, например, к `users/dep1/alice/mail`, Bob — к `users/dep1/bob/mail`. Эти grants не дают доступа к чужой области; изоляция предполагает отсутствие других политик, разрешающих пользователю более широкий доступ к `users`. Для удаления последней версии можно явно добавить permission `delete_latest`.

Если пользователи уже входили через LDAP, их entities и aliases могут существовать. Текущая роль не выбирает автоматически существующую entity по LDAP-логину и не переносит alias между entities. Для точечного назначения используйте реальный UUID существующей entity в `subjects: [{kind: user, uuid: "<UUID entity Alice>"}]`, не объявляя её повторно в users; либо выполните явное adoption существующей entity по правилам роли. Это требует знания существующих identities и неудобно для массового сценария.

Пустые каталоги в KV не создаются: роль выдаёт права, а путь становится видимым после первой записи секрета. LIST родительских каталогов для навигации в GUI задаётся отдельно через discovery_paths и раскрывает имена соседних ключей. `personal_access` с UUID-путями не формирует именованные пути `dep1/alice`.

### Массовый вариант: одна шаблонная политика для LDAP-группы

Роль генерирует policy с подстановкой LDAP-логина через `identity_source: ldap_login`. Одна политика, назначенная внешней Identity Group отдела `dep1`, выдаёт каждому участнику собственный путь: Alice — `users/dep1/alice/*`, Bob — `users/dep1/bob/*`. Пользователей не нужно перечислять в inventory, отслеживать их первый вход или вручную собирать UUID. Уже существующие entities/aliases используются самим Vault; роль их не переносит и не объединяет.

```yaml
vault_configuration_personal_access:
  enabled: true
  identity_source: ldap_login
  auth_mount: ldap
  mount: users
  path_prefix: dep1
  subjects:
    - {kind: group, id: ldap-dep1}
  permissions: [read, write, list]
```

Здесь `ldap-dep1` — inventory ID объявленной группы, например `type: external` с alias LDAP-группы отдела. Также допустимы внутренние группы и ссылки на существующие группы по UUID. У участника должен быть LDAP alias указанного auth mount; без него шаблонная policy не даёт доступа. Другие policies могут предоставлять дополнительные права.

| Поле personal_access | Контракт |
| --- | --- |
| `identity_source` | `entity_id` (default, прежний UUID-вариант) или `ldap_login` |
| `auth_mount` | Обязательный путь auth method типа ldap в LDAP-режиме; accessor определяется ролью |
| `path_prefix` | Относительный путь, например `dep1` или `department/team`; default `""` даёт `users/<логин>/*`. Только безопасные сегменты без шаблонов и wildcard; поле используется только в LDAP-режиме |
| `subjects` | Для ldap_login — `user` или `group` с id/uuid; для entity_id — только пользователи |
| `mount`, `permissions` | Выбранный KV v2 mount и обычные permissions роли |

В LDAP-конфигурации требуется `username_as_alias: true`. Роль проверяет тип auth method и этот параметр до записи. Если auth mount создаётся в том же apply, сначала создаётся и настраивается LDAP, затем его реальный accessor подставляется в policy. В dry для нового auth mount видна отложенная ссылка `$ldap_personal_policy`/`$ref`; это описание ещё не выделенного accessor, а не содержимое, отправляемое в Vault. Если LDAP уже настроен, в плане сразу виден итоговый HCL.

Пример с условным accessor `auth_ldap_a1b2c3d4`:

```hcl
path "users/data/dep1/{{identity.entity.aliases.auth_ldap_a1b2c3d4.name}}/*" {
  capabilities = ["create", "read", "update"]
}

path "users/metadata/dep1/{{identity.entity.aliases.auth_ldap_a1b2c3d4.name}}/*" {
  capabilities = ["list"]
}
```

Accessor вручную в inventory не задаётся. Это права на секреты внутри личного префикса, например `users/dep1/alice/mail`; отдельный секрет непосредственно на `users/dep1/alice` не разрешается. Корень `users` и каталог `dep1` для LIST не открываются. Для удаления последней версии добавьте permission `delete_latest`.

Один объект `personal_access` генерирует одну policy для одной комбинации mount/auth_mount/path_prefix; все subjects получают эту policy. На новых LDAP-участников выбранной группы права распространяются при входе без повторного apply. `enabled: false` снимает управляемое назначение. При смене сохранённого accessor роль требует явной миграции; auth mounts она не удаляет.

Export восстанавливает identity_source, auth_mount, path_prefix, permissions и subjects. Accessor исходного кластера не переносится в inventory: при импорте роль использует accessor целевого LDAP mount. Ручная правка templates или смешение разных личных префиксов/accessors в одной policy отклоняются при строгом экспорте.

Логины должны быть пригодны для одного сегмента ключа: без `/`, `\`, ACL wildcard и значений `.`/`..`. Роль не перечисляет всех пользователей LDAP для проверки логинов; формат задаётся правилами каталога. Переименование или повторное использование логина требует учёта, поскольку именованный путь связан с логином, а не неизменным UUID. Для UUID-путей прежний `identity_source: entity_id` сохраняется.

Готовый фрагмент для [LDAP-примера](examples/ldap-openldap.yml): [ldap-personal-access.yml](examples/ldap-personal-access.yml). Шаблоны `{{identity...}}` по-прежнему нельзя передавать в обычный grant `paths[].path`. Для назначения уже существующей внешней policy остаётся `existing_policies`; для описанного personal_access создавать HCL отдельно не требуется. Синтаксис Vault-подстановок: [Vault templated policies](https://developer.hashicorp.com/vault/docs/concepts/policies).

## Режимы, diff и теги

`dry` читает API, строит план и сохраняет YAML-отчёт на execution host (по умолчанию контроллере). Отчёт содержит `mode`, `plan.operations`, `plan.warnings`, `plan.digest` и `summary` с разделами «Планируем добавить», «Планируем изменить», «Планируем удалить». В `plan.operations` попадают только изменения: `create`, `update`, `detach`, `delete`, `forget`. Неизменяемые объекты (`noop`) исключены и из YAML, и из вывода dry; при отсутствии изменений список равен `[]`. Полный внутренний план используется при расчёте digest и применении. Файл создаётся атомарно с правами 0600, без токенов и паролей. Реестр и Vault не изменяются; `changed` отражает только создание/изменение файла отчёта. Одинаковый повторный dry не меняет файл. `--check` не требуется.

Имя и полный путь задайте в inventory:

```yaml
vault_configuration_config_mode: dry
vault_configuration_config_report_destination: "{{ inventory_dir }}/vault-dry-result.yml"
```

При отсутствии переопределения роль использует `{{ playbook_dir }}/vault-configuration-{{ inventory_hostname }}-dry.yml`. В inventory примера redos8 путь переопределён на `.state/dry-result.yml` только для режима dry. Каталог создаётся при необходимости; путь отчёта не должен совпадать с реестром, backup, lock или другими выходными файлами.

`apply` планирует, повторно читает состояние и затрагиваемые объекты, проверяет capabilities, затем применяет. `--check` строит прогноз без записи реестра/отчётов/Vault; даже при режиме dry YAML-файл не записывается. `--diff` возвращает before/after несекретных полей. Отдельный action plugin публикует безопасный отчёт и native Ansible diff после задачи с `no_log`. При dry diff также включается в YAML-отчёт.

Задача `Publish the sanitized result` показывает отчёт при обычной verbosity стандартного callback, без `-v`: mode, plan, summary и результат применения. При `changed=0` изменений не выполнено; summary показывает планируемые операции, а noop в plan означает совпадение с текущим состоянием. Пропуск задачи `Report failure…` означает отсутствие ошибки. Каждая переменная credentials должна быть объявлена в YAML только один раз: при дубликатах Ansible использует последнее значение.

Digest включает целевое несекретное состояние, UUID/accessors, snapshot и реестр. Режим запуска не входит в digest, пароли и их хеши не входят; ротация представлена revision. Изменение `vault_configuration_config_expected_plan_digest` не меняет вычисление самого digest.


## Владение, adoption и prune

Реестр принадлежит execution host, конкретному cluster_id и owner; права 0600, атомарная запись через fsync/replace, предыдущий файл `.bak`. Реестры всех owner одной области храните в одном выделенном каталоге. Общая локальная блокировка этого каталога сериализует apply, а peer registries проверяются на конфликты объектов и связей. Между execution hosts общей блокировки нет: сериализуйте CI jobs для всего Vault/области.

Entity/group metadata `vam_owner` и `vam_id` дополняют реестр. Префикс policy не доказывает владение. При существующем объекте без записи dry завершается с UUID/хешем для ручной проверки; после проверки добавьте точный adoption. Защищённые объекты нельзя изменять и через adoption. Чужая metadata/реестр блокируют принятие. Формат — [schemas/state.schema.json](schemas/state.schema.json).

Удаление сначала снимает управляемые связи, затем aliases/accounts/objects. Prune блокируется при известных сторонних memberships, aliases или policy bindings. API не позволяет доказать отсутствие всех сторонних потребителей и старых токенов: дополнительно обязательны актуальный hash и `dependencies_cleared: true` для policy/entity/group. Устраните зависимости до подтверждения. Данные KV при удалении пользователей не затрагиваются.

## Сбой и восстановление

Перед каждой записью реестр сохраняет `pending` с безопасными before/desired, ожидаемой записью registry и digest; после readback добавляет подтверждённую операцию в journal. При ошибке отчёт содержит `confirmed` и `uncertain`. Автоматического rollback или повторов записи после timeout нет. Перед продолжением роль снова читает API.

1. Остановите параллельные apply. Сохраните повреждённый/неполный реестр и `.bak` защищённым способом.
2. Сверьте cluster_id и фактические объекты. Для повреждённого JSON восстановите проверенную `.bak` по тому же пути с mode 0600; автоматического fallback нет.
3. При `pending` задайте `vault_configuration_config_management_recovery_digest: <из отчёта>` и `vault_configuration_config_management_recovery_outcome: applied` после подтверждения результата. `not_applied` допустим только при точном совпадении API с before; операция с паролем требует операторского разрешения как applied после проверки/ручной корректировки credentials.
4. После успеха уберите recovery. При полной потере реестра заново выполняйте adoption с текущими UUID/хешами. Нельзя принимать объекты только по префиксу или имени.

При потерянном ответе смены пароля проверьте пароль отдельно или выполните контролируемую ручную ротацию, затем подтвердите revision. Пароль невозможно проверить чтением API. Совпавшая revision не обнаруживает внешнюю смену пароля.

## Экспорт

```yaml
vault_configuration_config_mode: export
vault_configuration_config_connection_address: https://vault.example.org:8200
vault_configuration_config_management_owner: platform-team
vault_configuration_config_management_policy_prefix: vam-platform-
vault_configuration_config_management_state_file: /var/lib/ansible/vault-access/platform-state.json
vault_configuration_export:
  scope: managed
  destination: ./vault-access-manager-export.yml
  audit_destination: ./vault-access-manager-audit.json
  allow_partial: false
```

Export читает фактический API, включая ручные изменения собственных ACL, и обратимо преобразует поддерживаемые KV v2 blocks. Вывод — непосредственно `vault_configuration_*` variables в обычном YAML с mappings/lists, пригодный для `vars_files`, без connection/credentials/исходных UUID/accessors/ownership. Audit хранится отдельно в JSON-файле `.audit.json`. Оба файла 0600. `--check` только проверяет необходимость записи, не создавая файлов.

Поля `vault_configuration_export`: `scope: managed|scoped`, `destination`, `audit_destination` (default destination + `.audit.json`), `allow_partial` (false), фильтры `mounts`, `auth_mounts`, `entities`, `groups`, `policies`, `auth_roles`, `users`. В scoped identities выбираются по UUID или имени, auth roles и standalone userpass — по `auth_mount/name`; policies — по имени. Групповые зависимости и текущие subjects выбранных policies включаются автоматически. Managed выбирает объекты owner, также независимые identities, а не только участников grants.

Неподдерживаемые HCL, непривязанные policies, потерянные зависимости или несколько локальных логинов одной entity вызывают ошибку до записи. `allow_partial: true` создаёт явно неполный audit export; его нельзя считать резервной копией всех прав. Прямые userpass token policies не переводятся в entity grants, поскольку изменили бы смысл. Existing policies и существующие auth roles перечисляются как внешние зависимости целевой среды. Системные объекты исключены.

Userpass password нельзя прочитать. Export содержит `password: "{{ vault_configuration_passwords.get('alice', '') }}"`; задайте словарь секретов отдельно через Ansible Vault/inventory или lookup в variables. Для нового пользователя без пароля возникает ошибка до мутаций. Для существующего on_create пользователя отсутствие пароля допустимо. Новый Vault назначает собственные UUID; содержимое personal KV переносится отдельной процедурой, в эту роль она не входит. На исходном Vault чужие объекты при импорте требуют adoption; export владение не меняет.

## Credentials, bootstrap и offboarding

Роль использует **один `vault_configuration_token` для всех API-запросов**: чтения текущего состояния, создания mounts, настройки LDAP/AD, userpass, Identity, ACL и назначений существующим auth roles. Один запуск `apply` выполняет все необходимые изменения; отдельного bootstrap-этапа внутри роли и второго токена нет. Vault должен быть заранее установлен, initialized и unsealed.

[files/bootstrap-policy.hcl](files/bootstrap-policy.hcl) — готовая административная политика для этого токена. Она не зависит от имён mounts, вложенности auth paths и `vault_configuration_config_management_policy_prefix`. Изменения inventory не требуют перегенерации политики. Политика разрешает управление ACL, Identity и auth API, создание и настройку secret/auth mounts; `delete` на `sys/mounts/*` и `sys/auth/*` не предоставляется. Прямые права на пользовательские KV data не выдаются. Это доверенный администратор кластера: доступ к `auth/*` включает управление токенами и другими credentials, а изменение ACL позволяет расширить собственные права. Ограничения inventory не являются границей безопасности для владельца токена.

### Создание токена через root token

Выполните один раз на Ansible-контроллере или административной машине с Vault CLI, из корня этого репозитория. Root token нужен только для установки политики и выдачи административного токена. Не указывайте root token литералом в командной строке; `read` ниже запрашивает его без отображения (Bash).

```bash
export VAULT_ADDR='https://vault.example.org:8200'
export VAULT_CACERT='/path/to/vault-ca.pem'
read -r -s -p 'Vault root token: ' VAULT_TOKEN
printf '\n'
export VAULT_TOKEN

vault policy write vault-configuration-admin \
  roles/vault-configuration/files/bootstrap-policy.hcl

VAULT_CONFIGURATION_TOKEN="$(vault token create \
  -policy=vault-configuration-admin \
  -no-default-policy \
  -orphan \
  -ttl=8h \
  -explicit-max-ttl=8h \
  -renewable=false \
  -field=token)"
export VAULT_CONFIGURATION_TOKEN
unset VAULT_TOKEN
```

Токен привязан только к `vault-configuration-admin` и имеет срок действия не более восьми часов. `-orphan` отделяет его жизненный цикл от root token. Параметры описаны в [Vault token create](https://developer.hashicorp.com/vault/docs/commands/token/create). Сохраните токен в выбранном защищённом источнике, если последующие запуски будут выполняться из другой сессии. По истечении срока выдайте новый токен с той же политикой; роль не выполняет login или renewal.

В переменных конкретного кластера укажите этот токен, например через окружение контроллера:

```yaml
vault_configuration_token: "{{ lookup('ansible.builtin.env', 'VAULT_CONFIGURATION_TOKEN') }}"
vault_configuration_config_mode: apply
vault_configuration_config_connection_address: https://vault.example.org:8200
vault_configuration_config_connection_ca_file: /path/to/vault-ca.pem
```

Задайте остальные параметры кластера и желаемые LDAP/groups/grants в inventory, затем запустите свой playbook с ролью. Допускается сразу `apply`; предварительный `dry` необязателен. Альтернатива env lookup — хранить `vault_configuration_token` в зашифрованном Ansible Vault vars-файле. CLI и root token при выполнении роли не нужны. После проверки выданного доступа отзовите initial root token согласно вашей процедуре; orphan token останется действителен до собственного отзыва или истечения TTL.

Источники credentials выбираются в variables. `defaults/main.yml` содержит пример необязательного community.hashi_vault lookup; lookup-плагин нужен только при выборе этого источника. Первый automation token не должен зависеть от доступа к тому же ещё недоступному Vault. TLS verification включена; redirects никогда не следуются, включая HA. Используйте hostname из SAN и load balancer, направляющий на active node. CA/client cert/key уже существуют на execution host.

Offboarding: отключите entity, снимите управляемые grants/memberships, удалите локальный login при необходимости. Удаление userpass само по себе не отзывает ранее выданные токены. Прямые token policies и identity policies имеют различную семантику обновления; внешние группы могут обновиться после нового login/renewal. Отдельно выполните установленную в организации процедуру отзыва сессий; роль не ищет и массово не отзывает токены. Удаление entity не стирает её личные данные и не передаёт их новому UUID.

## Проверки

```sh
python3 -m unittest discover -s roles/vault-configuration/tests/unit -v
python3 -m unittest discover -s roles/vault-configuration/tests/integration -v
cd roles/vault-configuration
molecule test -s default
molecule test -s ha
```

Интеграционные тесты запускают собственные временные Vault и TokenReview API только на localhost, используют openssl для подписания JWT и тестового TLS. Они не используют переменные VAULT_ADDR/VAULT_TOKEN. HA проверяет три Raft voters и работу после потери active node. Molecule использует Docker с закреплённым digest; dev mode применяется только в default-тесте, HA использует initialized/unsealed Raft. Результаты и объективные границы покрытия — в TEST-REPORT.md. Production Vault тестами не затрагивается.

## Создание mounts и LDAP / Active Directory

Для пользователей с `source: userpass` роль сама создаёт отсутствующий auth mount из `auth_mount`. Несколько пользователей одного mount используют одно создание. Существующий mount другого типа, пересечение путей или смена сохранённого accessor вызывают отказ до записи. Создание входит в общий dry/apply-план и журнал восстановления; prune никогда не удаляет auth mount.

`vault_configuration_config_mounts` теперь задаёт KV v2 mounts, которые нужно обеспечить. Отсутствующие входят в план создания; apply создаёт их до ACL/identities, dry/check только планируют. Если имя занято KV v1 или другим engine, роль отказывает до изменений. Пересекающиеся пути mounts запрещены. Список можно оставить пустым для LDAP-only конфигурации. Удаление mounts запрещено в планировщике, executor и REST-клиенте; оно не появляется при prune, исчезновении имени из inventory или удалении реестра.

Теги роли: `pre-req` (и `always`), `config`. Задачи локальной очистки полностью удалены. Локальный реестр и отчёты сохраняются до явных действий оператора.

Новые переменные:

| Переменная | Контракт |
| --- | --- |
| `vault_configuration_ldap` | Не задано — не управлять LDAP/AD; список интеграций ниже |
| `vault_configuration_ldap_passwords` | `{}`; bind-пароли по стабильному `ldap[].id`, из Ansible Vault/inventory/необязательного lookup в variables |

Интеграция содержит `id`, `auth_mount`, `config`. Отсутствующий auth mount создаётся с типом ldap; существующий другой тип не переиспользуется. У уже настроенной чужой конфигурации нужно явное adoption `{kind: ldap_config, id: ..., hash: ...}`. Accessor сохраняется в реестре; его смена требует миграции. Пустой список LDAP или prune **не удаляет** LDAP config/auth mount. Сначала включается auth, затем применяется конфигурация, после чего создаются aliases и связи.

`config` принимает `url`, `binddn`, `userdn`, `userattr`, `userfilter`, `groupdn`, `groupattr`, `groupfilter`, `upndomain`, `certificate` (PEM CA), `starttls`, `insecure_tls`, `tls_min_version`, `tls_max_version`, `discoverdn`, `deny_null_bind`, `anonymous_group_search`, `case_sensitive_names`, `username_as_alias`, `use_token_groups`, `enable_samaccountname_login`, `dereference_aliases`, `max_page_size`, `connection_timeout`, `request_timeout`. Обязательны URL, userdn и groupdn. TLS version — tls12/tls13; для новой интеграции verification включена, username_as_alias true и case_sensitive_names false. Пользователи AD/LDAP уже существуют в каталоге; роль не меняет их пароли и членство.

При непустом binddn обязателен `bind_password_revision` и пароль в `vault_configuration_ldap_passwords[id]` для первой записи/смены revision или binddn. API не возвращает bind-пароль, поэтому revision управляет явной ротацией; повторный apply не требует секрета при совпавшей revision и не меняет пароль. Значение и хеш пароля не попадают в plan/diff/state/export. После потерянного ответа действует обычный pending/recovery протокол. Клиентские приватные TLS-ключи LDAP и server-side rotate-root этой ролью не управляются.

Примеры: [LDAP](examples/ldap-openldap.yml), [Active Directory](examples/ldap-ad.yml). В AD используется userattr samaccountname, groupattr cn и фильтр вложенных групп `member:1.2.840.113556.1.4.1941:`. `certificate` берётся из локального CA-файла через lookup в переменных; для StartTLS используйте ldap:// и starttls true. Чистый ldap:// допустим лишь с явным `allow_insecure_ldap: true` для тестового контура.

Права назначаются через обычные external Identity groups с alias `{auth_mount: ad, name: payments-prod}` и grants на эту группу. Имя alias должно совпадать с тем, что возвращает LDAP groupattr; при case_sensitive_names false используйте lowercase. Инвентарное membership внешней группе не задаётся: членство определяется каталогом при входе пользователя. Необязательный external user с alias может заранее закрепить пользователя LDAP за стабильной entity.

### Два механизма прав LDAP и отображение в GUI

Vault поддерживает два способа назначения прав пользователям LDAP. Настраивать оба для одной задачи не требуется:

| Механизм | Где задаются права | Где смотреть в GUI | Когда применяется |
| --- | --- | --- | --- |
| Прямое сопоставление LDAP-групп и policies | `auth/ldap/groups/<имя LDAP-группы>` | Authentication methods → ldap → Groups | Простые назначения, относящиеся к одному LDAP auth method |
| Identity Groups и group aliases | `identity/group` и `identity/group-alias` | Access → Groups | Общие права для локальных пользователей и разных auth methods, вложенные группы |

**Эта роль использует Identity Groups.** Она создаёт внешние группы, связывает их aliases с LDAP-группами и назначает policies через `vault_configuration_grants`. Записи `auth/ldap/groups/*` для этих назначений не создаются. Поэтому список Groups внутри LDAP auth method может быть пустым, хотя права успешно работают. Этот список не является перечнем всех групп каталога LDAP.

В примере redos8 в **Access → Groups** должны быть внешние группы `ldap-developers` и `ldap-operators`. У первой alias — `developers`, auth mount — `ldap`; у второй alias — `operators`. Назначенные policies смотрите на этих Identity Groups. При входе Vault получает LDAP-членство пользователя и сопоставляет его с group aliases; членство обновляется при последующем login/renewal. Описание механизмов: [LDAP group → policy mapping](https://developer.hashicorp.com/vault/docs/auth/ldap) и [Identity external/internal groups](https://developer.hashicorp.com/vault/docs/concepts/identity).

### Полный DN, имя группы и поиск по части имени

При используемом в примерах `groupattr: cn` в `alias.name` задаётся точное значение CN, которое возвращает LDAP auth method. Для группы `cn=developers,ou=groups,dc=example,dc=org` alias должен называться `developers`. Полный DN, строка `cn=developers` и шаблон `dev*` не являются эквивалентами этого alias.

| Поле | Назначение | Пример |
| --- | --- | --- |
| `config.groupdn` | Полный DN базы поиска групп | `ou=groups,dc=example,dc=org` |
| `config.groupfilter` | LDAP-фильтр поиска групп, учитывающий членство пользователя | `(&(objectClass=groupOfNames)(member={{.UserDN}}))` |
| `config.groupattr` | Атрибут для получения имени группы | `cn` |
| `vault_configuration_groups[].alias.name` | Точное имя группы для сопоставления с Identity Group | `developers` |

Поиск по части имени задаётся в `groupfilter`, например условием `(cn=dev*)`. Фрагмент `config` для OpenLDAP с `groupOfNames`:

```yaml
groupdn: ou=groups,dc=example,dc=org
groupattr: cn
groupfilter: "{{ '(&(objectClass=groupOfNames)(cn=dev*)(member={{.UserDN}}))' }}"
```

Фильтр вернёт только группы с CN, начинающимся на `dev`, в которых состоит входящий пользователь. Условие членства `member={{.UserDN}}` сохраняется: одного `(cn=dev*)` недостаточно для определения групп пользователя. Для Active Directory используйте подходящие objectClass и фильтр членства, как в [примере AD](examples/ldap-ad.yml).

**Фильтрация поиска не создаёт wildcard alias.** Например, найденным `developers` и `devops` нужны отдельные внешние Identity Groups с aliases `developers` и `devops`. Их можно включить в общую внутреннюю группу и назначить права один раз. Роль не перечисляет LDAP-группы по маске для автоматического создания aliases.

Если одноимённые CN существуют в разных OU, ограничьте базу `groupdn` и/или условия `groupfilter`, чтобы выбирать нужные группы; запись полного DN в `alias.name` при `groupattr: cn` не решает неоднозначность. Параметры поиска описаны в [LDAP auth method](https://developer.hashicorp.com/vault/docs/auth/ldap).

### Общая группа для локальных и LDAP-пользователей

Префикс `ldap-` в имени Vault-группы — только соглашение примера, он необязателен. Имя внешней группы Vault может отличаться от имени LDAP-группы; с LDAP сопоставляется именно `alias.name`. Значение `id` служит стабильной ссылкой внутри inventory.

В `type: external` нельзя вручную добавлять локальных пользователей через `members`: членство этой группы определяется LDAP. Для общих прав создайте `type: internal`, включите в неё локальных пользователей через `members`, а внешнюю группу — через `member_groups`. Policies назначьте общей внутренней группе.

Фрагмент inventory ниже предполагает, что пользователь `local-alice` и LDAP-интеграция с auth mount `ldap` уже объявлены. При объединении фрагмента с inventory сохраните остальные объявления групп и grants. В `member_groups` используются **inventory ID**, а не LDAP DN или alias:

```yaml
vault_configuration_groups:
  - id: ldap-developers
    name: ldap-developers
    type: external
    alias: {auth_mount: ldap, name: developers}
  - id: developers
    name: developers
    type: internal
    members: [local-alice]
    member_groups: [ldap-developers]

vault_configuration_grants:
  - id: developers-apps
    subjects: [{kind: group, id: developers}]
    paths:
      - mount: apps
        path: payments/dev
        scope: subtree
        permissions: [read, write, list]
```

В результате `local-alice` и участники LDAP-группы `developers` получают один набор прав через внутреннюю Vault-группу `developers`. Дублировать этот grant во внешней группе или в `auth/ldap/groups/developers` не требуется.

Go templates в LDAP filters нужно сохранить буквально через Ansible: примеры содержат выражения вида `"{{ '(&(objectClass=group)(member={{.UserDN}}))' }}"`. Export экранирует такие значения для повторного vars_files. Managed export включает принадлежащие owner LDAP configs; scoped export выбирает их через `vault_configuration_export.ldap: [ad]`. Bind-пароли остаются отдельной внешней зависимостью по id.

`pre-req` проверяет имена настроек/область исполнения; полную схему, ссылки и типы модуль проверяет до первой мутации. Необязательные users/groups/grants должны сохранять различие между отсутствием и `[]`, поэтому только для них остаётся `default(omit)`. Для настроек с defaults повторные default-фильтры убраны. Export и reconcile теперь отдельные include-задачи: export вообще не получает passwords/ldap_passwords и desired sections и не вычисляет их lookups.

Скрипт постоянного тестового стенда Vault 2.0.4 из RPM РЕД ОС 7.3: [scripts/README.md](../../scripts/README.md), [deploy-test-vault-redos73.py](../../scripts/deploy-test-vault-redos73.py). Он не входит в API-роль и запускается отдельно на выделенном тестовом узле.

LDAP config также поддерживает token_ttl, token_max_ttl, token_explicit_max_ttl, token_period, token_num_uses, token_no_default_policy, token_type и token_bound_cidrs. Прямые LDAP token_policies не назначаются: используйте grants на Identity groups. Непредставимые прямые LDAP token policies обнаруживаются при export. Имена directory aliases допускают Unicode без управляющих символов; для LDAP group aliases при case_sensitive_names false роль нормализует регистр в lowercase. Логические KV paths и стабильные inventory IDs остаются ASCII.
