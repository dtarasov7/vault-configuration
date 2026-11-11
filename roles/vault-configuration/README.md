# vault-configuration

Версия: [1.3.0](VERSION). Ansible-роль декларативной настройки Vault через API: KV v2 mounts, Identity entities/groups/aliases, userpass, LDAP/AD, ACL и назначения существующим AppRole/Kubernetes/JWT/OIDC roles. Роль не устанавливает Vault и не читает содержимое пользовательских KV-секретов.

## Target и место исполнения API

Playbook и `--limit` должны выбрать ровно один target. `inventory_hostname` — DNS-имя Vault, совпадающее с сертификатом; `ansible_host` используется только для SSH. Пример:

```ini
[vault]
vault01.example.org ansible_host=192.0.2.10 ansible_user=ansible
```

```yaml
- name: Configure Vault
  hosts: vault
  gather_facts: false
  roles:
    - vault-configuration
```

`gather_facts: false` позволяет работать без SSH, если API доступен с контроллера. Даже `hosts: all` допустим, если после inventory/limit остался один host. В `pre-req` проверяется `ansible_play_hosts_all`, а не размер текущего serial batch.

```yaml
vault_configuration_api_execution: controller  # controller или target
vault_configuration_api_scheme: https
vault_configuration_api_port: 8200
vault_configuration_api_use_loopback: false
```

Адрес — `<scheme>://<inventory_hostname>:<port>`. `controller` выполняет API-код локально, без SSH к target, даже если у него задан ansible_host для SSH. `target` запускает модуль через connection inventory; запрос к Vault идёт уже с target. Python со стандартной библиотекой нужен на выбранном хосте. PyYAML нужен только на Ansible-контроллере. API-модуль выполняется без become: административные права предоставляет токен, а не root ОС.

Для сервера, доступного по SSH, но недоступного с контроллера на порту API:

```yaml
vault_configuration_api_execution: target
vault_configuration_api_use_loopback: true
vault_configuration_config_connection_validate_tls: false
```

В этом случае URL использует `127.0.0.1`. Loopback разрешён только для target и сам не отключает проверку TLS. При сертификате только на DNS-имя проверку можно явно отключить, как выше; HTTPS продолжает шифровать соединение. Если loopback выключен, используется DNS-имя target. Явный `api_scheme: http` разрешает HTTP без отдельного флага.

`vault_configuration_config_connection_ca_file`, `client_cert`, `client_key` — существующие пути на хосте исполнения API. Роль не копирует их между хостами. `lookup('file', ...)` в переменных выполняется на контроллере независимо от места API-кода.

## Переменные и результаты

Все входные переменные, default и русские пояснения: [defaults/main.yml](defaults/main.yml). Машиночитаемый контракт: [schemas/inventory.schema.json](schemas/inventory.schema.json). Переменные соединения и экспорта плоские. Необязательные CA/mTLS пути и expected_plan_digest имеют default `null`.

`vault_configuration_token` — один существующий административный токен для dry/apply/export и matrix с источником cluster. `vault_configuration_passwords` содержит пароли по users[].id, `vault_configuration_ldap_passwords` — bind-пароли по ldap[].id. Значения задаются в защищённом inventory/Ansible Vault; lookup остаётся в переменных. У роли нет login/renewal/переключения токенов.

`vault_configuration_users`, `groups`, `grants`, `auth_roles`, `personal_access`, `ldap` по умолчанию равны `null`: раздел не управляется. Явный `[]` для списков задаёт пустое желаемое состояние; это не команда удаления объектов. `vault_configuration_result` и `vault_configuration_context` — выходы задач, не входные defaults.

Файлы dry/export/matrix всегда записываются **на Ansible-контроллере**. Относительные пути считаются от `playbook_dir`, даже при API-коде на target. Права новых каталогов — 0700, файлов — 0600; запись атомарная, symlink назначения отклоняется. В `--check` файлы не создаются, но changed прогнозируется.

- `dry`: YAML по `vault_configuration_config_report_destination`; default `{{ playbook_dir }}/vault-configuration-{{ inventory_hostname }}-dry.yml`. В обычном dry путь обязателен. Только create/update; noop скрыты. Есть summary, предупреждения и digest полного плана.
- `apply`: применяет план; JSON-отчёт включается явным report_destination. Для согласованного плана можно задать `vault_configuration_config_expected_plan_digest` из dry.
- `matrix`: CSV назначений прав KV v2 и пояснения; источник cluster либо inventory.
- `export`: YAML переменных и отдельный JSON-аудит на контроллере. API-модуль не создаёт файлов на target. Changed отражает изменение файлов; экспорт не изменяет Vault.

```yaml
vault_configuration_config_mode: export
vault_configuration_export_scope: managed
vault_configuration_export_destination: ./vault-access-manager-export.yml
vault_configuration_export_audit_destination: ./vault-access-manager-export.yml.audit.json
vault_configuration_export_allow_partial: false
```

Фильтры экспорта имеют префикс `vault_configuration_export_`: mounts, auth_mounts, entities, groups, policies, auth_roles, users, ldap. Для scoped entities/groups выбираются по имени/UUID, roles/users — по `auth_mount/name`, ldap — по auth mount. Managed выбирает entities/groups по `vam_owner`/`vam_id`, политики по префиксу, связанные аккаунты и LDAP-конфигурации по алиасам своих identities. Изолированный LDAP backend без своих алиасов экспортируется явно через scoped/ldap. LDAP id при экспорте выводится из пути auth mount; bind-пароли задаются внешним словарём по экспортированному id.

Экспорт читает фактические ACL и поддерживаемые поля, включая ручные изменения. Непредставимые HCL, прямые token policies и потерянные зависимости вызывают ошибку; allow_partial явно допускает неполный экспорт с аудитом причин. Пароли, connection settings, исходные UUID/accessors и ownership не переносятся в инвентарь. Go templates экранируются для vars_files. Неуправляемые политики становятся внешними зависимостями. Это экспорт конфигурации доступа, а не резервная копия KV-данных.

## Работа без реестра

Локального реестра, backup и recovery-журнала нет. Каждый запуск использует только inventory и текущий Vault. Разные контроллеры и CI/CD работают с одинаковым результатом при одном inventory/owner/prefix. Старые registry-файлы не читаются и не удаляются.

- Владелец и стабильный id сущности/группы хранятся в metadata `vam_owner` и `vam_id`. По ним находится UUID, поэтому переименование сохраняет сущность. Дубликаты id и чужой владелец отклоняются.
- Существующая немаркированная сущность/группа требует явного принятия через `vault_configuration_config_management_adoption: [{kind: entity, id: alice, uuid: ...}]` либо hash текущего объекта. Чужие ownership-метки не перезаписываются.
- ACL-политики определяются префиксом `vault_configuration_config_management_policy_prefix` и стабильным хешированным именем. Разные владельцы обязаны использовать разные префиксы. Смена owner/prefix — миграция, а не переименование параметра.
- Если grants задан, его назначения политик своего префикса полностью согласуются со всеми текущими субъектами, включая отсутствующих в users/groups. Политика personal управляется отдельно, только если задан personal_access. При `grants: []` свои обычные назначения снимаются, чужие политики сохраняются.
- `existing_policies` вне своего префикса добавляются по явному объявлению, но при исключении из inventory автоматически не снимаются: отличить ручное назначение без истории нельзя.
- Объявленная **внутренняя** группа имеет полный состав members/member_groups из inventory. Для неё ручные участники, не указанные в объявлении, снимаются. Внешним членством LDAP управляет auth backend. Общий субъект по UUID получает только изменения политик, его metadata и членство сохраняются.
- Пользователи, группы, алиасы, политики и mounts автоматически не удаляются. Для пользователя можно явно задать disabled; personal_access.enabled=false снимает свои персональные назначения. Пустой users/groups сохраняет существующие объекты. Отсутствующие KV/auth mounts создаются; несовместимые типы и пересечение путей отклоняются.

API Vault не предоставляет общей транзакции/CAS для всех этих объектов. **Сериализуйте apply на один кластер средствами CI/CD**; внутренних распределённых блокировок нет. Перед применением проверяется drift снимка и каждого затрагиваемого объекта, но это не заменяет сериализацию.

При ошибке отчёт содержит confirmed и uncertain. Автоматических повторов и rollback нет. После потери ответа проверьте фактическую конфигурацию и заново выполните dry. Новый запуск обнаружит уже созданные объекты по метаданным. Для секретных записей нельзя определить прочитанное обратно значение пароля.

## Пароли без истории ревизий

Userpass `password_policy` и LDAP `bind_password_policy`:

| Значение | Поведение |
| --- | --- |
| `on_create` (default) | Пароль нужен при создании. Для LDAP также при смене binddn. Повторный запуск существующего объекта не меняет пароль и может выполняться без его значения. |
| `always` | Явно записывать переданный пароль при каждом apply. Повтор всегда changed; используйте для управляемой смены или исправления пароля. |

Изменение строки пароля в inventory при on_create само по себе ничего не меняет. Для смены явно используйте always, затем верните on_create. Пароли и их хеши не записываются в отчёты. После потери ответа на password-write проверьте аутентификацию; роль не повторяет запрос автоматически. Поля password_revision/bind_password_revision и режим on_revision удалены.

## KV v2 permissions

| Permission | API prefix | Capabilities | Что разрешает |
| --- | --- | --- | --- |
| `read` | data | read | Читать содержимое последней или указанной версии секрета. |
| `write` | data | create, update | Создавать секрет и записывать новые версии его содержимого. |
| `patch` | data | patch | Частично обновлять существующий секрет через PATCH с созданием новой версии. |
| `list` | metadata | list | Просматривать имена ключей и каталогов без чтения содержимого секретов. |
| `read_metadata` | metadata | read | Читать метаданные секрета и сведения о его версиях без их содержимого. |
| `update_metadata` | metadata | create, update | Создавать и изменять метаданные ключа: custom metadata, лимит версий, CAS и автоматическое удаление версий. |
| `delete_latest` | data | delete | Мягко удалять последнюю версию; её можно восстановить до уничтожения. |
| `delete_versions` | delete | update | Мягко удалять явно указанные версии; их можно восстановить до уничтожения. |
| `undelete_versions` | undelete | update | Восстанавливать мягко удалённые версии. |
| `destroy_versions` | destroy | update | Безвозвратно уничтожать содержимое указанных версий. |
| `delete_metadata` | metadata | delete | Безвозвратно удалять ключ, его метаданные и все версии секрета. |

### Алиасы permissions

В `grants[].paths[].permissions` и `personal_access.permissions` можно использовать сокращения:

| Алиас | Разворачивается в |
|---|---|
| `all` | Все 11 permissions из таблицы выше, включая уничтожение версий и удаление метаданных |
| `read_only` | `list`, `read`, `read_metadata` |
| `read_write` | `list`, `read`, `read_metadata`, `write`, `patch`, `update_metadata` |

`read_write` не включает удаление, восстановление и уничтожение версий. Алиасы не меняют область доступа: mount/path/scope и субъекты по-прежнему задаются отдельно. `all` предоставляет все поддерживаемые операции KV v2 на выбранном пути, а не административные права на Vault или mount.

```yaml
# Полный доступ (пользователю либо группе из subjects)
vault_configuration_config_safety_allow_destructive_grants: true
vault_configuration_grants:
  - id: infra-admin
    subjects: [{kind: group, id: infra-admins-ad}]
    paths:
      - {mount: infra, path: team, scope: subtree, permissions: all}

# Можно сочетать алиас и отдельные операции:
# permissions: [read_only, write]
# permissions: [read_write, delete_latest]
```

Допускается строка с одним правом/алиасом либо список. Пересекающиеся наборы объединяются без повторов; повтор одного и того же входного имени считается ошибкой. Алиасы раскрываются до проверки безопасности: `all` требует `allow_destructive_grants: true`, корень mount — отдельного `allow_mount_root: true`. Все три алиаса включают `list`, поэтому в grants требуют `scope: subtree`; с `scope: exact` задавайте отдельные права без `list`.

Равнозначные списки и алиасы создают одинаковые ACL и digest плана; их замена не вызывает изменений в Vault. Export выдаёт явные списки прав, matrix сохраняет 11 позиций `LRWPMUDVNXZ`. В [примере AD](examples/ldap-ad.yml) `all` используется и для infra, и для персональных путей `users/<login>/*`.

`path` — относительный путь внутри mount, `scope: exact|subtree`; subtree создаёт базовое правило и правило `/*`. Exact+list отклоняется. Для всего infra задаются `path: ""`, `scope: subtree`, `vault_configuration_config_safety_allow_mount_root: true`; destroy_versions/delete_metadata требуют `vault_configuration_config_safety_allow_destructive_grants: true`. Полный пример: [ldap-ad.yml](examples/ldap-ad.yml). Эти права не дают администрирование или удаление самого mount. LIST каталогов раскрывает имена детей; discovery_paths выдаются явно.

## LDAP/AD и личные пути

Примеры: [ldap-openldap.yml](examples/ldap-openldap.yml), [ldap-ad.yml](examples/ldap-ad.yml), [ldap-personal-access.yml](examples/ldap-personal-access.yml), [общий inventory](examples/inventory.yml). Объявленный LDAP auth_mount/config — явно управляемая настройка указанного backend; существующие неназванные backends сохраняются.

Пример AD использует auth path `ldap`, TCP Global Catalog `ldap://...:3268`, `starttls: false`, `allow_insecure_ldap: true`. Plain LDAP явно разрешён в любом окружении. LDAPS использует TLS сразу (636 либо GC 3269), StartTLS — ldap:// и starttls:true. Поле insecure_tls относится к проверке сертификата LDAP и отдельно от TLS API Vault. Binddn должен иметь право поиска пользователей/групп. Входить в GUI нужно через path ldap, а не через id интеграции corporate-ad.

`config.certificate` поддерживается и содержит **PEM-содержимое CA**, которому Vault должен доверять при проверке сертификата AD. Это не путь к файлу и не `vault_configuration_config_connection_ca_file`: последняя переменная относится к соединению API-кода роли с Vault. Например, внутри `vault_configuration_ldap[].config`:

```yaml
certificate: "{{ lookup('file', playbook_dir ~ '/files/ad-ca-chain.pem') }}"
insecure_tls: false
```

Файл читается на Ansible-контроллере, содержимое передаётся в LDAP config Vault; копировать CA-файл на target для этого варианта не требуется. Альтернатива — непосредственно PEM-блок в `certificate: |`. Пустая строка использует системное доверие сервера Vault. При plain LDAP с `starttls: false` сертификат не используется. В [примере AD](examples/ldap-ad.yml) сохранён обычный LDAP и добавлены комментарии для необязательного перехода на LDAPS/StartTLS. Описание поля: [Vault LDAP API](https://developer.hashicorp.com/vault/api-docs/auth/ldap).

В AD userattr — samaccountname, groupattr — cn; вложенные группы находятся фильтром matching rule 1.2.840.113556.1.4.1941. Groupdn задаётся полным DN базы поиска, groupfilter может ограничивать группы по части cn, но alias.name должен совпасть с результатом groupattr: это не wildcard и обычно не полный DN. При case_sensitive_names:false имена aliases нормализуются в lowercase. Для Go templates используйте Jinja-строку, как в примерах; не позволяйте Ansible вычислять {{.UserDN}}.

В [ldap-ad.yml](examples/ldap-ad.yml) также настроены **все 11 permissions** для личных каталогов без промежуточного префикса: `alice` → `users/alice/*`, `bob` → `users/bob/*`. Шаблон политики — `users/data/{{identity.entity.aliases.<accessor>.name}}/*` и соответствующие пути metadata/delete/undelete/destroy. `path_prefix: ""` убирает `dep1`, используемый в другом примере ниже.

Политика назначается external Identity group `all-ad-users` с alias `vault-users`. **Группа `vault-users` должна уже существовать в AD и включать всех нужных пользователей**; она должна попадать в `groupdn` и `groupfilter`. Роль не создаёт группу в AD и не добавляет туда участников. Не используйте `Domain Users` как автоматическую замену: текущий фильтр по `member` не учитывает членство через primary group ([описание Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/e12954a4-6865-4432-94e6-00c310ca87c0)). Можно указать другую существующую группу с подходящим явным/вложенным составом. Пользователей в `vault_configuration_users` перечислять не нужно; права заработают при их LDAP-входе, предварительный вход не требуется.

Для совпадения пути с коротким именем входите как `alice` (`sAMAccountName`), а не `DOMAIN\alice` или UPN: при `username_as_alias: true` шаблон берёт логин входа. Используйте короткие логины в нижнем регистре, согласованные с именами личных каталогов. Полные права относятся к секретам **внутри** `users/alice/`, включая уничтожение версий/метаданных; доступ к чужим каталогам, LIST корня `users` и отдельный ключ `users/alice` эта политика не выдаёт. Каталоги KV виртуальные: отдельного создания не требуется, первый секрет может быть `users/alice/mail`. Другие политики пользователя могут расширить доступ.

Роль использует **Identity Groups**: внешняя группа и group alias, связанные с directory group. Они видны в Access → Groups; список Authentication methods → ldap → Groups может быть пустым, поскольку прямые auth/ldap/groups mappings роль не создаёт. Префикс ldap- в имени необязателен. Для общей группы локальных и LDAP-пользователей создайте внутреннюю группу с локальными members и внешними member_groups; внешняя группа сама не принимает локальных участников.

```yaml
vault_configuration_personal_access:
  enabled: true
  identity_source: ldap_login
  auth_mount: ldap
  mount: users
  path_prefix: dep1
  subjects: [{kind: group, id: developers-ldap}]
  permissions: [read, write, list]
```

Политика содержит шаблон `users/data/dep1/{{identity.entity.aliases.<accessor>.name}}/*`. Accessor определяется автоматически, в том числе после создания backend. Пользователей не нужно перечислять или ждать их первого входа: alice получает users/dep1/alice/*, bob — users/dep1/bob/*. Нужны username_as_alias:true и alias на выбранном mount; без него доступа нет. По умолчанию identity_source:entity_id использует {{identity.entity.id}} и принимает users. Персональный корневой ключ и LIST родителей не выдаются. Логины должны быть безопасными одиночными сегментами без /, wildcard и . или ..; повторное использование LDAP-логина требует управления жизненным циклом секретов. Другие политики могут расширить доступ.

## Токен и совместимость

[files/bootstrap-policy.hcl](files/bootstrap-policy.hcl) — доверенная административная политика без delete для sys/mounts/* и sys/auth/*. Она позволяет holder расширять права через ACL; выдавайте её доверенному оператору/CI.

```bash
export VAULT_ADDR=https://vault01.example.org:8200
vault login
# Введите root token интерактивно; не передавайте его в командной строке.
vault policy write vault-configuration-admin roles/vault-configuration/files/bootstrap-policy.hcl
vault token create -policy=vault-configuration-admin -ttl=8h
```

Полученный токен задайте через vault_configuration_token в Ansible Vault/секретах CI. Не сохраняйте его в открытом inventory.

Поддерживается только Vault 2.x; вся ветка 2.0.x считается проверенной по принятой политике, другие 2.x выполняются с информационным предупреждением. Реально протестированные релизы отделены от политики допуска в [compatibility.json](compatibility.json) и [TEST-REPORT.md](TEST-REPORT.md). Проверки поддерживаемых API, KV v2 и встроенных auth plugins сохраняются.

Transport-ошибки содержат безопасные reason/hint, verify_code для сертификата, источник CA, timeout и proxy=disabled. Проверяйте DNS/порт/TLS на хосте исполнения API. Curl и Python могут использовать разные trust stores. Тело HTTP-ответа, токен и исходные исключения не публикуются.

## Переход со старой модели

Уберите execution_host, config_connection_address, config_connection_allow_insecure_http, management_state_file/prune/prune_identities/deletion_approvals/recovery и safety_max_deletions/allow_empty_desired. Используйте api_execution/scheme/port/use_loopback и DNS target в inventory. Уберите password_revision/bind_password_revision; замените on_revision явным always только для требуемой смены. Словари config/export, compatibility_profile и config_schema_version также больше не принимаются. Существующие registry-файлы роль игнорирует; mounts и aliases сами не переносятся и не удаляются.

Тесты: `python3 -m unittest discover -s roles/vault-configuration/tests/unit -v`; реальные интеграционные тесты используют только временные localhost Vault/OpenLDAP. Для target без внешнего API-доступа есть отдельный тест маршрута выполнения через local connection; физический удалённый SSH-хост в среде тестов не используется.
## Матрица прав KV v2 (matrix)

Готовый офлайн-инвентарь: [examples/matrix.yml](examples/matrix.yml), [examples/matrix-playbook.yml](examples/matrix-playbook.yml).

Режим `matrix` создаёт CSV с назначенными правами пользователей и групп на mounts и пути KV v2. Vault не изменяется, значения секретов и список ключей KV не читаются. CSV и пояснения всегда записываются на Ansible-контроллере, независимо от `api_execution`. Дополнительные роли не нужны; playbook по-прежнему только вызывает `vault-configuration`.

```yaml
vault_configuration_config_mode: matrix
vault_configuration_matrix_source: cluster
vault_configuration_matrix_destination: ./vault-access-matrix.csv
```

```bash
ansible-playbook -i inventory.ini configure.yml -e vault_configuration_config_mode=matrix
# Только объявления inventory: без API, SSH, токена и паролей
ansible-playbook -i inventory.ini configure.yml -e vault_configuration_config_mode=matrix -e vault_configuration_matrix_source=inventory
```

- `cluster` (default) читает реальные KV v2 mounts, Identity entities/groups/aliases, ACL, userpass, LDAP mappings и поддерживаемые auth roles. Отчёт охватывает все обнаруженные KV v2 mounts и назначения, включая ручные и принадлежащие другим владельцам. `config_mounts`, owner, policy prefix и фильтры export не сужают матрицу. Нужен существующий токен с правами чтения соответствующих API; административный токен роли подходит. Ошибка чтения останавливает отчёт, прежние файлы не заменяются. Желаемые users/grants и пароли не вычисляются.
- `inventory` строит матрицу объявленных grants, personal_access и состава групп. Токен, passwords, ldap_passwords, LDAP config и inline users[].password не вычисляются. API-код выполняется на контроллере даже при `api_execution: target`; SSH не нужен. Сохраняются проверки объявлений, включая ссылки, циклы и разрешение опасных grants. `vault_configuration_users` должен быть явным YAML-списком словарей либо `null`: ссылка-шаблон на весь список отклоняется до вычисления, чтобы не вызвать вложенные password lookup. Шаблоны остальных полей пользователей поддерживаются. Права из `existing_policies` неизвестны без чтения Vault и обозначаются `?`. `null` не означает отсутствие прежних прав в кластере.

Относительный destination считается от `playbook_dir`. Создаются `<destination>` и `<destination>.notes.txt`: UTF-8 без BOM, LF, права 0600; новые каталоги — 0700. CSV использует `;` и стандартное экранирование кавычками; поля, похожие на формулы, получают начальный апостроф для открытия в табличных редакторах. Пояснения содержат читаемый JSON с легендой, источниками политик, цепочками групп, временным интервалом чтения и неопределёнными правилами. На экран выводятся сводка и пути файлов. `changed` отражает изменение файлов. При `--check` матрица рассчитывается, но файлы не создаются и не заменяются.

### Строки и колонки

Первые колонки — `mount` и `path`, затем отсортированные субъекты:

| Префикс | Смысл |
|---|---|
| `u:<name>` | Identity entity: её политики и известное членство в группах |
| `g:<name>` | Identity group: её политики и политики родительских групп |
| `a:<auth_mount>/<login>` | Известный userpass/LDAP login: его token policies, default (если не отключена), LDAP config/mappings и связанная entity с группами |
| `ldap-group:<auth_mount>/<name>` | Прямое назначение через `auth/<mount>/groups/<name>` и связанная external Identity group, если есть alias |
| `r:<auth_mount>/<name>` | Назначения существующей AppRole/Kubernetes/JWT/OIDC role; это не конкретный выданный токен |

В `inventory` выводятся объявленные `u:`, `g:`, `r:` и UUID-субъекты; auth-назначения, отсутствующие в инвентаре, не прогнозируются. Происхождение прав указывается в `policy_sources` файла пояснений: ячейка показывает операции, а не способ их назначения.

Для каждого mount есть строка `*`; остальные пути и маски берутся из ACL, а не из содержимого KV. Exact-путь и `path/*` — разные строки; пустой `path` обозначает точный корень API mount. Префиксная строка показывает покрывающие её правила; более узкие исключения выводятся отдельно. Для конкретного секрета учитывайте соответствующую более узкую строку. Разрешение `infra/*` само по себе не доказывает такое же разрешение на каждое исключение внутри него.

### Фиксированные позиции permissions

В каждой ячейке **ровно 11 символов без пробелов**; порядок постоянен: `LRWPMUDVNXZ`.

| Позиция | Символ | Permission |
|---|---|---|
| 1 | `L` | `list` |
| 2 | `R` | `read` |
| 3 | `W` | `write` |
| 4 | `P` | `patch` |
| 5 | `M` | `read_metadata` |
| 6 | `U` | `update_metadata` |
| 7 | `D` | `delete_latest` |
| 8 | `V` | `delete_versions` |
| 9 | `N` | `undelete_versions` |
| 10 | `X` | `destroy_versions` |
| 11 | `Z` | `delete_metadata` |

`.` — разрешение не найдено в модели отчёта; `!` — запрет соответствующей операции; `?` — неизвестный результат или неполный набор capabilities. Отключённая entity и её logins имеют `!!!!!!!!!!!`, что отдельно отмечается в `disabled_subjects`. Для W необходимы `create` **и** `update` на `data`, для U — на `metadata`; только одна из двух capabilities даёт `?`, подробности API-прав смотрите в самих политиках.

```csv
mount;path;g:developers;u:alice;u:bob
infra;*;LRW........;LRW........;LRW........
users;dep1/alice/*;...........;.RW........;...........
users;dep1/bob/*;...........;...........;.RW........
```

`LRWPMUDVNXZ` — все 11 операций; `LR.........` — list/read; `......D....` — delete_latest. Семантика каждой permission приведена также в таблице раздела grants ниже.

### LDAP, шаблоны и границы достоверности

Матрица включает Identity external groups и прямые назначения через `auth/ldap/groups` и `auth/ldap/users`. Известный Vault состав групп учитывается, включая вложенные группы; для login также учитываются группы из явного LDAP user mapping. Права самих LDAP-групп видны и до первого входа участников. Прямого подключения к LDAP/AD нет: состав LDAP-групп в Vault — наблюдавшееся состояние, которое может измениться при следующем входе. Пользователи, никогда не входившие в Vault и не объявленные явно, могут отсутствовать. `u:` не включает auth-specific policies, а `a:` включает назначения для конкретного login; неизвестное LDAP-членство не достраивается.

Известный UUID или LDAP alias подставляется в персональную политику, например `users/dep1/alice/*`. В inventory UUID не выдумывается. При неизвестном логине/UUID остаётся строка шаблона и `?` с причиной; наличие шаблонной политики у группы не позволяет перечислить всех её LDAP-пользователей.

Поддерживаются HCL/JSON path-блоки с capabilities, комментарии, точные пути и завершающая `*`. Учитывается приоритет наиболее конкретного пути Vault; capabilities одинаковых шаблонов объединяются, `deny` действует в выбранном правиле. Поэтому более конкретное разрешение может перекрыть более широкий deny. Маски `+`, другие identity templates, ограничения параметров и неизвестный синтаксис дают `?` в затронутой области; неизвестное тело внешней политики затрагивает все её потенциальные пути. Некорректный JSON и незакрытые скобки HCL останавливают отчёт.

Это матрица назначений ACL KV v2 с указанными ограничениями. Она не проверяет каждый существующий токен, CIDR/TTL/число использований, внешние механизмы авторизации и другие движки секретов. Чтение неатомарно. `.` не доказывает отсутствие доступа через механизмы вне модели. Правила сопоставления: [Vault policies](https://developer.hashicorp.com/vault/docs/concepts/policies); прямые LDAP mappings: [LDAP API](https://developer.hashicorp.com/vault/api-docs/auth/ldap).

