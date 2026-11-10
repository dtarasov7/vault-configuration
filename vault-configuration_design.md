# Техническое задание: Ansible-роль vault-configuration

Статус: задание на разработку; реализация роли в рамках этого документа не выполняется.

## 1. Назначение и терминология

Разработать декларативную Ansible-роль `vault-configuration` для управления локальными пользователями, идентичностями, группами и назначениями прав в HashiCorp Vault Community/OSS. Основной сценарий — выдача доступа к отдельным секретам и вложенным деревьям KV v2 по проектам и контурам.

**Версия сервера Vault и версия KV — разные параметры.** В этом задании `v2` однозначно означает движок KV версии 2. Формулировка «Vault OSS v2.x» сама по себе не задаёт проверенную серверную платформу: перед реализацией необходимо зафиксировать точный Community-релиз и образ, а поддержку серверной ветки 2.x подтверждать отдельно. Наличие Enterprise/RC-сборки не означает наличие соответствующего стабильного Community-релиза. Роль должна иметь явный список протестированных серверных версий и отклонять неизвестный профиль по умолчанию. [Официальный каталог релизов](https://releases.hashicorp.com/vault/)

Один запуск обслуживает один Vault и одного владельца конфигурации. Исполнение — на одном Ansible execution host с доступом к HTTPS API; установка роли на узлы Vault не требуется.

## 2. Исходная структура хранилища

Указанные mount обеспечиваются ролью: отсутствующие создаются с типом `kv` и `options.version: "2"`; существующие проверяются. Удаление secret/auth mount запрещено при любых настройках prune:

| Mount | Назначение | Типичные потребители |
| --- | --- | --- |
| `certs/` | Статические сертификаты и ключи | Ansible |
| `infra/` | Пароли инфраструктуры | Ansible, SRE |
| `apps/` | Секреты приложений Kubernetes | Deckhouse SSI |
| `cicd/` | Секреты конвейеров | GitLab, Jenkins |
| `users/` | Персональные секреты | Люди |

`certs/` здесь — KV v2, а не PKI engine: выпуск и отзыв сертификатов не входят в задачу.

Поддержать произвольную глубину относительного пути, без фиксированного порядка сегментов:

```text
infra/payments/postgres                 # только проект
infra/prod/shared/dns                   # контур и общая инфраструктура
apps/payments/prod/backend              # проект → контур → компонент
apps/prod/payments/backend              # контур → проект → компонент
cicd/payments/build/registry            # проект → назначение
certs/prod/payments/ingress             # контур → проект → компонент
users/<entity-id>/personal/service      # личная область
```

Роль не создаёт каталоги: в KV это префиксы ключей. Порядок сегментов задаёт inventory. Никакой автоматической связи между одноимёнными путями разных mount нет.

## 3. Обязательные возможности первой версии

1. Режимы через `vault_configuration_config_mode`: `apply`, `dry`, `export`. `dry` — самостоятельный режим чтения и планирования, не зависящий от `--check`/`--diff`; по умолчанию `dry`. Обычная семантика Ansible check/diff описана в разделе 10.
2. Управление Vault Identity entities и entity aliases для существующих auth mount.
3. Создание и удаление локальных учётных записей `userpass`, настройка разрешённых параметров токена и явная ротация пароля.
4. Внутренние Identity groups: прямые участники и вложенные группы, проверка циклов.
5. Внешние Identity groups и group aliases: связывание с группами уже настроенного IdP.
6. Генерация ACL policies из высокоуровневых назначений KV v2; привязка к entities/groups.
7. Привязка существующих ACL policies по имени, с проверкой их существования. Системные политики по умолчанию запрещены для назначения.
8. Ограниченное управление списком `token_policies` существующих auth roles типов Kubernetes, JWT/OIDC и AppRole, чтобы права могли получать SSI, CI/CD и Ansible.
9. Контроль владения объектами, явное принятие существующих объектов под управление, безопасное удаление и отчёт о частичном применении.
10. Экспорт поддерживаемой конфигурации без секретов, с отдельным отчётом о неподдерживаемых объектах.

Вне первой версии: установка/обновление/unseal Vault, установка IdP/AD/LDAP серверов и управление внешними пользователями; secret mounts создаются только как KV v2, LDAP auth mounts разрешено включать и настраивать, управление содержимым KV, генерация токенов/SecretID, настройка SSI/GitLab/Jenkins, Enterprise namespaces, Sentinel, произвольный HCL из inventory, автоматическое объединение entities и массовый отзыв токенов.

Для auth roles изменять только явно управляемый список политик. Остальные параметры, включая bound claims, аудитории, ServiceAccount bindings и TTL, сохранять. Реализовать отдельные адаптеры и тесты для каждого типа: общего универсального PATCH-контракта не предполагать. Не создавать отсутствующие auth roles; для неподдерживаемой версии адаптера завершать работу до изменений.

## 4. Модель идентичностей

Vault entity — идентичность, а не логин с паролем. Локальный логин создаёт `userpass`; для LDAP/OIDC субъект уже существует в каталоге; LDAP/AD auth mount роль может создать и настроить, затем связать субъект с entity. Alias определяется именем, которое реально возвращает auth method, и accessor конкретного auth mount. Для OIDC это не обязательно email.

Внутренняя группа управляет членством через inventory. Внешняя группа получает членство через auth method; задавать ей `members` запрещено. Изменения внешнего членства могут отражаться после следующего входа/renewal, поэтому применение роли не означает немедленного обновления всех сессий. [Vault Identity](https://developer.hashicorp.com/vault/docs/concepts/identity)

Для aliases accessor получать по пути auth mount; изменение accessor после переустановки mount считать миграцией, а не обычным обновлением. Конфликт уже существующего alias, связанного с другой entity/group, завершать ошибкой. Автоматическое объединение или перенос запрещены.

Идентичности имеют стабильный inventory `id`, не зависящий от отображаемого имени. Сохранять Vault UUID в реестре управления. Переименование entity не должно создавать новую личную область. Для внешних ссылок допускается Vault UUID с проверкой существования.

## 5. Контракт inventory

Все публичные переменные начинаются с `vault_configuration_`. Настройки задаются отдельными переменными `vault_configuration_config_*`: например, `vault_configuration_config_mode` и `vault_configuration_config_connection_address`; словарь `vault_configuration_config` не используется. Схему валидировать строго: неизвестные поля, дубликаты, неразрешённые ссылки и некорректные типы — ошибки до первой мутации.

Ниже предлагаемый обязательный формат. Пароли и токены — ссылки на защищённые переменные, а не значения в репозитории.

```yaml
vault_configuration_config_schema_version: 1
vault_configuration_config_mode: dry
vault_configuration_config_compatibility_profile: community-validated
vault_configuration_config_connection_address: https://vault.example.org:8200
vault_configuration_config_connection_validate_tls: true
vault_configuration_config_connection_ca_file: /etc/ansible/certs/vault-ca.pem
vault_configuration_config_connection_timeout_seconds: 30
vault_configuration_config_mounts:
- certs
- infra
- apps
- cicd
- users
vault_configuration_config_management_owner: platform-team
vault_configuration_config_management_policy_prefix: vam-platform-
vault_configuration_config_management_state_file: /var/lib/ansible/vault-access/platform-state.json
vault_configuration_config_management_prune: false
vault_configuration_config_management_prune_identities: false
vault_configuration_config_management_adoption: []
vault_configuration_config_safety_max_deletions: 5
vault_configuration_config_safety_allow_empty_desired: false
vault_configuration_config_safety_allow_mount_root: false
vault_configuration_config_safety_allow_destructive_grants: false
vault_configuration_config_safety_protected_policies:
- root
- default
vault_configuration_config_safety_protected_entities: []
vault_configuration_config_safety_protected_groups: []


vault_configuration_token: "{{ vault_admin_automation_token }}"

vault_configuration_users:
  - id: alice
    name: alice
    source: userpass
    auth_mount: userpass
    login: alice
    password: "{{ vault_alice_password }}"
    password_revision: initial-1
    password_policy: on_create           # on_create | on_revision
    disabled: false
  - id: bob
    name: bob
    source: external
    aliases:
      - auth_mount: oidc
        name: immutable-idp-subject-bob

vault_configuration_groups:
  - id: payments-dev
    name: payments-dev
    type: internal
    members: [alice, bob]
    member_groups: []
  - id: sre-prod
    name: sre-prod
    type: external
    alias:
      auth_mount: oidc
      name: sre-prod-idp-group

vault_configuration_grants:
  - id: payments-dev-write
    subjects:
      - kind: group
        id: payments-dev
    paths:
      - mount: apps
        path: payments/dev
        scope: subtree                  # exact | subtree
        permissions: [read, write, list]
  - id: sre-prod-infra
    subjects:
      - kind: group
        id: sre-prod
    paths:
      - mount: infra
        path: prod
        scope: subtree
        permissions: [read, list]
  - id: ansible-certificate
    subjects:
      - kind: auth_role
        id: ansible
    paths:
      - mount: certs
        path: prod/payments/ingress
        scope: exact
        permissions: [read]
  - id: ssi-payments-prod
    subjects:
      - kind: auth_role
        id: ssi-payments-prod
    paths:
      - mount: apps
        path: payments/prod
        scope: subtree
        permissions: [read]
  - id: pipeline-payments
    subjects:
      - kind: auth_role
        id: gitlab-payments
    paths:
      - mount: cicd
        path: payments/build
        scope: subtree
        permissions: [read]
  - id: alice-existing-policy
    subjects:
      - kind: user
        id: alice
    existing_policies: [company-self-service]

vault_configuration_auth_roles:
  - id: ansible
    type: approle
    auth_mount: approle
    name: ansible-prod
  - id: ssi-payments-prod
    type: kubernetes
    auth_mount: kubernetes-prod
    name: ssi-payments-prod
  - id: gitlab-payments
    type: jwt
    auth_mount: jwt-gitlab
    name: payments-build

vault_configuration_personal_access:
  enabled: true
  mount: users
  subjects:
    - kind: user
      id: alice
    - kind: user
      id: bob
  permissions: [read, write, list, delete_latest]
```

У grant ровно один источник: `paths` либо `existing_policies`. Для subject `user` политики назначаются entity; для `group` — Identity group; для `auth_role` — `token_policies` указанной роли. Созданные userpass accounts по умолчанию не дублируют ACL в token policies: основные права приходят через entity и группы.

Членство задаётся только в `groups[].members/member_groups`, поля `users[].groups` нет. Незаполненная секция означает «не управлять», явный пустой список — желаемое отсутствие объектов только в соответствующей области владения, с учётом защиты удаления.

Разрешить дополнительный `discovery_paths` у grant: список конкретных относительных каталогов для LIST metadata. Пустая строка означает корень mount и требует отдельного разрешения `allow_mount_root`. По умолчанию список пуст. Каждое такое разрешение показывать отдельно в плане с предупреждением о раскрытии имён.

## 6. Компиляция прав KV v2

Пользователь указывает логический путь без `/v1`, имени mount и служебного API-префикса. Например, `mount: apps`, `path: payments/prod/backend`. Компилятор сам добавляет `data`, `metadata` и прочие API-сегменты. Сегмент с именем `data` внутри логического пути допустим: не удалять его эвристически.

| Permission | API-путь относительно mount | ACL capabilities |
| --- | --- | --- |
| `read` | `data/<path>` | `read` |
| `write` | `data/<path>` | `create`, `update` |
| `patch` | `data/<path>` | `patch` |
| `list` | `metadata/<path>` | `list` |
| `read_metadata` | `metadata/<path>` | `read` |
| `update_metadata` | `metadata/<path>` | `create`, `update` |
| `delete_latest` | `data/<path>` | `delete` |
| `delete_versions` | `delete/<path>` | `update` |
| `undelete_versions` | `undelete/<path>` | `update` |
| `destroy_versions` | `destroy/<path>` | `update` |
| `delete_metadata` | `metadata/<path>` | `delete` |

Разделение операций соответствует API KV v2. Удаление metadata удаляет секрет со всеми версиями; destroy необратимо уничтожает выбранные версии. Обычные `read/write` этих прав не включают. `read` может читать доступные исторические версии, а не только latest. `patch` требует отдельной проверки поддержки сервером. [KV v2 HTTP API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2)

`destroy_versions` и `delete_metadata` требуют `allow_destructive_grants: true`. Удаление самой ACL policy не удаляет секреты. Роль только выдаёт разрешения из таблицы и никогда не выполняет эти операции с пользовательскими секретами.

`scope: exact` даёт права только на указанный ключ. `scope: subtree` включает сам путь и всех потомков, используя отдельные точное правило и правило с `/*`. LIST каталогов проверять с нормализованным завершающим `/`; `list` разрешён только для subtree/discovery, а `exact + list` отклоняется как неоднозначный запрос.

Пример результата для чтения дерева `apps/payments/prod`:

```hcl
path "apps/data/payments/prod" {
  capabilities = ["read"]
}
path "apps/data/payments/prod/*" {
  capabilities = ["read"]
}
```

Если дополнительно задан `list`, добавить:

```hcl
path "apps/metadata/payments/prod" {
  capabilities = ["list"]
}
path "apps/metadata/payments/prod/*" {
  capabilities = ["list"]
}
```

Не генерировать `apps/data/payments/prod*`: такой шаблон захватывает и `production`. Не добавлять автоматически права на `apps/metadata/`, `apps/metadata/payments/` и соседние деревья.

LIST возвращает имена дочерних ключей без фильтрации по возможности читать их содержимое. Поэтому доступ к корневому LIST не гарантирует конфиденциальности имён проектов. Интерфейс Vault UI может требовать дополнительных прав для навигации; в строгом режиме гарантировать API-доступ по известному пути, а не просмотр дерева из корня. [KV v2: list secrets](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#list-secrets)

В первой версии пользовательские `*`, `+`, шаблоны и произвольные HCL-выражения в `path` запрещены. Для нескольких контуров перечисляют несколько путей. Отклонять абсолютные пути, пустые сегменты, `.`/`..`, обратный слеш, управляющие символы и неоднозначное percent-encoding. Поддержку произвольных Unicode-имён отложить; зафиксировать безопасный ASCII-набор сегментов `[A-Za-z0-9_-][A-Za-z0-9_.-]*`.

Vault ACL не идентичен Kubernetes RBAC: есть приоритеты совпадающих путей и `deny`. Не обещать вычисление всех эффективных прав по одному inventory, особенно при существующих policies. Проверять фактический доступ тестовыми клиентами. [ACL policies](https://developer.hashicorp.com/vault/docs/concepts/policies)

## 7. Персональные секреты

Генерировать одну шаблонную policy для `users/<entity-id>/...`. Использовать `identity.entity.id`, а не login/email: имя можно изменить или повторно выдать другому человеку. [Templated policies](https://developer.hashicorp.com/vault/docs/concepts/policies#templated-policies)

```hcl
path "users/data/{{identity.entity.id}}/*" {
  capabilities = ["read", "create", "update", "delete"]
}
path "users/metadata/{{identity.entity.id}}/*" {
  capabilities = ["list"]
}
```

Шаблоны Vault сохранить буквально: Jinja Ansible не должен их вычислять. В личной области секреты располагаются под ID, сам корневой ключ `<entity-id>` не используется. LIST корня `users/` не выдавать. Проверить две разные entity, несколько aliases одной entity и токен без entity. Возможность администратора читать личные секреты зависит от остальных ACL: это не криптографическая изоляция от оператора Vault.

Удаление entity не удаляет её секреты и не передаёт их новому пользователю с тем же именем. Миграция существующих `users/<login>/...` в формат ID — отдельная операция вне роли.

## 8. Владение, идемпотентность и применение

Нельзя переносить механизм labels/UID Kubernetes на все Vault-объекты. Identity поддерживает metadata, но ACL policy не имеет универсального поля owner и версии для условного обновления. Использовать локальный постоянный реестр управления на execution host, защищённый правами `0600`, с атомарной записью и резервным восстановлением.

Реестр хранит идентификатор целевого Vault, owner, стабильные inventory ID, Vault UUID/accessors, имена policies, управляемые связи, хеш последнего применённого несекретного содержимого и revision пароля. Пароли, токены и их хеши не хранить. Идентификатор целевого Vault должен проверяться до мутаций; смена кластера по тому же URL не означает право принять его объекты под управление.

Для нового окружения создавать реестр только после проверки отсутствия конфликтов. При потере реестра не принимать существующие объекты автоматически: нужен явный adoption с ожидаемым UUID либо хешем текущего содержимого. Префикс policy — дополнительная защита, не доказательство владения. Точное описание формата реестра и восстановления входит в реализацию.

Для каждого grants ID генерировать детерминированное уникальное имя policy. Полностью управлять содержимым только собственной сгенерированной policy. Для списков политик/участников сохранять сторонние элементы, а удалять только связи, ранее добавленные этим owner. Коллизию владельцев считать ошибкой. Пересечение управляемых связей между несколькими owner запрещено.

Алгоритм:

1. Проверить схему, TLS, доступность/unsealed состояние Vault, серверный профиль, mount types/version, auth accessors и необходимые разрешения.
2. Прочитать текущее состояние и реестр; неполное чтение/403 не считать отсутствием ресурса.
3. Построить нормализованный план: create/update/detach/delete/noop, причины, scope и расширения прав. План не содержит секретов.
4. Проверить запреты, лимиты удаления, конфликты, ссылки и устаревание принятого плана.
5. При apply повторно прочитать затрагиваемые объекты. При дрейфе остановиться, а не затереть чужое изменение.
6. Создать policies и identities, затем aliases и связи; при удалении сначала убрать управляемые связи, затем объекты. Каждую успешную операцию фиксировать в журнале восстановления.
7. Повторно прочитать результат, завершить обновление реестра, выдать итоговый отчёт.

API не предоставляет общей транзакции/CAS для всех этих объектов: повторное чтение не устраняет окно гонки. Все apply к общей области сериализовать в CI; локальная блокировка файла защищает только один execution host. Не обещать атомарный rollback. При частичном сбое сообщать подтверждённые операции и неопределённый результат; перед продолжением перечитывать API. Потеря ответа на запись не должна приводить к слепому повтору.

`prune: false` по умолчанию. Prune касается только объектов и связей этого owner в явно управляемых секциях. Удаление identities/userpass дополнительно требует `prune_identities`. Защитить automation identity, системные policies, перечисленные защищённые объекты; защищённые объекты нельзя менять и через adoption. При внешних зависимостях, которые невозможно достоверно проверить, удаление policy/identity блокируется до явного устранения зависимости. Очистка локальных файлов не удаляет ресурсы Vault.

## 9. Пароли, сессии и секреты роли

Применить проектный подход `ansible-role-secrets`: источники секретов выбираются в variables, не внутри tasks. Поддержать Ansible Vault/inventory и необязательный внешний Vault lookup; lookup-плагин не должен быть обязательной runtime-зависимостью роли. Для первого доступа нельзя требовать получение токена из того же недоступного Vault.

Пароль userpass нельзя прочитать обратно через API. `on_create` задаёт его только при создании; `on_revision` меняет при явном изменении `password_revision`, фиксируемом после успешной записи. Одинаковая revision не позволяет обнаружить внешнюю смену пароля — это документированное ограничение. При неопределённом результате смены не выполнять бесконечные повторы. [Userpass API](https://developer.hashicorp.com/vault/api-docs/auth/userpass)

`disabled` относится к entity. Не представлять его или удаление userpass как гарантию отзыва всех ранее выданных токенов: отключение identity, удаление логина и отзыв сессий — разные операции. Документировать процедуру offboarding и границы по token/identity policies; автоматический поиск и массовый revoke не входят в первую версию.

Для роли использовать заранее полученный короткоживущий automation token с необходимыми административными ACL, без требования root token. Управление ACL само по себе привилегированно: запреты inventory не являются границей безопасности против владельца такого токена. Подготовить отдельную bootstrap policy и объяснить её полномочия.

TLS verification включена по умолчанию; CA и при необходимости client cert/key — переменные. Не передавать токены в CLI, URL, debug, traceback, план, export или Ansible diff. Чувствительные module arguments — `no_log`; публичный отчёт формировать отдельно. HTTP redirects с передачей токена на произвольный host запрещены.

## 10. Apply, dry, export и Ansible check/diff

Режим задаётся переменной `vault_configuration_config_mode` и принимает три основных значения:

| Режим | Действие | Поведение Ansible |
| --- | --- | --- |
| `apply` | Читает состояние, строит план и применяет изменения | `changed` соответствует выполненным изменениям |
| `dry` | Читает реальное состояние Vault и строит план без мутаций | Без `--check` и `--diff`; `changed: false`, если не запрошена запись локального отчёта |
| `export` | Читает фактическое состояние и сохраняет YAML с целевыми значениями | Изменение локального файла отражается в `changed`, Vault не изменяется |

Dry обязательно выводит **«Планируем добавить»**, **«Планируем изменить»**, **«Планируем удалить»**: число и список объектов с типом/именем и причиной изменения. Дополнительно возвращать структурированный план и digest. Dry не пишет в Vault, не создаёт реестр и не выполняет login/renewal: использует переданный токен. Сохранение локального отчёта — только по явно заданному пути.

`--check` не заменяет выбранный режим: для apply строит план и прогноз changed, для dry сохраняет read-only поведение, для export читает фактическое состояние и проверяет необходимость записи файла без его создания. `--diff` показывает обычный Ansible before/after для поддерживаемых несекретных изменений, отдельно или с `--check`. Токены, пароли и другие секреты в diff не попадают. Не включать server-side проверки, выполняющие мутации, в dry/check.

Digest строится из целевой конфигурации без секретов, текущих UUID/accessors и хешей управляемых полей. Применение сохранённого плана требует повторной проверки; смену пароля представляет revision, не digest пароля.

### Формат и назначение экспорта

`vault_configuration_export.destination`, по умолчанию `./vault-access-manager-export.yml`, содержит **непосредственно переменные желаемого состояния**, без обёртки inventory, аудита, UID исходного кластера и connection/config:

```yaml
vault_configuration_users: []
vault_configuration_groups: []
vault_configuration_grants: []
vault_configuration_auth_roles: []
vault_configuration_personal_access:
  enabled: false
```

Это пример формы, а не требование выводить пустые разделы: файл содержит реальные значения выбранной области. Его можно без редактирования содержимого подключить через vars_files, поместить в group_vars или вставить в vars инвентаря. Кластерные настройки, credentials и существующие внешние зависимости задаются отдельно для целевой среды. Неподдерживаемые или невыбранные секции нельзя подменять пустыми списками, означающими желаемое удаление.

Export нужен для двух обязательных сценариев: перенос поддерживаемой конфигурации на другой Vault и сохранение фактических ручных изменений обратно в inventory. Чтение не ограничивается последним desired state в реестре. Предусмотреть managed (объекты owner) и scoped (явно выбранные существующие объекты, включая созданные вручную), фильтры mounts/auth mounts/идентичностей и исключение системных объектов. Включать самостоятельных пользователей/группы и необходимые зависимости, а не только участников grants.

Для ACL реализовать обратное преобразование поддерживаемого подмножества правил KV v2 в paths/permissions. При ручном изменении собственной policy не выгружать устаревшие grants из реестра. Если правило, policy или зависимость нельзя представить без потери смысла, по умолчанию завершить экспорт ошибкой до записи файла. Допустим отдельный явный `allow_partial: true` для аудита с предупреждением о неполноте. Ссылки existing_policies переносимы только при наличии соответствующих policies на целевом Vault; export обязан перечислить эти зависимости.

Аудит, исходные UUID/accessors, ownership, пропущенные поля и внешние зависимости сохраняются отдельно через `vault_configuration_export.audit_destination`; они не попадают в подключаемые переменные. На целевом кластере aliases вновь разрешаются через auth mount paths, а UUID идентичностей назначает целевой Vault. Новые personal paths используют новые entity IDs; перенос содержимого KV в задачу роли не входит. Применение к существующим чужим объектам исходного Vault требует явного adoption; экспорт не меняет владение.

### Секреты и объективная граница переноса userpass

Пароли userpass невозможно прочитать обратно через API. Поэтому export не может быть самодостаточной резервной копией локальных credentials. Сохранять пароль в inventory в виде несуществующего прочитанного значения запрещено.

Задать стабильный контракт `vault_configuration_passwords` — словарь внешне передаваемых секретов по users[].id. Экспорт userpass содержит готовое выражение, например `password: "{{ vault_configuration_passwords['alice'] }}"`, и совместимую password_policy/revision. Файл не требует правок, если словарь секретов задан отдельно в Ansible Vault или через lookup. Для переноса без известного исходного пароля оператор должен заранее предоставить новый пароль в этом словаре. Ошибка отсутствующего секрета должна возникать до первой мутации. Для уже существующего on_create-пользователя реализация должна допускать отсутствие секрета и не инициировать смену пароля.

Для внешних OIDC/LDAP users пароли не нужны, а identity/groups/grants переносятся в пределах поддерживаемой схемы. Токены, SecretID, приватные ключи и KV data не экспортировать. Файлы экспорта и аудита имеют права 0600; исходное содержимое секретов и их значения не выводить в stdout/diff.

## 11. Требования к реализации и поставке

Разместить роль в `roles/vault-configuration/`. Следовать структуре существующей роли: `defaults`, `tasks`, `handlers`, `meta`, `library/module_utils`, `templates`, `molecule`, unit/integration tests, русские `README.md`/`CHANGELOG.md` и английские версии. Не добавлять systemd, OS users и logrotate для роли, которая работает только через API. Не создавать пустые сущности ради формального сходства.

Выделить независимые компоненты: строгая валидация inventory; компилятор KV grants; REST-клиент с редактированием секретов в ошибках; адаптеры identity/userpass/auth roles; planner; executor; state store; exporter. Не копировать Kubernetes-клиент с заменой URL.

Зафиксировать runtime-зависимости и матрицу Python/ansible-core. Наследовать профили существующей роли только после фактических тестов. Базовый API-доступ не должен требовать Vault CLI, `kubectl` или `community.hashi_vault`; использование дополнительных Python-библиотек явно отразить в requirements. Все текстовые файлы UTF-8 с LF.

Документация включает рабочие примеры для каждого из пяти mount, обоих порядков project/environment, личных областей, userpass, внешних групп, SSI Kubernetes auth, CI JWT и Ansible AppRole. Примеры не содержат действительных паролей и токенов. Отдельно описать bootstrap permissions, восстановление реестра, adoption, ротацию пароля и offboarding.

## 12. Проверки и критерии приёмки

Обязательные unit-тесты:

- Валидация путей, точный ключ и subtree, схожие префиксы `prod/production`, конфликтующие/неизвестные ссылки, циклы групп.
- Детерминированные ACL и планы; отсутствие расширения прав вне заданных mount/path.
- Раздельные destructive permissions, отказ root scope без разрешения, сохранение Vault templates буквально.
- Отсутствующая секция против пустого списка, protected objects, adoption, лимиты prune и конфликт owner.
- Сохранение чужих связей и auth-role полей, пароли по revision, редактирование секретов в результатах/ошибках.

Интеграционные тесты на настоящем Vault Community с заранее подготовленными пятью KV v2 mounts:

1. Создать identities/groups/aliases/userpass и политики, выполнить второй apply: `changed: false`.
2. Установить fixture-секреты отдельно от роли. Войти обычными клиентами, проверить разрешённые и запрещённые реальные API-операции.
3. Для `apps/payments/prod` разрешён свой backend; запрещены `apps/payments/dev`, `apps/other/prod`, `apps/payments/production` и другой mount.
4. Проверить exact, subtree и оба порядка сегментов; LIST работает только там, где запрошен. Отдельно показать раскрытие соседних имён при разрешённом parent LIST.
5. Read не разрешает запись/удаление, write не разрешает destroy; отдельно проверить каждую операцию с версиями.
6. Две личные entity не читают секреты друг друга. Переименование сохраняет доступ, новый UUID не наследует личные данные, токен без entity не получает доступ.
7. Внутреннее/вложенное членство и внешний group alias действительно влияют на права. Для external groups нужен тестовый IdP/auth flow, а не только создание объекта API.
8. Для Kubernetes, JWT/OIDC и AppRole подтвердить получение новых токенов с назначенными policies и сохранение исходных auth-role ограничений. Проверить отличие новых токенов от ранее выданных.
9. Dry/check/export не выполняют мутаций Vault; export не читает KV data. Проверить журнал запросов, три сводки dry без CLI-флагов, apply --check/--diff и export --check. Файл export должен подключаться через vars_files без преобразования; проверить перенос на второй Vault и сохранение ручного изменения ACL. Для userpass отдельно проверить внешнюю передачу пароля. Проверять идемпотентность повторного применения импортированного файла.
10. Проверить 403, sealed Vault, timeout до/после записи, недостоверный TLS, частичное применение, дрейф, утрату/повреждение реестра и повторный запуск после сбоя.
11. Prune не затрагивает чужие политики/пользователей/связи, а удаление пользователя не стирает KV-секреты. Зафиксировать поведение старых сессий в тесте offboarding.
12. Molecule/Docker проверяет роль с реальным API; отдельный HA-сценарий проверяет смену active node и отсутствие передачи токена недоверенному redirect. Dev mode использовать только в тестах.

Готовность означает: поставлены роль, документация, примеры, bootstrap policy, схема inventory/реестра, тесты и отчёт с точными версиями образов и результатами. Непроверенные auth/серверные профили не объявляются поддержанными. Проверки на production Vault без отдельного задания не выполнять.

## 13. Порядок разработки

1. Зафиксировать серверный Community-релиз, runtime и тестовые auth mounts; реализовать схему, compiler и read-only dry.
2. Реализовать state/ownership и apply для ACL, entities, внутренних групп; закрыть негативные тесты изоляции путей.
3. Добавить userpass, aliases, external groups, персональные области и три адаптера существующих auth roles.
4. Реализовать безопасные detach/prune, export, восстановление после частичного сбоя и HA-тесты.
5. Завершить примеры всех mount, bootstrap/offboarding инструкции и отчёт совместимости.

До запуска в конкретной среде должны быть заданы: точная версия сервера; существующие auth mount и роли; реальные alias claims; выбранные соглашения о путях; постоянное место и резервирование реестра; automation credentials. Эти параметры не меняют требования к разработке и не заменяются догадками в коде.

## Дополнение: создание mounts, LDAP/AD и тестовый стенд

Отсутствующие vault_configuration_config_mounts создаются только в apply. Dry/check/export не создают их; существующий KV v1 или другой engine не преобразуется. Mounts нельзя удалять, в том числе через prune. Локальные задачи очистки и соответствующий режим исключены.

vault_configuration_ldap задаёт LDAP auth integrations (id/auth_mount/config/bind_password_revision), а vault_configuration_ldap_passwords — внешние bind secrets по id. Поддерживаются LDAPS/StartTLS, CA, AD samaccountname и фильтр вложенных AD-групп; внешним Identity groups выдаются права через group aliases/grants. Пароли и их хеши исключены из plan/state/diff/export. Неопределённые записи восстанавливаются через pending/recovery. Установка AD/LDAP сервера в задачу роли не входит.

Скрипт scripts/deploy-test-vault-redos73.py подготавливает постоянный TLS-стенд Vault 2.0.4 из подписанного пакета РЕД ОС 7.3 на выделенном узле. Он не меняет существующую другую версию Vault, не стирает данные и не удаляет mounts.
