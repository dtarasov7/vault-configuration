# Отчёт о проверках / Verification report

## 2026-11-11 — алиасы permissions

- 93 модульных теста прошли: 7 новых проверок all/read_only/read_write, строковых и смешанных списков, неизменности исходного inventory, destructive/exact guards, явного экспорта и 11 позиций матрицы.
- Полный набор из 34 интеграционных тестов прошёл на Vault 2.0.4. Новый сценарий проверяет реальные capabilities обычного и персонального пути, идентичность ACL/digest для алиаса и явного списка, повторный apply без изменений и явные permissions в export.
- Новый интеграционный сценарий также прошёл на Vault 2.0.0. JSON Schema/defaults и все примеры инвентаря прошли проверку; пример AD с permissions: all прошёл шаблонизацию и валидацию роли.

## 2026-11-11 — matrix

- 86 модульных тестов: в том числе 16 новых проверок фиксированных 11 позиций, ACL specificity/deny, вложенных групп, LDAP-шаблонов, неизвестных политик, отдельных login policies, CSV escaping, приватных файлов, отказа без замены файлов и исключения password lookup до шаблонизации.
- Полный набор: 33 интеграционных теста на изолированном Vault 2.0.4 прошли. Четыре новых matrix-сценария сравнивают ACL с sys/capabilities, читают реальные LDAP mappings и проверяют Ansible online/offline/--check без SSH и вычисления секретов.
- После расширения проверки повторён реальный OpenLDAP login: права Identity external group и прямого LDAP group mapping попадают в колонку соответствующего LDAP login; другой пользователь этих прав не получает.
- Четыре matrix-сценария также прошли на Vault 2.0.0. Физический SSH target не использовался; production Vault и AD не затрагивались.
- JSON Schema валидна, все 44 входные переменные defaults отражены в ней, пример matrix и YAML задач прошли проверку.

## 2026-11-11 — stateless и controller-артефакты

- 70 модульных тестов: ACL-компилятор/validation, metadata ownership и adoption, authoritative policy bindings/группы, password policies, TLS-диагностика, приватные файлы контроллера и unsafe-строки Ansible.
- 29 интеграционных тестов на Vault 2.0.4: ACL/Identity/auth roles, OpenLDAP, LDAP login templates и переносимый export/import, три Raft voters с failover, реальный RED OS lab playbook init/unseal/configuration и LDAP seeder, TLS/redirect/timeout.
- Дополнительно 6 новых stateless/Ansible сценариев прошли на Vault 2.0.0: controller-only API без SSH, target/loopback, независимые контроллеры, owned bindings и неопределённая password-write.
- Проверен повтор с двух независимых controller directories без registry; отсутствие SSH при controller execution; target execution через loopback; один target после --limit и отказ при нескольких hosts; старые registry/prune параметры отклоняются.
- Dry/export/audit сохраняются только на контроллере с 0600; относительные пути разрешаются от playbook_dir, --check не создаёт файлов. API-модуль не использует PyYAML или локальное состояние.
- Target execution проверялся через inventory connection local, моделирующий удалённый модуль. Физический удалённый SSH-хост не использовался. Production Vault и корпоративный AD не затрагивались.
- Нет распределённой блокировки и durable recovery: apply jobs на кластер сериализуются средствами CI/CD; неопределённая password-write требует проверки аутентификации оператором.

Ниже сохранены историческая матрица и результаты прежней модели; упоминания registry/recovery в исторических сценариях не описывают текущий контракт.

## Историческая проверка — 2026-10-24

Дата: 2026-10-24. Проверялась только изолированная инфраструктура. Системный Vault на execution host не обновлялся; production Vault и корпоративный AD не использовались.

## Проверенная матрица

| Компонент | Значение |
| --- | --- |
| Vault Community | 2.0.0 (обратная совместимость), 2.0.4 (полный актуальный набор) |
| ОС native API-тестов | РЕД ОС 7.3.6, x86_64 |
| RPM | `vault-2.0.4-1.el7.x86_64.rpm`, официальный updates-репозиторий РЕД ОС 7.3 |
| RPM SHA256 | `31e7e0458802d176e746a281edb987b3d4b624774ed1ae9a0f54cc9450d1e35b` |
| Проверка RPM | `rpm -K`: digests signatures OK; имя/версия/архитектура проверены |
| Vault Docker image | `hashicorp/vault:2.0.4@sha256:5be49781ecf78bfe775c5309c6a4d9f4e9e040b6c885c99eb2b12fb69855e1a2` |
| LDAP fixture | `osixia/openldap:1.5.0@sha256:18742e9c449c9c1afe129d3f2f3ee15fb34cc43e5f940a20f3399728f41d7c28` |
| Auth plugins | built-in userpass, approle, jwt, oidc, kubernetes, ldap, версия соответствует точному Vault server |
| Python / ansible-core / Jinja | 3.8.20 / 2.13.13 / 3.1.6 |
| Molecule / plugins | 4.0.4 / 23.0.0 |
| community.docker / ansible.posix | 2.7.3 / 1.4.0 |
| Docker Engine | 29.1.3, linux/amd64 |

На 2026-11-11 вся ветка 2.0.x считается проверенной по политике совместимости; остальные версии Vault 2.x разрешены с информационным предупреждением; Vault 1.x не поддерживается. Указанные выше точные релизы остаются проверенной матрицей, а не списком разрешённых версий. Проверка допуска других номеров 2.x выполнена модульными тестами с имитацией API и не означает проверку реального сервера этой версии. Enterprise/namespaces и внешние версии auth plugins не заявлены. Наличие релиза сверено с [каталогом Vault 2.0.4](https://releases.hashicorp.com/vault/2.0.4/). LDAP/AD параметры сверены с [официальным LDAP API](https://developer.hashicorp.com/vault/api-docs/auth/ldap), включая AD nested-group matching rule; затем проверены на реальном Vault/OpenLDAP. Точный RPM получен с `https://repo1.red-soft.ru/redos/7.3/x86_64/updates/vault-2.0.4-1.el7.x86_64.rpm`.

## Результаты

| Проверка | Результат |
| --- | --- |
| Unit tests | PASS: 38, включая installer bootstrap/recovery, Unicode aliases, create-only mounts и запрет DELETE до сетевого запроса |
| Полный integration suite на 2.0.4 из RPM | PASS: 26 |
| LDAP/mount integration subset на прежнем 2.0.0 | PASS: 4 |
| Molecule default, Vault 2.0.4 | PASS: mounts изначально отсутствуют, роль создаёт их; converge/idempotence, обычный клиент, TLS-independent API fixture, destroy |
| Molecule HA, Vault 2.0.4 | PASS: 3 Raft voters, потеря active node, election, unchanged reapply, write/read, destroy |
| Syntax-check playbook, YAML/JSON, JSON Schema defaults/examples/live registry | PASS |
| Python compilation, UTF-8/LF | PASS |
| Installer `--help`, read-only preflight, package validation, bootstrap unit tests | PASS; на текущем узле preflight ожидаемо отказывает из-за установленного Vault 2.0.0 |

Полный native набор использовал бинарник, **извлечённый** из проверенного RPM внутрь `.work/vault-2.0.4/rpm-root`; установка RPM в систему не выполнялась:

```sh
python3 -m unittest discover -s roles/vault-configuration/tests/unit -v
PATH=$PWD/.work/vault-2.0.4/rpm-root/usr/bin:$PATH \
  python3 -m unittest discover -s roles/vault-configuration/tests/integration -v
```

Molecule запускается из каталога роли с локальными cache/temp путями:

```sh
XDG_CACHE_HOME=$PWD/../../.work/cache \
ANSIBLE_LOCAL_TEMP=$PWD/../../.work/ansible-local \
MOLECULE_EPHEMERAL_DIRECTORY=$PWD/../../.work/molecule-default \
molecule test -s default

XDG_CACHE_HOME=$PWD/../../.work/cache \
ANSIBLE_LOCAL_TEMP=$PWD/../../.work/ansible-local \
MOLECULE_EPHEMERAL_DIRECTORY=$PWD/../../.work/molecule-ha \
molecule test -s ha
```

Журналы: `.work/vault-2.0.4/integration-final.log`, `ldap-legacy-2.0.0.log`, `molecule-default.log`, `molecule-ha.log`. `.work/` не входит в репозиторий. Для localhost sockets и Docker понадобился запуск вне сетевой песочницы. Сценарии используют собственные синхронные create/destroy playbooks и не записывают async-файлы в HOME.

## Что проверено

- Создание отсутствующих KV v2 engines и LDAP auth mounts в общем плане; dry/check/export не мутируют Vault. Несовместимый KV v1 отклоняется до записи. Пропущенные имена и prune не удаляют engines/auth mounts. REST-клиент самостоятельно отказывает в DELETE sys/mounts и sys/auth.
- LDAP bind с внешним паролем, конфигурация directory search, реальный login Alice, получение внешней группы через group alias и чтение разрешённого секрета. Bob вне группы и неверный пароль не получают доступ.
- LDAP credentials не попадают в план/diff/реестр/export/stdout; повторный apply не требует bind-пароля с неизменной revision. Сохраняются engine token settings, в том числе TTL.
- Экспорт LDAP config, сохранение Go filter templates через настоящий Ansible vars_files, применение на втором Vault с внешним словарём bind secrets и идемпотентность импорта.
- Включение нового LDAP auth и создание KV mount с automation token по bootstrap policy без root. У policy нет DELETE для mounts.
- Все три режима через плоские переменные, check/diff и отсутствие вычисления credentials/desired sections в export. Отказ от устаревшего словаря/неизвестных настроек, сохранение defaults.
- Exact/subtree, prod/production, оба порядка сегментов, явный discovery LIST и раскрытие соседних имён; отсутствие автоматических ancestor LIST.
- Раздельные read/write/patch/list/metadata/version permissions, историческое чтение, delete/undelete/destroy и негативные реальные API-операции.
- Entities, aliases, userpass, внутренние/вложенные и внешние группы; реальный JWT groups claim; OIDC adapter сохраняет redirects/scopes/claims.
- Токены AppRole/JWT/Kubernetes получают policies; bindings, audiences, claims и TTL сохраняются; отличие новых от ранее выданных token policies.
- Personal isolation двух entities, rename с сохранением UUID, токен без entity, новый UUID не наследует старые данные; удаление userpass не отзывает старую сессию и не стирает KV.
- Owner/adoption, protected objects, чужие links и auth-role fields, effective membership cycles, max deletions, detach перед допустимым prune объектов доступа.
- Потеря/повреждение реестра, другой cluster_id, дрейф, потерянный ответ после записи и password revision recovery. Нет слепых повторов неизвестной записи.
- 403, sealed Vault, timeout, TLS CA/hostname checks, HTTP 307 без передачи token другому endpoint.
- Installer unit tests: init один раз, сохранение fixture passwords, mode 0600, отсутствие credentials в stdout, отказ при смене cluster_id/потере init file, read-only отказ при другой установленной версии.

## Границы проверенного

Windows Active Directory и его nested-group matching rule не тестировались на живом DC: поставлены LDAP/AD параметры и готовый пример фильтра, а фактическая аутентификация/групповые ACL проверены с OpenLDAP. Проверка AD DN, CA, userattr/groupattr и членства выполняется на тестовом домене оператора.

Kubernetes flow использует реальный Vault plugin и подписанный JWT, но fixture TokenReview API. Браузерный OIDC flow, корпоративный IdP и mTLS с обязательным client certificate не разворачивались.

Полная установка RPM/systemd новым installer на текущем узле не запускалась: пользователь запросил подготовить скрипт, а существующая другая версия Vault должна остаться нетронутой. Подтверждены совместимость бинарника RPM с РЕД ОС 7.3, реальные API-тесты этой версии, подпись/хеш пакета, синтаксис и защищённая bootstrap/recovery логика. Системный deploy проверяется на выделенном пустом стенде командой из scripts/README.md.

Общей транзакции/CAS в API нет; межхостовую сериализацию обеспечивает CI. Полное отсутствие старых токенов/внешних зависимостей нельзя доказать API-чтением: опасный prune access objects требует актуального хеша и операторского подтверждения. Mount removal отсутствует полностью, независимо от таких подтверждений.

English: The exact 2.0.4 RED OS RPM was verified and extracted into the workspace; its binary passed the full isolated API/HA/LDAP suite without changing the installed server. LDAP login and group authorization were exercised against OpenLDAP, not a live Windows DC. The persistent RPM/TLS/systemd installer is supplied and unit tested; system installation was intentionally not executed on this host with another Vault version. Use a dedicated lab host.


## Дополнение: наполнение LDAP для РЕД ОС 8

Поставлен самостоятельный `scripts/seed-test-ldap-redos8.py` и инструкция `scripts/LDAP-REDOS8.md`. Изменений в API-логике роли нет.

- PASS: 9 новых unit-тестов наполнения; весь unit-набор — 47 tests.
- PASS: 2 новых интеграционных сценария (`test_seeded_ldap.py`) на изолированном OpenLDAP 2.4.57 и Vault 2.0.4.
- Проверены read-only check, создание отдельной MDB и 11 entries, сохранение UUID/паролей/изменённого членства, отсутствие паролей в argv/stdout, permissions 0600.
- Bind account реально получает отказ LDAP 50 при попытке записи и не видит userPassword; все четыре аккаунта проходят LDAP/Vault login и получают только свои групповые права.
- Восстановление после успешного LDAP add с потерянным ответом сохраняет исходные credentials и завершает pending entry без повторного создания.
- LDAP часть запускается в контейнере; целевая systemd/RPM обёртка РЕД ОС 8 не выполнялась на реальном узле. CLI-paths и SASL/EXTERNAL сверены с официальной инструкцией РЕД ОС 8. Текущий execution host — РЕД ОС 7.3 и не изменялся.

Журнал: `.work/ldap-seed-integration.log`. Приватные файлы и базы тестовых контейнеров удаляются после проверки.

## Дополнение: один административный токен — 2026-10-25

- PASS: 55 unit-тестов и syntax-check example playbook.
- PASS: `test_bootstrap_policy_works_without_root_token` на Vault 2.0.4: неизменённая политика из роли, один non-root token, произвольный policy prefix, вложенные userpass/AppRole auth paths, создание KV mount, создание/изменение ACL, назначения существующей AppRole, идемпотентность, export и подтверждённый prune ACL.
- PASS: 4 сценария `test_ldap_mounts.py` на Vault 2.0.4/OpenLDAP, включая создание вложенного LDAP auth mount, external group и grant одним административным токеном; реальный LDAP login получает групповые права.
- Vault непосредственно возвращает HTTP 403 на DELETE secret/auth mount с этим токеном, в обход защитной проверки REST-клиента. Прямая запись пользовательских KV data также запрещена ACL. Администратор с правом изменения ACL может расширить собственные полномочия.
- PASS: UTF-8/LF изменённых файлов и синтаксис Python. Полный integration/Molecule набор повторно не запускался.
- Обнаруженное существующее ограничение: обратный экспорт ACL для вложенного KV mount (например, `company/apps`) отклоняется компилятором. В проверке экспорта использован обычный KV mount; вложенные auth paths проверены отдельно и работают. Логика экспорта в этом изменении не менялась.

## Дополнение: inventory и два playbook для redos8 без TLS — 2026-10-25

- Пример `examples/redos8-lab` содержит ровно два вызова основных ролей: `01-install.yml` → `hashicorp-vault`, `02-configure.yml` → `vault-configuration`. Bind DN, bind password и локальные пароли задаются в group_vars. Вспомогательная роль удалена.
- PASS: 58 unit-тестов, включая однократное создание общего userpass mount, порядок создания до пользователей/aliases, конфликты типа/пути/accessor и запрет prune auth mount.
- PASS: 6 интеграционных сценариев на Vault 2.0.4/OpenLDAP: обновлённый `test_redos8_example_inventory_and_playbooks`, `test_bootstrap_policy_works_without_root_token` и 4 сценария `test_ldap_mounts.py`.
- В примере первый playbook вызывается с `--tags init` на настоящем неинициализированном Vault с файловым storage: роль сама создаёт приватный каталог, выполняет init/unseal, пишет файл 0600 и сохраняет initial root token и ключи при повторном запуске. Только установка RPM/systemd заменена временным процессом Vault.
- Полный второй playbook получает единственный токен из результата init и bind-пароль через inventory, без SSH-чтения секретов. Проверены dry/check до создания auth mounts, apply и повторный apply с changed=0, реальные входы двух локальных и четырёх LDAP-пользователей, положительные и отрицательные проверки групповых прав.
- Non-root административный токен также создаёт отсутствующий вложенный userpass auth mount в общем плане, затем управляет пользователями, ACL и существующей AppRole. LDAP-регрессии прошли после выделения общего планирования auth mounts.
- PASS: syntax-check обоих playbook; проверка ровно одной требуемой роли в каждом и отсутствия tasks/pre_tasks/post_tasks/handlers; YAML/Python/Bash syntax и UTF-8/LF. Токены, доли ключа и пароли не попадают в вывод Ansible.
- Установка RPM/systemd на реальном РЕД ОС 8 и пользовательский сервер `redos8` не затрагивались. Полный Molecule/HA набор в этом изменении повторно не запускался.

## Дополнение: YAML-результат dry — 2026-10-25

- Обычный dry в роли автоматически сохраняет YAML-файл; путь и имя задаются `vault_configuration_config_report_destination`. Default: `{{ playbook_dir }}/vault-configuration-{{ inventory_hostname }}-dry.yml`; в inventory redos8: `.state/dry-result.yml`.
- PASS: 59 unit-тестов, включая отказ до API-запросов при отсутствии PyYAML для YAML-отчёта.
- PASS: 3 интеграционных сценария на Vault 2.0.4: `test_dry_check_export_and_transfer`, `test_ansible_import_vars_files_check_diff`, `test_redos8_example_inventory_and_playbooks` (с OpenLDAP).
- Проверены обычный YAML, чтение через safe_load, mode/plan/digest/summary, имя из inventory и имя по умолчанию, permissions 0600, отсутствие токенов и локальных/LDAP-паролей. Повторный dry не переписывает одинаковый отчёт; --check не создаёт файл. Реестр и API Vault в dry не изменяются; конфликт пути с реестром отклоняется.
- Apply и export сохраняют прежний контракт, включая changed=0 при повторном apply. В redos8 destination включён только для dry, чтобы apply не перезаписывал сохранённый план.
- PASS: syntax-check, YAML/JSON/Python/Bash syntax и UTF-8/LF изменённых файлов. Полный integration/Molecule набор не повторялся.

## Дополнение: видимость отчёта apply — 2026-10-25

- `Publish the sanitized result` теперь выводит отчёт стандартным callback без `-v`, включая mode, plan, summary и результат применения. API-задача продолжает работать с no_log.
- В inventory устранено повторное объявление `vault_configuration_token`; программно проверено сохранение всех эффективных значений credentials без вывода самих значений.
- PASS: `test_ansible_import_vars_files_check_diff` и `test_redos8_example_inventory_and_playbooks` на временных Vault 2.0.4/OpenLDAP. Проверены видимые три сводки и mode=apply при обычной verbosity, отсутствие токенов и локального/LDAP-пароля в stdout, прежние dry/check/apply/export и идемпотентность.
- Тест примера явно подставляет временные токен и пароли, чтобы ручные изменения credentials inventory не использовались против тестовых серверов.
- PASS: syntax-check, Python/YAML syntax, отсутствие дубликатов ключей credentials и UTF-8/LF. Пользовательский Vault не применялся и не перезапускался.

## Дополнение: YAML export и пять mounts — 2026-10-25

- Основной export теперь сериализуется в обычный YAML через safe_dump; JSON сохранён только для отдельного `.audit.json`. Проверка PyYAML выполняется до API-запросов. Существующий JSON-вариант основного файла перезаписывается в YAML при повторном export.
- В `examples/redos8-lab/group_vars/vault/20-configuration.yml` исправлен override списка mounts: certs, infra, apps, cicd, users.
- PASS: 59 unit-тестов и 25 интеграционных сценариев на Vault 2.0.4: все 20 `test_vault.py`, 4 `test_ldap_mounts.py` и пример redos8 из `test_seeded_ldap.py`.
- Подтверждены YAML-экспорт и импорт через настоящий Ansible vars_files, сохранение Go LDAP filters, JSON-аудит, отсутствие секретов и прежние dry/check/apply/export сценарии.
- Новый `test_expand_three_mounts_to_five_without_recreating_existing` создаёт начальные apps/infra/users, применяет желаемые пять и проверяет ровно две записи создания: certs/cicd. Данные sys/mounts существующих трёх mounts не меняются; повторный apply имеет changed=false. Пример redos8 также проверяет тип kv/version=2 всех пяти mounts.
- Полный Molecule/HA набор не запускался повторно; на пользовательском Vault изменения не выполнялись.

## Дополнение: dry только с изменениями — 2026-10-25

- В публичном dry-плане исключены операции noop. Фильтрация применяется к результату до записи YAML и вывода Ansible; полный план для executor и вычисленный digest сохранены.
- PASS: `test_dry_reports_only_changes_and_preserves_plan_digest` на временном Vault 2.0.4: после converge список операций пуст и все счётчики нулевые; после изменения disabled в отчёт входит ровно один update. Проверены YAML, отсутствие записей noop, неизменность Vault в dry и совпадение digest с полным apply/check-планом.
- PASS: `test_ansible_import_vars_files_check_diff`: в YAML и обычном консольном dry после converge нет noop; apply/check/export и повторный запуск сохраняют прежнее поведение.
- PASS: Python syntax и UTF-8/LF изменённых файлов. Полный набор интеграционных/Molecule тестов не повторялся.

## Дополнение: personal_access по LDAP-логину — 2026-10-26

- Добавлены identity_source=ldap_login, auth_mount и path_prefix. Политика использует `identity.entity.aliases.<LDAP accessor>.name`; subjects допускают пользователей и группы по id/uuid. Прежний entity_id остаётся default.
- PASS: 63 unit-теста, включая компиляцию/обратное преобразование шаблона, nested prefix, отложенное разрешение нового accessor, username_as_alias, ограничения subjects и недопустимых путей/accessors, миграционный guard, сохранность membership существующей внешней группы.
- PASS на Vault 2.0.4: 21 сценарий `test_vault.py` и 6 `test_ldap_mounts.py`. Прежние UUID personal policies, общий dry/apply/export, ownership и recovery прошли регрессии.
- PASS на Vault 2.0.0: оба новых сценария personal LDAP policies, включая YAML export/import. Реальные версии бинарников проверены локально.
- Новая LDAP policy создаётся вместе с LDAP auth mount одним apply и non-root административным токеном. Проверены readonly dry/check и применение expected_plan_digest, созданного до выделения accessor.
- Реальные Alice/Bob получают read/write/list только под своим users/dep1/<login>/*; чтение и запись чужой области, другой prefix, родительский LIST и токен без LDAP alias получают отказ. Alice сохраняет UUID при повторном входе и обновлении policy. Charlie добавлен в LDAP после apply и получает свой путь без изменения inventory или повторного apply; users в desired sections отсутствуют.
- YAML-export восстанавливает auth_mount вместо source accessor. Полный Ansible vars_files импорт на второй Vault использует новый accessor; повторный apply идемпотентен, все три LDAP-пользователя получают собственные пути. Токен и bind-пароль не попадают в stdout.
- Снятие personal policy отключает доступ существующего LDAP-токена. Для existing group UUID metadata и автоматическое LDAP membership сохраняются. Исправлены формирование payload external UUID groups и отсутствие path у модели detach-only.
- PASS: JSON Schema и runtime validation нового/старого формата, пример ldap-personal-access.yml, RU/EN примеры, syntax-check playbook, Python/JSON/YAML syntax, UTF-8/LF.
- Живой Windows AD, повторный полный Molecule/HA и пользовательский Vault не затрагивались. Логины для именованных путей должны быть безопасными одиночными сегментами; rename/reuse LDAP-логина и перенос самих KV data остаются эксплуатационной ответственностью.
