# Роль `hashicorp-vault`

Роль устанавливает HashiCorp Vault на RedOS или EL-совместимую систему и настраивает
integrated storage (Raft) для одного либо трёх узлов. Поддерживаются установка пакета
`vault` из подключённого репозитория RedOS и установка готового исполняемого файла из
`files/` роли.

При первом запуске роль инициализирует Vault пятью долями ключа Шамира с порогом две
доли, сохраняет результат только на Ansible-контроллере с правами `0600` и распечатывает
узлы двумя долями. Файл содержит unseal-ключи и root token: его необходимо немедленно
перенести в защищённое хранилище, проверить резервную копию и удалить рабочую копию.

## Требования

- Ansible 2.13 или новее;
- RedOS либо EL-совместимая система версии 7 или новее;
- inventory-группа ровно из одного или трёх узлов;
- пакет Vault в настроенном репозитории или Linux-бинарник в `files/vault`.

## Переменные

### Установка и пути

| Переменная | Значение по умолчанию | Описание |
|---|---|---|
| `hashicorp_vault_install_method` | `package` | `binary` или `package`. |
| `hashicorp_vault_package_name` | `vault` | Имя пакета в репозитории RedOS. |
| `hashicorp_vault_package_version` | `2.0.1-1.el7` | Версия и release пакета RedOS. |
| `hashicorp_vault_binary_file` | `vault` | Файл внутри `files/`; с `remote_src` — абсолютный путь на узле. |
| `hashicorp_vault_binary_remote_src` | `false` | Брать бинарник с управляемого узла, а не из роли. |
| `hashicorp_vault_binary_path` | `/usr/local/bin/vault` | Путь установки бинарника. |
| `hashicorp_vault_versionlock` | `true` | Зафиксировать установленную пакетную версию. |
| `hashicorp_vault_user` / `hashicorp_vault_group` | `vault` | Системные пользователь и группа. |
| `hashicorp_vault_config_dir` | `/etc/vault.d` | Каталог конфигурации. |
| `hashicorp_vault_data_dir` | `/var/lib/vault` | Каталог integrated storage. |
| `hashicorp_vault_log_dir` | `/var/log/vault` | Каталог логов. Сам сервис пишет в journald. |
| `hashicorp_vault_log_archive_dir` | `/var/log/vault/archive` | Каталог архивов логов. |
| `hashicorp_vault_tls_dir` | `/etc/vault.d/tls` | Каталог сертификатов. |
| `hashicorp_vault_service_name` | `vault` | Имя systemd-сервиса. |
| `hashicorp_vault_environment_file` | `/etc/sysconfig/vault` | Environment-файл сервиса. |
| `hashicorp_vault_service_environment` | `{}` | Дополнительные переменные окружения сервиса. |

### Кластер и Vault

| Переменная | Значение по умолчанию | Описание |
|---|---|---|
| `hashicorp_vault_cluster_group` | `vault` | Inventory-группа из 1 или 3 узлов. |
| `hashicorp_vault_cluster_name` | `vault` | Имя Raft-кластера. |
| `hashicorp_vault_api_port` / `hashicorp_vault_cluster_port` | `8200` / `8201` | API- и cluster-порты. |
| `hashicorp_vault_bind_address` | `0.0.0.0` | Адрес listener. |
| `hashicorp_vault_api_address` | `inventory_hostname` | DNS-имя узла для API-запросов, `api_addr`, `cluster_addr` и `retry_join`; должно входить в SAN TLS-сертификата. |
| `hashicorp_vault_disable_mlock` | `true` | Отключить `mlock`; для production рекомендуется настроить capability и `false`. |
| `hashicorp_vault_ui` | `true` | Включить web UI. |
| `hashicorp_vault_log_level` | `info` | Уровень логирования Vault. |
| `hashicorp_vault_telemetry_enabled` | `true` | Включить telemetry-блок Vault для Prometheus. |
| `hashicorp_vault_prometheus_retention_time` | `30s` | Время хранения метрик в памяти для Prometheus endpoint. |
| `hashicorp_vault_telemetry_disable_hostname` | `true` | Не добавлять hostname Vault в имена метрик. |
| `hashicorp_vault_unauthenticated_metrics_access` | `true` | Разрешить Prometheus читать endpoint без Vault token. |
| `hashicorp_vault_required_packages` | `[ca-certificates]` | Системные зависимости. |
| `hashicorp_vault_minimum_os_major_version` | `7` | Минимальная основная версия ОС. |

### Инициализация и секреты

| Переменная | Значение по умолчанию | Описание |
|---|---|---|
| `hashicorp_vault_initialize` | `true` | Инициализировать ещё не инициализированный Vault. |
| `hashicorp_vault_key_shares` | `5` | Число долей ключа; роль требует ровно 5. |
| `hashicorp_vault_key_threshold` | `2` | Порог распечатывания; роль требует ровно 2. |
| `hashicorp_vault_auto_unseal_after_init` | `true` | Распечатать узлы сохранёнными долями при выполнении роли. |
| `hashicorp_vault_init_output_path` | `{{ playbook_dir }}/vault-init-keys.json` | Защищённый файл на контроллере. |
| `hashicorp_vault_init_output_owner` | пользователь контроллера | Владелец файла инициализации. |
| `hashicorp_vault_init_output_group` | не изменять | Группа файла инициализации. |
| `hashicorp_vault_no_log` | `true` | Скрывать ключи, токены, сертификаты и environment из вывода Ansible. |

Отсутствующий родительский каталог `hashicorp_vault_init_output_path` роль создаёт на контроллере с mode `0700` до инициализации. Права существующего каталога сохраняются; подготовка каталога отдельными задачами playbook не требуется.

Если Vault уже инициализирован, для автоматического распечатывания роль читает тот же
защищённый JSON-файл. При его отсутствии роль останавливается, чтобы не создавать ложное
ощущение восстановленного доступа. Для ручного распечатывания установите
`hashicorp_vault_auto_unseal_after_init: false`.

### TLS

| Переменная | Значение по умолчанию | Описание |
|---|---|---|
| `hashicorp_vault_tls_enabled` | `false` | Включить TLS listener. |
| `hashicorp_vault_api_validate_certs` | `true` | Проверять сертификат в API-запросах роли. |
| `hashicorp_vault_hashi_vault_path` | `""` | Пусто — локальные файлы; `secret=...:` — lookup `hashi_vault`. |
| `hashicorp_vault_hashi_vault_path_root` | `""` | Путь lookup для корневого CA. |
| `hashicorp_vault_hashi_vault_path_certificates` | значение предыдущей переменной | Выбранный источник сертификатов. |
| `hashicorp_vault_certfile` | `<host>.cer` | Имя сертификата узла. |
| `hashicorp_vault_cerkeyfile` | `<host>.key` | Имя закрытого ключа. |
| `hashicorp_vault_cacertfile` | `root.cer` | Имя корневого CA. |
| `hashicorp_vault_local_certs_path` | `./certs/` | Путь сертификатов на контроллере. |
| `hashicorp_vault_certificates` | список CA/cert/key | Подготовленное содержимое для `ssl.yml`. |

Переключение локального источника сертификатов на HashiCorp Vault выполняется только
переменными. Lookup-логика не находится в tasks.

## Inventory

Одноузловой вариант:

```ini
[vault]
vault1.example.org ansible_host=10.10.10.11
```

Трёхузловой вариант:

```ini
[vault]
vault1.example.org ansible_host=10.10.10.11
vault2.example.org ansible_host=10.10.10.12
vault3.example.org ansible_host=10.10.10.13
```

## Playbook

Установка бинарника `roles/hashicorp-vault/files/vault`:

```yaml
---
- name: Deploy Vault
  hosts: vault
  become: true
  roles:
    - role: hashicorp-vault
      hashicorp_vault_install_method: binary
      hashicorp_vault_init_output_path: "{{ playbook_dir }}/private/vault-init.json"
```

Установка из репозитория RedOS:

```yaml
---
- name: Deploy packaged Vault
  hosts: vault
  become: true
  roles:
    - role: hashicorp-vault
      hashicorp_vault_install_method: package
      hashicorp_vault_package_version: 2.0.1-1.el7
```

## Теги

- `pre-req` — проверки ОС, topology, параметров и файлов;
- `user` — системные пользователь и группа;
- `install` — зависимости, каталоги и Vault;
- `ssl` — сертификаты;
- `config` — HCL, systemd и запуск;
- `init` — инициализация и распечатывание;
- `clean` — полное удаление, используется вместе с `hashicorp_vault_clean_confirm=true`;
- `never` — блокирует случайный запуск очистки.

## Метрики Prometheus

При `hashicorp_vault_telemetry_enabled: true` метрики доступны по адресу
`/v1/sys/metrics?format=prometheus` на API-порту Vault. По умолчанию endpoint доступен
без Vault token, чтобы Prometheus мог опрашивать его напрямую. Для защищённого endpoint
задайте `hashicorp_vault_unauthenticated_metrics_access: false` и настройте передачу
токена с правом `read` на `sys/metrics` в Prometheus.

```yaml
scrape_configs:
  - job_name: vault
    metrics_path: /v1/sys/metrics
    params:
      format: [prometheus]
    static_configs:
      - labels:
          env: production
          group: vault
        targets:
          - vault1.example.org:8200
```

Готовый дашборд Grafana 12 находится в `dashboards/vault.json`. Он использует
Prometheus datasource variable и фильтры `job`, `env`, `group`, `instance`. Метки
`env` и `group` должны быть заданы в `scrape_config`, как в примере выше.

## Molecule

Сценарий `default` поднимает три systemd-контейнера RedOS 7.3.6, устанавливает
`vault-2.0.1-1.el7` из репозитория `updates`, разворачивает Raft,
проверяет сервис, API, Prometheus metrics endpoint, запись и чтение KV, останавливает один follower и повторяет
запись/чтение при отказе узла. Сценарий `single` проверяет одноузловой вариант.

```bash
molecule test -s default
molecule test -s single
```

Сценарии используют локальный образ `molecule_local/redos:7.3.6`; загрузка внешнего
бинарника в тестах не выполняется.

## Удаление

Очистка необратимо удаляет Raft-данные узла:

```bash
ansible-playbook site.yml --tags clean -e hashicorp_vault_clean_confirm=true
```

Файл с init-ключами на контроллере роль намеренно не удаляет.
