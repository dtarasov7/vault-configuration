# `hashicorp-vault` role

This role installs HashiCorp Vault on RedOS or an EL-compatible host and configures
integrated Raft storage for exactly one or three nodes. Vault can be installed from a
configured RedOS repository or from an executable placed in the role's `files/` directory.
The default package version is `vault-2.0.1-1.el7` from the RedOS `updates` repository.

On first deployment, the role creates five Shamir key shares with a threshold of two,
stores the initialization response only on the Ansible controller with mode `0600`, and
unseals every node with two shares. Move that file to protected storage immediately,
verify its backup, and remove the working copy.

## Main variables

- Installation: `hashicorp_vault_install_method` (`binary` or `package`),
  `hashicorp_vault_package_name`, `hashicorp_vault_package_version`,
  `hashicorp_vault_binary_file`, `hashicorp_vault_binary_remote_src`,
  `hashicorp_vault_binary_path`, and `hashicorp_vault_versionlock`.
- Paths and identity: `hashicorp_vault_user`, `hashicorp_vault_group`,
  `hashicorp_vault_config_dir`, `hashicorp_vault_data_dir`, `hashicorp_vault_log_dir`,
  `hashicorp_vault_log_archive_dir`, `hashicorp_vault_tls_dir`,
  `hashicorp_vault_service_name`, and `hashicorp_vault_environment_file`.
- Cluster: `hashicorp_vault_cluster_group`, `hashicorp_vault_cluster_name`,
  `hashicorp_vault_api_port`, `hashicorp_vault_cluster_port`,
  `hashicorp_vault_bind_address`, `hashicorp_vault_api_address`,
  `hashicorp_vault_disable_mlock`, `hashicorp_vault_ui`, and `hashicorp_vault_log_level`.
  `hashicorp_vault_api_address` defaults to `inventory_hostname` and must be a DNS name
  present in the Vault TLS certificate SAN.
- Telemetry: `hashicorp_vault_telemetry_enabled`,
  `hashicorp_vault_prometheus_retention_time`, `hashicorp_vault_telemetry_disable_hostname`,
  and `hashicorp_vault_unauthenticated_metrics_access`.
- Initialization: `hashicorp_vault_initialize`, `hashicorp_vault_key_shares` (must be 5),
  `hashicorp_vault_key_threshold` (must be 2), `hashicorp_vault_auto_unseal_after_init`,
  `hashicorp_vault_init_output_path`, `hashicorp_vault_init_output_owner`,
  `hashicorp_vault_init_output_group`, and `hashicorp_vault_no_log`.
- TLS: `hashicorp_vault_tls_enabled`, `hashicorp_vault_api_validate_certs`,
  `hashicorp_vault_hashi_vault_path`, `hashicorp_vault_hashi_vault_path_root`,
  `hashicorp_vault_certfile`, `hashicorp_vault_cerkeyfile`,
  `hashicorp_vault_cacertfile`, `hashicorp_vault_local_certs_path`, and
  `hashicorp_vault_certificates`.
- Cleanup: `hashicorp_vault_clean_confirm` must be true before destructive cleanup runs.

Before initialization, the role creates a missing parent directory of `hashicorp_vault_init_output_path` on the controller with mode `0700`. Existing directory permissions are preserved; no separate playbook preparation tasks are needed.

See `defaults/main.yml` for documented defaults and `README.md` for the complete variable
table, inventory examples, TLS source selection, and operational warnings.

## Inventory and playbook

```ini
[vault]
vault1.example.org ansible_host=10.10.10.11
vault2.example.org ansible_host=10.10.10.12
vault3.example.org ansible_host=10.10.10.13
```

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

## Tags and tests

When telemetry is enabled, Prometheus metrics are exposed at
`/v1/sys/metrics?format=prometheus`. Anonymous scrape access is enabled by default; set
`hashicorp_vault_unauthenticated_metrics_access: false` and configure a token with read
access to `sys/metrics` when the endpoint must be protected.
The Grafana 12 dashboard is provided at `dashboards/vault.json` and uses Prometheus
datasource, `job`, `env`, `group`, and `instance` variables. Set the `env` and `group`
labels in the Prometheus scrape configuration.

Tags are `pre-req`, `user`, `install`, `ssl`, `config`, `init`, `clean`, and `never`.
The default Molecule scenario uses `molecule_local/redos:7.3.6` and tests a three-node
cluster, Prometheus metrics, KV I/O, and operation after one follower is stopped. The `single` scenario tests
one-node deployment with the same RedOS image and Vault 2.0.1 package.

```bash
molecule test -s default
molecule test -s single
```
