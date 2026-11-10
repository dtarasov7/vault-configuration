# Changelog

## 1.1.0 — 2026-11-10

- Added safe transport diagnostics for DNS, connectivity, timeouts, TLS and certificate verification with verify_code. Messages include TLS validation settings, CA source, timeout and disabled proxy use without exposing secrets or raw exception text.
- CA/client certificate/key loading failures identify the stage and safe reason; HTTP error and uncertain-write recovery semantics are preserved.

### Changes — 2026-10-26

- Added personal_access with identity_source=ldap_login, auth_mount and path_prefix: login-templated policies assigned to users/groups without enumerating LDAP members.
- Accessors are resolved automatically, including mounts created in the same apply; recorded accessor changes require migration. Added portable YAML export/import while preserving entity_id behavior.

### Documentation — 2026-10-26

- Added named LDAP personal paths, existing-entity assignments and a shared LDAP-group templated policy, with explicit current role limitations.

## 1.0.0 — 2026-10-24

- Clarified groupdn/groupattr/alias.name, DN and wildcard-alias limitations, and partial-CN group searches with membership checks.
- Documented both LDAP authorization mechanisms, Identity Groups UI locations and a shared internal group for local and LDAP users.
- Dry YAML and console reports now omit noop objects and show only changes; the complete internal plan and digest are preserved.
- Main exports now use ordinary YAML; separate audits remain JSON. Restored all five KV v2 mounts in the redos8 inventory: certs, infra, apps, cicd, users.
- The sanitized apply report is now visible at normal Ansible verbosity without `-v`.
- Ordinary dry runs automatically save a 0600 YAML report; inventory selects its path/name through `vault_configuration_config_report_destination`. Added the PyYAML runtime dependency for reporting.
- The `examples/redos8-lab` example uses only `hashicorp-vault` and `vault-configuration`, with bind credentials and local passwords in inventory. The API role creates missing userpass auth mounts in its normal plan.
- Made the single-token administrative policy independent of mount names and policy prefixes; documented token creation using root in README.
- Added create-only KV v2 mounts, LDAP/AD authentication and external bind credentials; removed local deletion tasks.
- Added a separate persistent RPM/TLS Vault 2.0.4 lab installer for RED OS 7.3; split export and reconcile tasks.
- Replaced the `vault_configuration_config` dictionary with independent `vault_configuration_config_*` variables, including connection/management/safety settings.
- Added API management of Vault Identity, userpass, KV v2 ACLs and assignments to existing auth roles.
- Added standalone dry, apply/check/diff, ownership registry, adoption, guarded prune and partial-apply recovery journal.
- Added reverse export of actual ACLs, external password inputs, TLS and credential-safe redirect rejection.
- Included inventory/state schemas, bootstrap policy, examples, unit/integration tests and Docker Molecule default/HA scenarios.
- Exact tested versions and results are recorded in TEST-REPORT.md; other profiles are not claimed as supported.
