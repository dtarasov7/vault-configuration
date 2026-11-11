# vault-configuration

Version: [1.3.0](VERSION). Stateless Ansible configuration of Vault KV v2 mounts, Identity, userpass, LDAP/AD, ACLs and existing AppRole/Kubernetes/JWT/OIDC roles. The role never installs Vault or reads application KV data.

## Targets and execution

Select exactly one target through hosts/inventory/--limit. `inventory_hostname` must be the Vault DNS hostname, not an IP or a convenient alias; `ansible_host` is for SSH only. Disable fact gathering when SSH is unavailable.

```yaml
- hosts: vault
  gather_facts: false
  roles: [vault-configuration]
```

```yaml
vault_configuration_api_execution: controller
vault_configuration_api_scheme: https
vault_configuration_api_port: 8200
vault_configuration_api_use_loopback: false
```

The API URL uses scheme://inventory_hostname:port. Controller execution forces a local connection and the controller Python interpreter, without SSH to target. Target execution uses the target's inventory connection/interpreter. The module runs without become; privileges come from the Vault token. Loopback is valid only with target execution and uses 127.0.0.1. TLS verification remains independent; explicitly set vault_configuration_config_connection_validate_tls:false if using a DNS-only certificate with loopback. HTTPS still encrypts traffic. Explicit scheme:http needs no additional opt-in variable.

CA/client certificate/key paths must exist on the API execution host; they are not copied automatically. Variable lookups, including lookup('file'), execute on the controller. Python standard library is sufficient for API execution; PyYAML is required on the controller.

## Defaults and controller artifacts

Every input and default is documented in Russian in [defaults/main.yml](defaults/main.yml); [JSON Schema](schemas/inventory.schema.json) validates inventory shape. All configuration/export settings are flat. Desired users/groups/grants/auth_roles/personal_access/ldap sections default to null (unmanaged); [] explicitly declares an empty list and never deletes objects. vault_configuration_context/result are task outputs, not defaults.

Dry YAML, export YAML/audit JSON, and optional apply JSON are always saved on the controller. Relative paths resolve from playbook_dir. Files are atomically replaced with mode 0600; new directories use 0700. Symlink destinations are rejected. Check mode predicts changes without creating files. Dry requires a report destination; apply reporting is optional.

```yaml
vault_configuration_config_mode: export
vault_configuration_export_scope: managed
vault_configuration_export_destination: ./vault-access-manager-export.yml
vault_configuration_export_audit_destination: ./vault-access-manager-export.yml.audit.json
vault_configuration_export_allow_partial: false
```

Export filters use vault_configuration_export_ plus mounts/auth_mounts/entities/groups/policies/auth_roles/users/ldap. Scoped entities/groups use names/UUIDs; users/roles use auth_mount/name; LDAP uses auth mount. Managed selection discovers owner metadata, policy prefixes and related aliases. Isolated LDAP backends require explicit scoped/ldap selection. Exported LDAP IDs are derived from mount paths; supply external bind passwords under the exported IDs. Export payloads are ordinary vars_files YAML; source IDs/accessors/ownership and dependencies go into the separate audit. Unsupported/lossy ACLs fail unless allow_partial is explicitly enabled. Passwords and connection credentials are not exported. Vault Go templates remain literal on import.

## No registry

Every run reconciles inventory against live Vault. No registry, backup, recovery journal or local apply lock exists. Old registry files are neither read nor deleted. Independent controllers work with the same owner/prefix and inventory.

Entities/groups carry vam_owner/vam_id metadata. These identify stable UUIDs across renames. Foreign owners and duplicate IDs fail; unmarked identities require explicit management_adoption with UUID/hash. Policies belong to a unique owner prefix; separate owners must not share a prefix. Declared LDAP configs explicitly manage the selected backend settings.

When grants is supplied, assignments of ordinary policies in that prefix are authoritative across current subjects, including identities omitted from users/groups. Personal policy assignments are managed separately only when personal_access is supplied. Other policies are preserved. existing_policies outside the prefix are added explicitly but are not removed automatically when omitted: their assignment provenance cannot be inferred without history.

Declared internal groups have authoritative members/member_groups. External LDAP memberships remain controlled by authentication; shared UUID subjects retain metadata/membership. Objects are never automatically deleted: missing declarations leave users/groups/aliases/policies/backends in place. Explicit disabled and personal_access.enabled:false support disabling users and detaching personal rights. Missing KV/auth mounts are created; incompatible engines and overlapping paths fail.

Serialize apply jobs per cluster in CI/CD. There is no distributed lock and no general multi-object Vault transaction/CAS. Snapshot and pre-write drift checks reduce conflicts but do not replace serialization. Failures report confirmed/uncertain operations, never retry or roll back automatically. Inspect live configuration and run dry again after a lost response.

## Password policies

Userpass password_policy and LDAP bind_password_policy default to on_create. Credentials are required on creation, and LDAP bind passwords also when binddn changes. Existing objects can be reconciled without passwords. Explicit always writes the supplied password on every apply and always reports changed; use it to rotate/correct a credential, then restore on_create. Inventory password changes alone do not rotate existing credentials. Password values cannot be read back; verify authentication after an uncertain write. Removed fields: password_revision/bind_password_revision and on_revision.

## KV v2 permissions

| Permission | API prefix | Capabilities | Allows |
| --- | --- | --- | --- |
| `read` | data | read | Read the latest or a specified secret version. |
| `write` | data | create, update | Create secrets and write new versions of their contents. |
| `patch` | data | patch | Partially update an existing secret through PATCH, creating a new version. |
| `list` | metadata | list | List key and directory names without reading secret contents. |
| `read_metadata` | metadata | read | Read key metadata and version information without secret contents. |
| `update_metadata` | metadata | create, update | Create and update key metadata: custom metadata, version limits, CAS and automatic version deletion. |
| `delete_latest` | data | delete | Soft-delete the latest version; it remains recoverable until destroyed. |
| `delete_versions` | delete | update | Soft-delete specified versions; they remain recoverable until destroyed. |
| `undelete_versions` | undelete | update | Restore soft-deleted versions. |
| `destroy_versions` | destroy | update | Permanently destroy the contents of specified versions. |
| `delete_metadata` | metadata | delete | Permanently delete the key, its metadata and every secret version. |

Paths use mount/path/scope exact|subtree. Subtrees include a base rule and /*; exact+list is rejected. Whole-mount access uses path:"", scope:subtree and safety_allow_mount_root:true. destroy_versions/delete_metadata require safety_allow_destructive_grants:true. See [AD full-access example](examples/ldap-ad.yml). Secret rights do not grant mount administration. Ancestor LIST/discovery is explicit and exposes sibling names.

## Permission aliases

Both grants[].paths[].permissions and personal_access.permissions accept a scalar name or a mixed list of operations/aliases:

| Alias | Canonical operations |
|---|---|
| `all` | All 11 KV v2 permissions, including irreversible version/metadata deletion |
| `read_only` | list, read, read_metadata |
| `read_write` | list, read, read_metadata, write, patch, update_metadata |

Examples: `permissions: all`, `permissions: read_only`, `permissions: [read_only, write]`, `permissions: [read_write, delete_latest]`. read_write includes no delete/undelete/destroy operations. Aliases do not change subjects, mount/path/scope or grant Vault/mount administration.

Aliases expand before safety validation: all requires config_safety_allow_destructive_grants:true; a mount-root grant separately requires config_safety_allow_mount_root:true. All three aliases include list and therefore require subtree scope in grants. For exact scope use explicit operations without list. Overlapping sets are deduplicated; repeated input names remain invalid.

Equivalent aliases and explicit lists produce identical ACLs and plan digests, with no Vault changes when switching representations. Export retains explicit lists; matrix retains its 11 positions. The [AD example](examples/ldap-ad.yml) uses all for infra and personal users/<login>/* access.

## LDAP/AD and personal paths

Examples: [OpenLDAP](examples/ldap-openldap.yml), [AD](examples/ldap-ad.yml), [personal access](examples/ldap-personal-access.yml), [inventory](examples/inventory.yml). The AD example uses auth path ldap, plain LDAP Global Catalog port 3268, starttls:false and explicit allow_insecure_ldap:true. Plain LDAP is permitted in any environment; LDAPS uses 636/3269, StartTLS uses ldap:// with starttls:true. LDAP certificate/insecure_tls settings are independent of Vault API TLS.

AD uses samaccountname, groupattr cn and nested-group matching rule 1.2.840.113556.1.4.1941. groupdn is a full search-base DN; groupfilter can select partial CNs, but alias.name must exactly match groupattr (lowercase with case_sensitive_names:false). Preserve Go filters through Jinja string literals as in the examples.

LDAP `config.certificate` remains supported. Supply X.509 PEM CA **contents**, for example `certificate: "{{ lookup('file', playbook_dir ~ '/files/ad-ca-chain.pem') }}"`, or an inline YAML PEM block. The file is read on the controller; Vault uses the supplied contents to verify AD during LDAPS/StartTLS with `insecure_tls: false`. An empty certificate uses the Vault server's system trust store. This setting is independent of the API client's `vault_configuration_config_connection_ca_file`. Plain LDAP with starttls:false does not use it. The AD example retains plain LDAP and documents optional LDAPS/StartTLS settings. See [LDAP API](https://developer.hashicorp.com/vault/api-docs/auth/ldap).

The [AD example](examples/ldap-ad.yml) grants all 11 personal KV v2 permissions with an empty path_prefix: alice gets users/alice/* and bob gets users/bob/*. The policy is assigned to external Identity group all-ad-users, aliased to **an existing AD group vault-users containing all intended users**. The group must be discoverable through groupdn/groupfilter. The role does not modify AD memberships; use a suitable explicit/nested-membership group. Do not assume Domain Users works with the example member filter: AD primary-group membership is not represented by member ([Microsoft documentation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/e12954a4-6865-4432-94e6-00c310ca87c0)). No inventory users or prior Vault logins are needed.

Use short sAMAccountName logins (alice), not DOMAIN\alice or UPN: username_as_alias:true uses the login as the personal path component; use lowercase short logins consistently with the personal directory names. Full permissions cover secrets under users/alice/, including irreversible version/metadata deletion. They do not grant other users' paths, parent LIST or a separate secret at users/alice. KV directories are virtual; the first secret can be users/alice/mail. Other policies may broaden access.

The role uses external Identity Groups and aliases, shown in Access → Groups, not direct auth/ldap/groups mappings. Therefore Authentication methods → ldap → Groups may be empty. Group names need no ldap- prefix. Combine LDAP external subgroups and local users through an internal wrapper group; do not add local users directly to an external group.

LDAP personal_access uses identity_source:ldap_login, auth_mount:ldap, mount:users, path_prefix:dep1, subjects and permissions. Native alias templates grant users/dep1/alice/* and users/dep1/bob/* without enumerating accounts or waiting for first login. username_as_alias:true is required. Accessors are resolved automatically, including newly enabled backends. Default entity_id mode uses identity.entity.id and user subjects. Parent LIST and the personal root key are not granted; other policies can broaden access. Logins must be safe single path segments; login reuse/rename requires managing the secret lifecycle.

## Token, compatibility and migration

Use one existing administrative token for all operations. Store it and password dictionaries in Ansible Vault or CI secrets. The role never logs in, renews or switches tokens. [bootstrap-policy.hcl](files/bootstrap-policy.hcl) is a trusted administrative policy without mount-delete privileges; its holder can expand ACLs.

```bash
export VAULT_ADDR=https://vault01.example.org:8200
vault login
# Enter the root token interactively.
vault policy write vault-configuration-admin roles/vault-configuration/files/bootstrap-policy.hcl
vault token create -policy=vault-configuration-admin -ttl=8h
```

Only Vault 2.x is supported. The 2.0.x series is treated as validated; other 2.x versions continue with informational warnings. Actual tested releases remain recorded separately in [compatibility.json](compatibility.json) and [TEST-REPORT.md](TEST-REPORT.md). Built-in plugin/API/KV checks remain enabled. Transport failures report safe reason/hint, certificate verify_code, CA source and timeout; environment proxies are disabled. Raw exception/HTTP response bodies and credentials are suppressed.

Remove execution_host, config_connection_address, config_connection_allow_insecure_http, management_state_file/prune/prune_identities/deletion_approvals/recovery and safety_max_deletions/allow_empty_desired. Use api_execution/scheme/port/use_loopback and a DNS inventory target. Remove password revisions; use always only for intentional credential writes. config/export dictionaries, compatibility_profile and config_schema_version are also rejected. No existing mount or alias is moved automatically.

Run unit tests with python3 -m unittest discover -s roles/vault-configuration/tests/unit -v. Integration tests use temporary localhost Vault/OpenLDAP; target execution is exercised using a local inventory connection, not a physical remote SSH host.
## KV v2 access matrix (matrix)

Complete offline inventory: [examples/matrix.yml](examples/matrix.yml), [examples/matrix-playbook.yml](examples/matrix-playbook.yml).

`matrix` creates a CSV of assigned user/group KV v2 permissions. It never modifies Vault, reads secret values or enumerates KV keys. Both CSV and notes are always published on the controller. Existing controller/target API execution settings apply to the cluster source; no additional role is needed.

```yaml
vault_configuration_config_mode: matrix
vault_configuration_matrix_source: cluster  # cluster | inventory
vault_configuration_matrix_destination: ./vault-access-matrix.csv
```

```bash
ansible-playbook -i inventory.ini configure.yml -e vault_configuration_config_mode=matrix
ansible-playbook -i inventory.ini configure.yml -e vault_configuration_config_mode=matrix -e vault_configuration_matrix_source=inventory
```

`cluster` reads all discovered KV v2 mounts, Identity objects, ACLs, userpass accounts, LDAP mappings and supported auth roles, including manually configured/foreign objects. Config mounts, owner, policy prefix and export filters do not restrict this report. Supply a token permitted to read these APIs; the role's administrative token works. Read failures stop publication. Desired declarations and password variables are not evaluated.

`inventory` shows declared grants, personal access and group membership, without API, SSH, token/password/bind-password lookups or LDAP configuration. It runs on the controller even with `api_execution: target`. Inline users[].password is removed before templating. Users must be a literal YAML list of mappings or null; a template referencing the entire list is rejected to avoid evaluating nested password expressions. Other user fields support templates. Normal declaration/reference/cycle/safety validation still applies. Existing external policy bodies are unavailable and produce `?`; omitted sections do not predict absence of live permissions.

Relative destinations resolve from playbook_dir. CSV and `<destination>.notes.txt` are UTF-8 without BOM, LF, mode 0600; new directories use 0700. CSV uses semicolons and standard quoting; formula-like fields receive an apostrophe prefix. Notes contain readable JSON: legend, policy provenance, group chains, UTC read interval and unknown rules. Console output contains summary/paths only. Changed reflects file changes; `--check` calculates the report without writing files.

Columns start with `mount;path`, followed by sorted subjects:

| Prefix | Meaning |
|---|---|
| `u:<name>` | Identity entity policies and known group membership |
| `g:<name>` | Identity group policies, including parent groups |
| `a:<auth_mount>/<login>` | Known local/LDAP account: login policies, default unless disabled, LDAP config/mappings, associated Identity policies/groups |
| `ldap-group:<auth_mount>/<name>` | Direct LDAP group mapping plus its external Identity group when linked by alias |
| `r:<auth_mount>/<name>` | Existing AppRole/Kubernetes/JWT/OIDC role assignments |

Offline reports include declared u/g/r and UUID subjects. Provenance is in notes.policy_sources. Every mount has a `*` row; other rows come from ACL paths, not existing secrets. Exact paths and `path/*` are separate rows; an empty path denotes the exact mount API root. Prefix rows show covering rules; narrower exceptions appear separately and must be consulted for a concrete secret.

Each permission cell has **exactly 11 characters, without spaces**, in permanent order `LRWPMUDVNXZ`:

| Position | Symbol | Permission |
|---|---|---|
| 1 | L | list |
| 2 | R | read |
| 3 | W | write |
| 4 | P | patch |
| 5 | M | read_metadata |
| 6 | U | update_metadata |
| 7 | D | delete_latest |
| 8 | V | delete_versions |
| 9 | N | undelete_versions |
| 10 | X | destroy_versions |
| 11 | Z | delete_metadata |

`.` means no permission found within the model; `!` means denied; `?` means unknown/partial capabilities. Disabled entities/logins show `!!!!!!!!!!!` and are listed in notes.disabled_subjects. W requires create+update on data; U requires create+update on metadata. A partial pair produces `?`.

```csv
mount;path;g:developers;u:alice;u:bob
infra;*;LRW........;LRW........;LRW........
users;dep1/alice/*;...........;.RW........;...........
users;dep1/bob/*;...........;...........;.RW........
```

`LRWPMUDVNXZ` represents all operations; `LR.........` list/read; `......D....` delete_latest.

LDAP reports include Identity external groups and auth/ldap/users/groups mappings. Known memberships and nested groups are included; user mappings add explicitly configured LDAP groups. LDAP group rights are visible before users log in, but directory membership is never queried: Vault only retains an observed membership snapshot, and users who never logged in may be absent. u columns show Identity rights; a columns additionally show login-specific assignments. Unknown membership is not invented.

Known entity UUIDs/LDAP aliases resolve personal templates, for example users/dep1/alice/*. Unknown values remain symbolic with `?` and notes. Offline UUIDs are not invented. A group's templated policy does not enumerate all its LDAP users.

Supported ACL syntax: capabilities-only HCL/JSON path blocks, comments, literal paths and trailing *. Vault's most-specific path wins; equal patterns combine capabilities and deny applies within the selected rule. A more specific allow may override a broader deny. Plus wildcards, other templates, parameter constraints and unknown syntax produce `?` in the affected scope; an unavailable policy body can affect every path. Invalid JSON/unbalanced HCL stops publication.

The matrix describes assigned KV v2 ACLs, not every issued token's effective access. CIDR/TTL/use limits, Sentinel, unsupported auth methods and other secret engines are excluded. Reading is not atomic; `.` does not prove absence of access outside this model. References: [Vault policies](https://developer.hashicorp.com/vault/docs/concepts/policies), [LDAP API](https://developer.hashicorp.com/vault/api-docs/auth/ldap).

