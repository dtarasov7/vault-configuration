# vault-configuration

Version: [1.1.0](VERSION).

Declarative Vault Community access management over HTTPS: Identity entities and aliases, internal/nested and external groups, local userpass accounts, KV v2 ACL compilation, and policy assignments to existing AppRole/Kubernetes/JWT/OIDC roles. Run on a single Ansible execution host per Vault/owner. The role creates missing KV v2 and userpass/LDAP auth mounts but never deletes mounts. It does not install Vault or configure directory servers, read or write application KV data, log in, renew credentials, issue tokens or create SecretIDs.

See [TEST-REPORT.md](TEST-REPORT.md) and [compatibility.json](compatibility.json) for exact tested versions. Unknown servers and external auth plugin versions fail before writes. KV v2 and the Vault server version are separate concepts.

## Running

Tested runtime: Python 3.8.20 and ansible-core 2.13.13. The API client uses Python's standard library; YAML reports and exports require PyYAML 6.0.2 from `requirements.txt`. Additional testing dependencies are pinned in `requirements-test.txt` and `molecule/requirements.yml`. Other runtime combinations are not claimed as tested. Vault CLI and community.hashi_vault are not role dependencies.

For a complete single-server RED OS 8 lab without TLS, with local users and TCP LDAP, see [examples/redos8-lab](../../examples/redos8-lab/README.md). It includes `hosts.ini`, `group_vars` and separate installation/configuration playbooks using both roles.

```sh
ansible-playbook -i localhost, roles/vault-configuration/examples/playbook.yml
ansible-playbook -i localhost, roles/vault-configuration/examples/playbook.yml --check --diff
```

[examples/inventory.yml](examples/inventory.yml) covers all five mounts, both project/environment orders, personal areas, userpass, external groups, SSI Kubernetes auth, CI JWT, and Ansible AppRole. Supply your actual connection, existing auth roles/mounts, alias claims and protected variables separately. Create the referenced `company-self-service` policy or remove that grant.

```ini
[vault_access_execution]
localhost ansible_connection=local
```

Use one play host. `vault_configuration_execution_host` defaults to `localhost`; it needs API connectivity and existing CA/client certificate files. No systemd, OS accounts or log rotation are installed.

## Public variables

| Variable | Contract |
| --- | --- |
| `vault_configuration_config_*` | Individual settings detailed below |
| `vault_configuration_token` | One existing administrative token for all API operations; default empty; provisioning described below |
| `vault_configuration_passwords` | External secret dictionary indexed by user inventory ID; default `{}` |
| `vault_configuration_users` | Optional user declarations; omission leaves this scope unmanaged |
| `vault_configuration_groups` | Optional group declarations |
| `vault_configuration_grants` | Optional KV/existing-policy assignments |
| `vault_configuration_auth_roles` | Optional references to existing auth roles |
| `vault_configuration_personal_access` | Optional personal policy declaration |
| `vault_configuration_export` | Default scope `managed`, destination `./vault-access-manager-export.yml`, allow_partial false |
| `vault_configuration_execution_host` | Module execution host, default localhost |
| `vault_configuration_result` | Registered module result; `.report` is safe to publish |

Configuration fields:

| Field | Default / meaning |
| --- | --- |
| `vault_configuration_config_schema_version` | `1` |
| `vault_configuration_config_mode` | `dry`; also `apply`, `export` |
| `vault_configuration_config_compatibility_profile` | `community-validated`; `community-candidate` is for profile development |
| `vault_configuration_config_connection_address` | HTTPS origin without credentials, query or `/v1`; override the default example address |
| `vault_configuration_config_connection_validate_tls`, `vault_configuration_config_connection_ca_file` | true; optional existing execution-host PEM CA file |
| `vault_configuration_config_connection_client_cert`, `vault_configuration_config_connection_client_key` | Optional existing PEM file pair for mTLS |
| `vault_configuration_config_connection_timeout_seconds` | 30; integer 1–600 |
| `vault_configuration_config_connection_allow_insecure_http` | false; explicit test-only HTTP opt-in |
| `vault_configuration_config_mounts` | `[certs, infra, apps, cicd, users]`; missing mounts are created as KV v2; incompatible existing mounts fail; mounts are never deleted |
| `vault_configuration_config_management_owner` | Required ownership domain; default platform-team |
| `vault_configuration_config_management_policy_prefix` | Required generated ACL prefix; default vam-platform- |
| `vault_configuration_config_management_state_file` | Required absolute `.json` path; default `/var/lib/ansible/vault-access/platform-state.json` |
| `vault_configuration_config_management_prune`, `vault_configuration_config_management_prune_identities` | false; identities/accounts/aliases additionally need prune_identities |
| `vault_configuration_config_management_adoption` | `[]`; `{kind, id, uuid}` or `{kind, id, hash}` with the expected current fingerprint |
| `vault_configuration_config_management_deletion_approvals` | `[]`; `{kind, id, hash, dependencies_cleared: true}` for policy/entity/group deletion |
| `vault_configuration_config_management_recovery_digest` / `vault_configuration_config_management_recovery_outcome` | Omitted; operation digest and outcome `applied|not_applied` for a pending write |
| `vault_configuration_config_safety_max_deletions` | 5; includes account/alias deletes |
| `vault_configuration_config_safety_allow_empty_desired` | false; required for empty managed sections with prune enabled |
| `vault_configuration_config_safety_allow_mount_root` | false; separate approval for root subtree/discovery grants |
| `vault_configuration_config_safety_allow_destructive_grants` | false; required for destroy_versions/delete_metadata |
| `vault_configuration_config_safety_protected_policies` | `[root, default]`; these two always remain nonassignable |
| `vault_configuration_config_safety_protected_entities`, `vault_configuration_config_safety_protected_groups` | `[]`; inventory IDs, names or Vault UUIDs; automation entity is automatically protected |
| `vault_configuration_config_report_destination` | In dry: 0600 YAML report, default `{{ playbook_dir }}/vault-configuration-{{ inventory_hostname }}-dry.yml`; override its full path/name in inventory. Omitted in other modes; explicit apply reports retain JSON format |
| `vault_configuration_config_expected_plan_digest` | Omitted; require the freshly rebuilt plan to match this reviewed digest |

Override each setting independently; defaults for other variables remain in effect. The `vault_configuration_config` dictionary is no longer used. Unknown fields/types fail validation. See [schemas/inventory.schema.json](schemas/inventory.schema.json); Python additionally validates references, cycles, paths and safety constraints.

### Declarations

* Users require `id`, `name`, `source: userpass|external`. Optional `disabled` defaults false; aliases are `{auth_mount, name}`. Userpass additionally requires auth_mount, lowercase login and password_revision. password_policy is on_create (default) or on_revision; password is optional when supplied through `vault_configuration_passwords[id]`.
* Userpass `token_parameters`: nonnegative integer token_ttl/token_max_ttl/token_explicit_max_ttl/token_period/token_num_uses, boolean token_no_default_policy, token_type service/batch/default, and token_bound_cidrs string list. Bcrypt passwords are limited to 72 UTF-8 bytes and checked before writing. Direct account token policies are not assigned; access comes from entities/groups.
* Groups require id/name/type internal or external. Internal groups accept members/member_groups, default empty lists. Members reference inventory IDs or `{uuid: ...}` existing identities. External groups cannot declare membership; they may declare one alias `{auth_mount, name}`. Cycles include preserved foreign memberships.
* Auth roles require id/type/auth_mount/name; type is approle, kubernetes, jwt or oidc. Only existing roles are updated. Separate adapters preserve bindings, claims, audiences, TTLs and other validated fields. Unknown fields/plugin versions fail. AppRole local_secret_ids is never re-sent on update.
* Grants require id and nonempty subjects `{kind: user|group|auth_role, id}`. User/group subjects may use uuid instead of id to manage only new links on an existing identity. Exactly one of paths or existing_policies is required. System/protected policies are not assignable.
* Paths require mount/path/scope exact or subtree/permissions. Paths are arbitrary-depth relative ASCII segments matching `[A-Za-z0-9_-][A-Za-z0-9_.-]*`; no wildcards, percent encoding, Unicode, absolute paths or empty segments. An internal segment named data is preserved.
* Optional discovery_paths contains `{mount, path}` directory LIST entries. Empty path is mount root and requires allow_mount_root. Each discovery permission warns about disclosure of all immediate child names.
* Personal access is `{enabled: true, mount: users, subjects: [...], permissions: [...]}`. identity_source is entity_id by default (users only) or ldap_login (users/groups, required auth_mount, optional path_prefix). `{enabled: false}` detaches only owned personal links. Grant ID personal is reserved while enabled.

Omitted sections preserve their scope. Explicit `[]` detaches previously owned relationships; deleting objects also requires prune and its safeguards. Existing foreign links remain foreign and are preserved. An auth role itself is shared, never adopted/deleted: only newly added policy links are owned.

Stable inventory IDs map to Vault UUIDs. Entity rename preserves personal paths. Login/mount/UUID/accessor changes require an explicit migration. Aliases are never moved, and entities are never merged.

### Connection diagnostics

Failures with `status=transport` include a safe `reason` and a troubleshooting `hint`. For example, `reason=tls_certificate_verification_failed; verify_code=20` means Python could not build a trusted certificate chain. Check the execution host CA trust and the intermediate certificates served by Vault.

| Reason | Check on the execution host |
| --- | --- |
| `dns_resolution_failed` | Vault address and DNS. |
| `connection_refused` | Address, port, listener and Vault service status. |
| `network_unreachable`, `host_unreachable` | Routing and firewall. |
| `timeout` | Vault availability, firewall and connection_timeout_seconds. |
| `connection_reset`, `connection_closed` | Vault, load balancer and TLS listener logs. |
| `tls_certificate_verification_failed` | Trust chain, certificate validity and hostname/IP SAN; `verify_code` narrows the cause. |
| `tls_error` | HTTP/HTTPS, TLS versions, mTLS and PEM files; known failures include `tls_reason`. |
| `file_not_found`, `permission_denied` | CA/client certificate/key files, execution user permissions and local network restrictions. |
| `os_error`, `transport_error` | Other local failures; follow the hint and inspect execution host logs. |

Messages also include `timeout_seconds`, `tls_validation`, `ca_source` and `proxy=disabled`. The CA source is `explicit_ca_file` when `vault_configuration_config_connection_ca_file` is supplied, otherwise `python_default_trust_store`. A successful curl without `-k` does not prove Python uses the same trust store. When running Ansible in a container, check connectivity and certificate availability inside it. The role ignores HTTP(S)_PROXY environment variables.

CA/client certificate loading failures identify `stage=load_ca` or `stage=load_client_certificate`. Tokens, request/response bodies and raw exception text are never published. HTTP errors retain their numeric status, such as `403`. Uncertain writes still require recovery before retrying.

## KV permissions

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

See [examples/ldap-ad.yml](examples/ldap-ad.yml) for a complete AD example: the external Vault group `infra-admins-ad` maps to an existing AD group with `cn=infra-admins` and receives every permission above on `infra`. Keep `infra` in `vault_configuration_config_mounts` when loading the example; it also uses `apps`.

An empty `path: ""` with `scope: subtree` covers the entire mount, including root LIST. This requires `vault_configuration_config_safety_allow_mount_root: true`. The `destroy_versions` and `delete_metadata` permissions additionally require `vault_configuration_config_safety_allow_destructive_grants: true`; both flags are enabled in the example. These settings permit the corresponding grants; permissions are assigned only to the subjects of each grant. They provide full access to KV v2 secrets without mount configuration, mount deletion or Vault administration rights.

Subtree emits a base rule and a separate `/*` rule: prod cannot match production. Exact+list is rejected. Ancestor LIST is never implicit. Read can access historical versions; write cannot destroy versions. Destroy is irreversible and metadata deletion removes all versions. The role grants capabilities without executing those operations on application data. Vault UI navigation may require separate rights; known-path API access is the supported interface.

By default (`identity_source: entity_id`), personal policies contain literal `{{identity.entity.id}}/*` below the selected data/metadata mount. Secrets live below the entity ID; its root key is unused. `identity_source: ldap_login` uses the LDAP alias name and an optional path_prefix, as described below. Root LIST is not granted. This isolates ordinary identities through ACL, not cryptographically from administrators.

### Named LDAP personal paths: users/dep1/alice and users/dep1/bob

Individual grants already support these paths. Set mount `users` and relative paths `dep1/alice` and `dep1/bob`; use `/` separators. Include `users` in `vault_configuration_config_mounts` and configure the LDAP auth mount with `username_as_alias: true`.

The following example assumes that these LDAP users have no existing Vault entities/aliases. Merge it with your other user and grant declarations:

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

Alice can access, for example, `users/dep1/alice/mail`; Bob can access `users/dep1/bob/mail`. These grants do not grant access to each other's area. Isolation also requires that other policies do not grant broader access to `users`. Add `delete_latest` explicitly if deleting the latest version is required.

Users who previously logged in through LDAP may already have entities and aliases. The role does not automatically choose an existing entity by LDAP login or move aliases between entities. For individual assignments, reference the actual existing entity UUID with `subjects: [{kind: user, uuid: "<Alice entity UUID>"}]` without redeclaring that user; alternatively, explicitly adopt the existing entity according to the role's ownership rules. This requires knowing existing identities and is cumbersome at scale.

KV has no empty directory creation step. The role grants access; a path becomes visible after the first secret write. Parent LIST permissions for UI navigation are separate discovery_paths and expose sibling key names. UUID-based `personal_access` does not generate the named `dep1/alice` paths.

### At scale: one templated policy for an LDAP group

The role generates policies interpolating LDAP login names with `identity_source: ldap_login`. One policy assigned to a department's Identity Group grants Alice `users/dep1/alice/*`, Bob `users/dep1/bob/*`, and future members their own prefixes. There is no need to list users, track first logins or collect entity UUIDs. Vault uses existing entities/aliases; the role does not move or merge them.

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

Here `ldap-dep1` is an inventory ID of a declared group, typically external with the department's LDAP group alias. Internal groups and existing groups referenced by UUID are also supported. A member must have an LDAP alias at the selected mount; without it this policy grants no access. Other policies may grant additional permissions.

| personal_access field | Contract |
| --- | --- |
| `identity_source` | `entity_id` (default, existing UUID behavior) or `ldap_login` |
| `auth_mount` | Required LDAP auth mount path for ldap_login; the role resolves its accessor |
| `path_prefix` | Relative prefix such as `dep1` or `department/team`; default `""` gives `users/<login>/*`. Safe path segments only, no templates or wildcards; LDAP mode only |
| `subjects` | Users or groups with id/uuid in LDAP mode; users only in entity_id mode |
| `mount`, `permissions` | Selected KV v2 mount and ordinary role permissions |

LDAP must use `username_as_alias: true`. The role checks the auth method type and configuration before writing. If LDAP is enabled in the same apply, it is created/configured first and its real accessor is then inserted into the policy. For a new mount, dry shows a deferred `$ldap_personal_policy`/`$ref` describing the not-yet-allocated accessor; this representation is not sent to Vault. Existing LDAP mounts produce the final HCL during planning.

For an illustrative accessor `auth_ldap_a1b2c3d4`:

```hcl
path "users/data/dep1/{{identity.entity.aliases.auth_ldap_a1b2c3d4.name}}/*" {
  capabilities = ["create", "read", "update"]
}

path "users/metadata/dep1/{{identity.entity.aliases.auth_ldap_a1b2c3d4.name}}/*" {
  capabilities = ["list"]
}
```

No accessor is supplied in inventory. This permits secrets under the prefix, such as `users/dep1/alice/mail`, not a secret directly at `users/dep1/alice`. It grants no parent/root LIST. Add `delete_latest` to permit deleting the latest version.

One personal_access object generates one policy for a single mount/auth_mount/path_prefix combination; all subjects receive that policy. New directory group members receive access on login without another apply. `enabled: false` detaches the managed assignment. A changed recorded accessor requires explicit migration; the role never deletes auth mounts.

Export reconstructs identity_source, auth_mount, path_prefix, permissions and subjects. The source accessor is not embedded in exported inventory: import resolves the target mount's accessor. Unsupported template edits or mixed prefixes/accessors in one policy fail strict export.

Login names must be suitable as one key segment, without `/`, `\`, ACL wildcards or `.`/`..` values. The role does not enumerate all LDAP users to validate logins; enforce the naming rules in the directory. Renames and login reuse require consideration because named paths follow logins rather than immutable UUIDs. Existing entity_id behavior remains available for UUID-based paths.

See [ldap-personal-access.yml](examples/ldap-personal-access.yml), a fragment for the [LDAP example](examples/ldap-openldap.yml). Ordinary grant paths still reject arbitrary `{{identity...}}` templates. existing_policies remains available for pre-existing external policies; the personal_access mode above needs no separately created HCL. See [Vault templated policies](https://developer.hashicorp.com/vault/docs/concepts/policies) for interpolation syntax.

## Modes, check/diff and tags

Dry reads actual API state and saves a YAML report on the execution host (the controller by default). The report contains mode, plan operations/warnings/digest and three summaries: «Планируем добавить», «Планируем изменить», «Планируем удалить». Reported operations include only create/update/detach/delete/forget; noop objects are omitted from both YAML and console dry reports. Without changes, operations is `[]`. The complete internal plan is retained for digest calculation and application. The file is written atomically with mode 0600, without tokens or passwords. It creates no registry and does not mutate Vault; changed reflects only report creation/update. An identical repeated dry leaves the file unchanged. No CLI flags are needed.

Select the full path/name in inventory:

```yaml
vault_configuration_config_mode: dry
vault_configuration_config_report_destination: "{{ inventory_dir }}/vault-dry-result.yml"
```

Without an override, the role uses `{{ playbook_dir }}/vault-configuration-{{ inventory_hostname }}-dry.yml`. The redos8 inventory overrides it with `.state/dry-result.yml` for dry only. Parent directories are created as needed; reports must not overlap registry/backup/lock or other output paths.

Apply re-reads the snapshot and affected objects, verifies mutation capabilities and executes the plan. Check mode forecasts changes without writing Vault, registry or local outputs, including dry YAML reports. Diff contains ordinary nonsensitive before/after fields. A separate action plugin publishes the safe report and native Ansible diff after the no_log API task. Dry diff is also included in the YAML report.

`Publish the sanitized result` displays mode, plan, summary and the apply result with the default callback at normal verbosity, without `-v`. `changed=0` means no changes were performed; summary lists planned operations and noop entries match current state. A skipped `Report failure…` task means no failure was reported. Define each credential variable only once in YAML; Ansible uses the last value when duplicate keys occur.

The digest includes nonsensitive desired state, UUIDs/accessors, snapshot and registry. Mode/expected_plan_digest/report path do not influence it. Passwords and password hashes are excluded; rotation is represented by revision.


## Ownership and recovery

The 0600 execution-host registry stores cluster_id, owner, stable IDs, UUIDs/accessors, managed relationships, nonsensitive hashes, password revisions and a recovery journal. Writes use fsync/atomic replace with a `.bak`. Keep all owner registries for one scope together in a dedicated directory. A shared local directory lock serializes apply and peer registries prevent ownership overlap. Serialize all Vault/scope jobs across execution hosts in CI; the API has no general transaction/CAS and no atomic rollback is promised.

Identity metadata uses vam_owner/vam_id. A policy prefix is insufficient proof of ownership. Existing objects without a record require explicit adoption after reviewing the current UUID or canonical API-field hash reported by dry. Protected objects cannot be adopted; foreign metadata/registries block takeover. See [schemas/state.schema.json](schemas/state.schema.json).

Prune detaches owned links before removing aliases/accounts/objects. Known foreign memberships, aliases or policy assignments block deletion. Because API discovery cannot prove absence of every old token/external consumer, policy/entity/group deletion additionally requires an up-to-date hash and explicit dependencies_cleared attestation. Clear those dependencies first. User KV data is never deleted.

Before each mutation, pending intent is persisted with nonsensitive before/desired/record/digest. A successful readback records a confirmed operation. Failure reports contain confirmed and uncertain operations; writes are not blindly retried after timeout.

1. Stop concurrent apply jobs and preserve the registry/backup securely.
2. Verify cluster_id and actual objects. For corrupt JSON restore a verified `.bak` at the same path with mode 0600; there is no silent backup fallback.
3. Reconcile pending API state and set vault_configuration_config_management_recovery_digest and vault_configuration_config_management_recovery_outcome: applied. not_applied requires an exact pre-write API state. Password outcomes cannot be verified by reading the API: confirm/correct credentials separately, then resolve as applied.
4. Remove recovery after success. A completely lost registry requires explicit adoption with current UUIDs/hashes, never automatic prefix-based takeover.

Matching password_revision cannot detect an external password change. on_create only sets a creation password; on_revision rotates explicitly. Passwords and their hashes are never stored in the registry.

## Export

Set vault_configuration_config_mode to export and configure `vault_configuration_export`. Scope managed selects owned objects, including independent identities; scoped selects existing objects explicitly. Fields: destination, audit_destination (default destination + `.audit.json`), allow_partial false, and optional mounts/auth_mounts/entities/groups/policies/auth_roles/users filters. Scoped entities/groups accept UUIDs or names; roles and standalone userpass accounts use auth_mount/name; policies use names. Dependencies and actual subjects of selected policies are included.

Export reads actual ACL rather than cached grants and reverses the supported KV v2 subset. The 0600 output is ordinary YAML mappings/lists containing direct `vault_configuration_*` variables, usable as vars_files without conversion. Source UUIDs/accessors/ownership/audit and external dependencies are separate. The separate `.audit.json` audit stays JSON. Connection and credentials are not exported. Check mode predicts local file changes without creating them; Vault remains read-only and KV data is not read.

Unsupported HCL, unbound policies, missing dependencies, multiple local logins per entity and other lossy mappings fail before file writes. Explicit allow_partial true permits an incomplete audit export, which is not a complete access backup. Direct userpass token policies are not converted to entity grants, because that changes semantics. Existing policies and existing auth roles must be provided separately on the destination. System objects are excluded.

Userpass passwords cannot be read. Export emits expressions such as `{{ vault_configuration_passwords.get('alice', '') }}`. Supply that dictionary separately through Ansible Vault/inventory or an optional variable-level lookup. Missing passwords for new accounts fail before mutation. Existing on_create accounts may omit passwords. Destination Vault allocates new entity UUIDs; migration of personal KV content is a separate operation. Re-import into existing foreign source objects needs adoption; export does not change ownership.

## Credentials, bootstrap and offboarding

The role uses **one `vault_configuration_token` for every API request**: discovery, mount creation, LDAP/AD, userpass, Identity, ACLs and assignments to existing auth roles. One `apply` run performs all necessary changes. There is no separate bootstrap stage or second token inside the role. Vault must already be installed, initialized and unsealed.

[files/bootstrap-policy.hcl](files/bootstrap-policy.hcl) is the administrative policy for this token. It works independently of mount names, nested auth paths and `vault_configuration_config_management_policy_prefix`; inventory changes need no policy regeneration. It permits ACL, Identity and auth API administration and secret/auth mount creation/configuration, without granting `delete` on `sys/mounts/*` or `sys/auth/*`. It grants no direct application KV data permissions. This is a trusted cluster administrator: `auth/*` includes token and credential management, and ACL updates allow the holder to expand its own permissions. Inventory safeguards are not a security boundary against this token holder.

### Create the token using a root token

Run this once on the Ansible controller or an administrative machine with Vault CLI, from the repository root. Root is used only to install the policy and issue the administrative token. The Bash prompt reads root without echoing it or including it in shell command history.

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

The token has only the `vault-configuration-admin` policy and a maximum lifetime of eight hours. `-orphan` makes its lifecycle independent of the root token. See [Vault token create](https://developer.hashicorp.com/vault/docs/commands/token/create) for the options. Store it in your protected credential source for runs outside this session. Issue a new token with the same policy when it expires; the role does not log in or renew tokens.

Configure the cluster variables to use that token, for example from the controller environment:

```yaml
vault_configuration_token: "{{ lookup('ansible.builtin.env', 'VAULT_CONFIGURATION_TOKEN') }}"
vault_configuration_config_mode: apply
vault_configuration_config_connection_address: https://vault.example.org:8200
vault_configuration_config_connection_ca_file: /path/to/vault-ca.pem
```

Define the remaining cluster settings and desired LDAP/groups/grants in inventory, then run your playbook with the role. You may use `apply` directly; a preliminary `dry` run is optional. An encrypted Ansible Vault vars file can supply the token instead of the environment lookup. The role run requires neither CLI nor root. Revoke the initial root token according to your procedure after verifying the issued access; the orphan token remains valid until its own expiry or revocation.

Secret source selection belongs in variables. defaults/main.yml demonstrates an optional community.hashi_vault lookup; that plugin is required only if you choose it. Bootstrap credentials must not depend on a still-inaccessible target Vault. TLS verification defaults true. Use certificate hostnames and an active-node load balancer. Redirects are never followed, including HA redirects, so credentials cannot be forwarded to arbitrary hosts. CA/client files already exist on the execution host.

Offboarding disables the entity, removes managed grants/membership and optionally deletes the local login. Deleting userpass does not revoke old tokens. Token policies and identity policies update differently; external membership may refresh on login/renewal. Follow a separate session-revocation procedure. The role neither discovers nor mass-revokes tokens. Entity removal leaves personal data in place and does not transfer it to a new UUID.

## Verification

```sh
python3 -m unittest discover -s roles/vault-configuration/tests/unit -v
python3 -m unittest discover -s roles/vault-configuration/tests/integration -v
cd roles/vault-configuration
molecule test -s default
molecule test -s ha
```

Integration tests start temporary localhost Vault servers and TokenReview API, and use openssl for JWT/TLS fixtures. They do not consume VAULT_ADDR/VAULT_TOKEN. HA checks three Raft voters and continued operation after losing the active node. Molecule uses pinned Docker image digests, dev mode only in default tests, and initialized/unsealed Raft in HA tests. Coverage results and limits are documented in TEST-REPORT.md; production Vault is not contacted.

## Create-only mounts and LDAP / Active Directory

For users with `source: userpass`, the role creates a missing `auth_mount` before accounts and aliases. Users sharing a mount produce a single creation. Incompatible types, overlapping paths and changed recorded accessors fail before writes. Creation uses the same dry/apply plan and recovery journal; prune never removes auth mounts.

`vault_configuration_config_mounts` now ensures missing KV v2 mounts. Apply creates them before ACL/identity writes; dry/check only plan them. Existing KV v1 or incompatible engines and overlapping mount paths fail before mutation. An empty list supports LDAP-only configurations. Mount deletion is forbidden in the planner, executor and REST client, including prune and inventory removal. Role tags are pre-req (always) and config; local deletion tasks have been removed.

`vault_configuration_ldap` is an optional list of integrations; omission preserves them. `vault_configuration_ldap_passwords` defaults to `{}` and supplies external bind passwords by stable integration ID. Each entry requires id, auth_mount and config. Missing auth mounts are enabled as ldap; incompatible mounts fail. Existing foreign configuration requires explicit `{kind: ldap_config, id, hash}` adoption. Accessor changes require migration. Empty lists/prune never delete LDAP configuration or auth mounts.

Config fields: url, binddn, userdn, userattr, userfilter, groupdn, groupattr, groupfilter, upndomain, certificate (PEM CA), starttls, insecure_tls, tls_min_version, tls_max_version, discoverdn, deny_null_bind, anonymous_group_search, case_sensitive_names, username_as_alias, use_token_groups, enable_samaccountname_login, dereference_aliases, max_page_size, connection_timeout and request_timeout. URL/userdn/groupdn are required. TLS versions are tls12/tls13; new integrations enable verification, username_as_alias true and case_sensitive_names false. Plain LDAP is allowed with explicit `allow_insecure_ldap: true` at the integration level in any environment, including production. LDAPS is not mandatory. Plain LDAP does not encrypt traffic; `insecure_tls: false` alone does not enable TLS.

Nonempty binddn requires bind_password_revision. The external password is needed for initial configuration, changed binddn or changed revision; unchanged revisions do not require it again. Passwords and their hashes never enter plans/diffs/state/exports. Uncertain password writes use the existing recovery journal. Client private TLS keys and server-side rotate-root are outside the supported configuration.

See [LDAP](examples/ldap-openldap.yml) and [AD](examples/ldap-ad.yml). AD uses samaccountname, cn and the nested-membership matching-rule OID 1.2.840.113556.1.4.1941. Directory users/groups already exist; the role does not create them or change membership. Assign grants to external Identity groups with LDAP group aliases. Match the returned groupattr and use lowercase aliases when case_sensitive_names is false. A normal external user alias can prebind a directory user to a stable entity. Group membership refreshes through authentication.

The AD example uses auth path `ldap` and plain LDAP on Global Catalog port `3268`, with `starttls: false` and `allow_insecure_ldap: true`. Use LDAP method path `ldap` in the login UI; the integration ID `corporate-ad` is not a login path. For LDAPS, select `ldaps://...:636` (Global Catalog: `3269`); for StartTLS, select `ldap://...` and `starttls: true`. A CA can be supplied through `certificate` using a variable lookup.

An existing `auth/ad` is not renamed or deleted. Changing a previously recorded integration path or alias accessor requires an explicit migration; simply replacing the path in inventory is rejected by the role's migration guards.

### Two LDAP authorization mechanisms and their UI locations

Vault supports two ways to grant policies to LDAP users. Configuring both for the same purpose is not required:

| Mechanism | Policy assignment | UI location | Typical use |
| --- | --- | --- | --- |
| Direct LDAP group-to-policy mapping | `auth/ldap/groups/<LDAP group name>` | Authentication methods → ldap → Groups | Simple assignments scoped to one LDAP auth method |
| Identity Groups and group aliases | `identity/group` and `identity/group-alias` | Access → Groups | Shared access across local users and auth methods, nested groups |

**This role uses Identity Groups.** It creates external groups, associates their aliases with LDAP groups and assigns policies through `vault_configuration_grants`. It does not create `auth/ldap/groups/*` entries for those assignments. Consequently, the Groups list inside the LDAP auth method may be empty while authorization works. That list is not an enumeration of all groups in the LDAP directory.

For the redos8 example, look in **Access → Groups** for external groups `ldap-developers` and `ldap-operators`. Their aliases are `developers` and `operators`, respectively, associated with the `ldap` auth mount. Policies are attached to these Identity Groups. During login Vault resolves directory membership and matches group aliases; membership refreshes on subsequent login/renewal. See [LDAP group-to-policy mapping](https://developer.hashicorp.com/vault/docs/auth/ldap) and [Identity external/internal groups](https://developer.hashicorp.com/vault/docs/concepts/identity).

### Full DNs, group names and partial-name searches

With `groupattr: cn` as used in the examples, `alias.name` must be the exact CN value returned by the LDAP auth method. For `cn=developers,ou=groups,dc=example,dc=org`, the alias is `developers`. A full DN, `cn=developers`, and the pattern `dev*` are not equivalent aliases.

| Field | Purpose | Example |
| --- | --- | --- |
| `config.groupdn` | Full DN of the group search base | `ou=groups,dc=example,dc=org` |
| `config.groupfilter` | LDAP group search filter that accounts for user membership | `(&(objectClass=groupOfNames)(member={{.UserDN}}))` |
| `config.groupattr` | Attribute used to obtain group names | `cn` |
| `vault_configuration_groups[].alias.name` | Exact group name mapped to an Identity Group | `developers` |

Partial-name searches belong in `groupfilter`, for example `(cn=dev*)`. The following is a `config` fragment for OpenLDAP `groupOfNames`:

```yaml
groupdn: ou=groups,dc=example,dc=org
groupattr: cn
groupfilter: "{{ '(&(objectClass=groupOfNames)(cn=dev*)(member={{.UserDN}}))' }}"
```

This filter returns groups whose CN starts with `dev` and which contain the authenticating user. Keep the membership condition `member={{.UserDN}}`; `(cn=dev*)` alone does not identify the user's memberships. For Active Directory, use its objectClass and membership filter as shown in the [AD example](examples/ldap-ad.yml).

**Search filtering does not create wildcard aliases.** If the search finds `developers` and `devops`, declare separate external Identity Groups with exact aliases `developers` and `devops`. They can be included in one internal group to share a policy assignment. The role does not enumerate LDAP groups by pattern to automatically generate aliases.

If different OUs contain identical CNs, restrict `groupdn` and/or `groupfilter` to select the intended groups. Supplying a full DN as `alias.name` with `groupattr: cn` does not disambiguate them. See the search parameters in [LDAP auth method](https://developer.hashicorp.com/vault/docs/auth/ldap).

### Sharing a group between local and LDAP users

The `ldap-` prefix is only a naming convention in the example. Vault external group names may differ from LDAP group names: `alias.name` provides the directory mapping. The inventory `id` is a stable reference used by the role.

You cannot manually add local users to a `type: external` group through `members`; its membership is determined by LDAP. Create a `type: internal` group, add local users through `members` and include the external group through `member_groups`. Assign policies to that shared internal group.

The following fragment assumes that `local-alice` and the LDAP integration at auth mount `ldap` are already declared. Preserve other group and grant declarations when merging it into inventory. `member_groups` refers to **inventory IDs**, not LDAP DNs or aliases:

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

Both `local-alice` and members of the LDAP `developers` group receive the same access through the internal Vault group `developers`. The grant need not be duplicated on the external group or at `auth/ldap/groups/developers`.

Keep Vault Go templates literal using the Jinja string-expression form in the examples. Export escapes them for direct vars_files reuse. Managed export includes owned LDAP configs; scoped selection uses `vault_configuration_export.ldap: [ad]`. Bind passwords remain external inputs on the destination.

Pre-req checks variable names/execution scope; the module validates complete types/references before any write. Optional users/groups/grants keep default(omit), because omission differs from an empty desired list. Redundant default filters on settings with role defaults were removed. Export and reconcile use separate task includes: export never receives or evaluates desired sections or password lookups.

The separate [RED OS lab installer](../../scripts/README.md) deploys persistent TLS Vault 2.0.4 from the exact signed RPM on a dedicated RED OS 7.3 host. It is not executed by the API role.

LDAP config also accepts token_ttl, token_max_ttl, token_explicit_max_ttl, token_period, token_num_uses, token_no_default_policy, token_type and token_bound_cidrs. Direct LDAP token_policies are not assigned; use Identity group grants. Export detects unrepresentable direct LDAP token policies. Directory aliases allow Unicode without control characters. LDAP group aliases are normalized to lowercase when case_sensitive_names is false; logical KV paths and stable inventory IDs remain ASCII.
