# One administrative token for all vault-configuration operations on this cluster.
# Independent of inventory mount names and policy prefixes, including nested mounts.
# ACL/auth administration is privileged: the holder can change its own permissions.
path "sys/health" { capabilities = ["read"] }
path "sys/mounts" { capabilities = ["read"] }
# Create/read only: mount removal is never granted.
path "sys/mounts/*" { capabilities = ["create", "read", "update", "sudo"] }
path "sys/auth" { capabilities = ["read"] }
path "sys/auth/*" { capabilities = ["create", "read", "update", "sudo"] }
path "sys/capabilities-self" { capabilities = ["update"] }
path "sys/policies/acl" { capabilities = ["list"] }
path "sys/policies/acl/*" { capabilities = ["create", "update", "delete", "read"] }
path "identity/entity/id" { capabilities = ["list"] }
path "identity/entity/id/*" { capabilities = ["read", "update", "delete"] }
path "identity/entity/name/*" { capabilities = ["read"] }
path "identity/entity" { capabilities = ["create", "update"] }
path "identity/group/id" { capabilities = ["list"] }
path "identity/group/id/*" { capabilities = ["read", "update", "delete"] }
path "identity/group/name/*" { capabilities = ["read"] }
path "identity/group" { capabilities = ["create", "update"] }
path "identity/entity-alias/id" { capabilities = ["list"] }
path "identity/entity-alias/id/*" { capabilities = ["read", "update", "delete"] }
path "identity/entity-alias" { capabilities = ["create", "update"] }
path "identity/group-alias/id" { capabilities = ["list"] }
path "identity/group-alias/id/*" { capabilities = ["read", "update", "delete"] }
path "identity/group-alias" { capabilities = ["create", "update"] }
# All auth paths cover LDAP/AD config, userpass, existing auth roles and token lookup.
# Also grants other auth API operations (including token management); treat as admin.
path "auth/*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
