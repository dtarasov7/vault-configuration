# Changelog

## Fixes — 2026-10-25

- The role creates a missing initialization-output directory on the controller before init, with mode 0700 for a new directory.

## 1.2.0 — 2026-09-25

- Switched API requests, `api_addr`, `cluster_addr`, and `retry_join` from IP addresses to node DNS names for correct TLS SAN validation.
- Updated Molecule scenarios to access Vault through inventory hostnames.

## 1.1.0 — 2026-09-14

- Added Vault metrics output in Prometheus format.
- Added Molecule coverage for the metrics endpoint.
- Updated the Vault dashboard for Grafana 12 and hierarchical Prometheus filters.

## 1.0.0 — 2026-08-07

- Added installation from a RedOS repository or a local executable.
- Added one-node and three-node integrated Raft storage configurations.
- Added protected initialization with five shares and a threshold of two.
- Added systemd, optional TLS, cleanup, and Molecule scenarios.
- Switched Molecule to RedOS 7.3.6 and `vault-2.0.1-1.el7` from `updates`.
