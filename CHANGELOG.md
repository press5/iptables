# Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] — 2026-03-23

### Added
- Molecule integration test suite with two scenarios (`default`, `no_ipsets`) covering Debian 12 and Ubuntu 22.04; verifies files written, service state, ipset kernel presence, systemd drop-in lifecycle, idempotency, and that ipset DROP rules precede open-port ACCEPT rules in the live kernel chain
- Molecule scenarios added to GitHub Actions and GitLab CI pipelines (parallel to the existing native-host integration job)
- `molecule-requirements.txt` for installing Molecule and the Docker driver

### Tests
- Added v6 mirrors of all three rule-ordering assertions (`test_open_ports_appear_after_custom_rules`, `test_ipset_match_rules_appear_before_open_ports`, `test_log_rules_appear_after_open_ports_and_ipset`) — previously these only covered the IPv4 template
- Added `TestExplicitRuleOrdering` class: explicit `table.rules` entries are verified to appear before ipset match rules in both IPv4 and IPv6 output

### Meta
- Added `namespace: jkl` to `meta/main.yml` to satisfy Galaxy naming requirements (and suppress Molecule prerun validation errors)

## [1.1.0] — 2026-03-23

### Fixed
- ipset `match:` rules are now injected **before** convenience port rules (`iptables_open_ports`, `iptables_v4_open_ports`, `iptables_v6_open_ports`) in the filter table. Previously the order was reversed, meaning a blocklist `DROP` rule would never fire for ports opened via the convenience variables.
- The systemd drop-in (`netfilter-persistent.service.d/ipset-first.conf`) is now removed when `iptables_ipsets` is set to an empty list. Previously it persisted as a stale artifact after all ipset definitions were removed.

## [1.0.0] — 2026-03-02

### Added
- IPv4 and IPv6 iptables rule management via `iptables-restore` format
- ipset set management with atomic create→populate→swap→destroy cycle (live set is never empty during an update)
- Auto-generated `-m set --match-set` iptables rules from ipset `match:` blocks, with support for single port, multiport, `proto: both`, and configurable chain/direction/target
- Debian/Ubuntu support (`netfilter-persistent`, `/etc/iptables/`)
- RedHat/EL support (`iptables-services`, `/etc/sysconfig/`)
- Systemd drop-in on Debian to restore ipsets before iptables at boot, fixing the `netfilter-persistent` plugin ordering issue
- Backup of existing rules files before overwrite (`iptables_backup_rules`)
- Check mode support
- Pytest template unit test suite (38 tests, no target host required)
- GitHub Actions and GitLab CI pipelines
