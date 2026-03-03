# Changelog

All notable changes to this project will be documented in this file.

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
