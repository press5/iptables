# iptables role

Manages iptables/ip6tables firewall rules and ipset sets on Debian/Ubuntu and RedHat/EL systems. Rules are written in `iptables-restore` format and applied atomically; ipset sets are swapped in without dropping traffic.

## Requirements

- Ansible 2.12+
- Debian Bullseye/Bookworm, Ubuntu Focal/Jammy/Noble, or RHEL/Rocky/AlmaLinux 8–9
- `become: true` (tasks require root)

## Packages installed

| OS family | Packages |
|---|---|
| Debian/Ubuntu | `iptables`, `ipset`, `netfilter-persistent`, `iptables-persistent`, `ipset-persistent` |
| RedHat/EL | `iptables-services`, `ipset`, `ipset-service` |

## Role variables

### Behaviour flags

| Variable | Default | Description |
|---|---|---|
| `iptables_manage_packages` | `true` | Install packages and configure the service |
| `iptables_service_enabled` | `true` | Enable the firewall service(s) at boot |
| `iptables_force_reload` | `false` | Re-apply rules/sets even when unchanged |
| `iptables_backup_rules` | `true` | Back up rules.v4, rules.v6, and ipset.conf before overwriting. Backups are written to the same directory with a timestamp suffix (e.g. `rules.v4.2025-03-02@14:23:01~`) |
| `iptables_log_enable` | `false` | Append a rate-limited `LOG` rule to every filter chain whose default policy is `DROP`, just before the policy fires |
| `iptables_log_prefix` | `"iptables-drop: "` | Kernel log prefix string passed to `--log-prefix` |
| `iptables_log_limit` | `"5/min"` | Rate limit passed to `-m limit --limit` (prevents log flooding) |

### Convenience port-opening

These generate `-A INPUT -p <proto> --dport <port> -j ACCEPT` rules appended to the `filter` table. They are merged into the template after any explicit rules in `iptables_v4_tables` / `iptables_v6_tables`.

| Variable | Applies to |
|---|---|
| `iptables_open_ports` | Both IPv4 and IPv6 |
| `iptables_v4_open_ports` | IPv4 only |
| `iptables_v6_open_ports` | IPv6 only |

Each entry is a dict with `port` and `proto`:

```yaml
iptables_open_ports:
  - { port: 22,  proto: tcp }
  - { port: 53,  proto: udp }
```

### iptables rules (`iptables_v4_tables` / `iptables_v6_tables`)

Rules are expressed as a dict keyed by table name (`raw`, `mangle`, `nat`, `filter`). Tables are rendered in that order.

```yaml
iptables_v4_tables:
  filter:
    policies:           # built-in chain default policies
      INPUT: DROP
      FORWARD: DROP
      OUTPUT: ACCEPT
    chains: []          # user-defined chains (get "- [0:0]" header line)
    rules:              # raw iptables-restore rule strings
      - "-A INPUT -i lo -s 127.0.0.0/8 -j ACCEPT"
      - "-A INPUT ! -i lo -s 127.0.0.0/8 -j DROP"
      - "-A INPUT -m conntrack --ctstate INVALID -j DROP"
      - "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
      - "-A INPUT -p icmp --icmp-type echo-request -j ACCEPT"
```

The defaults provide a sensible base policy (DROP input/forward, ACCEPT output): accept loopback traffic only from `127.0.0.0/8`/`::1`, drop spoofed loopback-sourced packets arriving on other interfaces, drop INVALID conntrack state packets, accept established/related connections, and accept ICMP echo requests.

Rules files are validated with `iptables-restore --test` before being written and are only applied when the file changes or `iptables_force_reload` is set.

### ipset sets (`iptables_ipsets`)

A list of set definitions. Each set is created atomically using a create-flush-populate-swap-destroy cycle so the live set is never empty during an update.

```yaml
iptables_ipsets:
  - name: blocklist
    type: hash:ip          # any valid ipset type
    family: inet           # inet or inet6 (omit for types that don't support it)
    hashsize: 4096         # optional
    maxelem: 131072        # optional
    timeout: 0             # optional; seconds, 0 = no expiry
    comment: true          # optional; enables per-entry comments
    entries:
      - 192.0.2.1
      - 198.51.100.0/24
    match:                 # optional: auto-generate an iptables rule for this set
      chain: INPUT         # INPUT, FORWARD, OUTPUT — default: INPUT
      direction: src       # src or dst — default: src
      proto: tcp           # tcp, udp, both — omit for protocol-independent match
      ports: [80, 443]     # optional; single port uses --dport, multiple uses -m multiport --dports
      target: DROP         # ACCEPT, DROP, REJECT — default: ACCEPT
      ipversion: [4, 6]    # optional; inferred from family (inet→[4], inet6→[6]) if omitted
```

The `match` block generates the corresponding `-m set --match-set` rule and injects it into the appropriate rules template (v4, v6, or both). A `proto: both` value expands into separate `tcp` and `udp` rules.

Sets are re-applied when the ipset config file changes, a set is not currently loaded, or `iptables_force_reload` is set.

### OS-specific variables (not intended for override)

Loaded automatically from `vars/<ansible_os_family>.yml`. Do not override these in inventory or playbooks.

| Variable | Debian/Ubuntu | RedHat/EL |
|---|---|---|
| `iptables_v4_rules_path` | `/etc/iptables/rules.v4` | `/etc/sysconfig/iptables` |
| `iptables_v6_rules_path` | `/etc/iptables/rules.v6` | `/etc/sysconfig/ip6tables` |
| `iptables_ipset_save_path` | `/etc/ipset.conf` | `/etc/sysconfig/ipset` |
| `iptables_service_name` | `netfilter-persistent` | `iptables` |
| `iptables_extra_services` | *(empty)* | `[ip6tables]` |
| `iptables_rules_dir` | `/etc/iptables` | *(empty — `/etc/sysconfig/` already exists)* |

On RedHat/EL, `iptables` and `ip6tables` are separate services; the role enables both. The rules file format (`iptables-restore`) is identical across OS families — only the paths differ.

## Boot-time ordering

**Debian/Ubuntu:** `iptables-persistent` plugins load in numerical order — `15-ip4tables` and `15-ip6tables` fire before `25-ipset`. If any iptables rule references an ipset set, the load fails at boot. When `iptables_ipsets` is non-empty the role installs a systemd drop-in (`netfilter-persistent.service.d/ipset-first.conf`) that restores the ipset config via `ExecStartPre` before any plugin runs.

**RedHat/EL:** `ipset.service` (from `ipset-service`) declares `Before=iptables.service` in its unit file, so the correct ordering is handled natively. No drop-in is installed.

## Handlers

| Listen name | Action |
|---|---|
| `restore iptables` | `iptables-restore <rules.v4>` |
| `restore ip6tables` | `ip6tables-restore <rules.v6>` |
| `restore netfilter` | restart `netfilter-persistent` |
| `reload systemd daemon` | `systemctl daemon-reload` |

## Testing

### Unit tests

Template unit tests exercise the Jinja2 templates directly — no Ansible or target host required.

```bash
cd roles/iptables/tests
pip install -r requirements.txt
pytest -v
```

The suite covers filter table structure, table render ordering, open-port scoping (v4/v6/both), ipset match rule generation (`--dport`, multiport, `proto: both`, direction, chain, target), IP-version scoping (`family`, `ipversion` override), `ipset.conf` rendering, drop logging (`iptables_log_enable`, prefix, limit, ordering), and rule ordering invariants — including that ipset match rules precede convenience port rules — verified for both IPv4 and IPv6.

### Integration tests (Molecule)

Molecule scenarios apply the role against Debian 12 and Ubuntu 22.04 containers and verify end-to-end behaviour: files written to correct paths, `netfilter-persistent` enabled, iptables rules and ipset sets loaded in the kernel, systemd drop-in lifecycle (created when ipsets defined, removed when not), idempotency, and that the ipset DROP rule precedes open-port ACCEPT rules in the live kernel chain.

Two scenarios:

| Scenario | `iptables_ipsets` | Key assertions |
|---|---|---|
| `default` | blocklist with one entry | ipset in kernel, drop-in present, DROP precedes ACCEPT in `iptables-save` |
| `no_ipsets` | `[]` | drop-in absent, no stale sets in kernel |

```bash
pip install -r molecule-requirements.txt
cd roles/iptables
molecule test              # default scenario (Debian 12 + Ubuntu 22.04)
molecule test -s no_ipsets
```

Requires Docker with privileged container support (for kernel netfilter access).

## Example playbook

A complete playbook for a typical web server: SSH access restricted to an allowlisted set of admin IPs, HTTP/HTTPS open to the world, and a blocklist of known-bad addresses dropped before anything else.

```yaml
---
- hosts: webservers
  become: true
  roles:
    - role: iptables
      vars:
        # Drop traffic from known-bad IPs immediately, and allow SSH only
        # from admin hosts. HTTP/HTTPS is open to everyone.
        iptables_ipsets:
          - name: blocklist
            type: hash:net
            family: inet
            hashsize: 4096
            entries:
              - 198.51.100.0/24
              - 203.0.113.42
            match:
              target: DROP

          - name: admin_hosts
            type: hash:ip
            family: inet
            entries:
              - 10.0.0.10
              - 10.0.0.11
            match:
              proto: tcp
              ports: [22]
              target: ACCEPT

        # HTTP and HTTPS open to all (ipset rules are appended after these)
        iptables_open_ports:
          - { port: 80,  proto: tcp }
          - { port: 443, proto: tcp }

        # Extend the default IPv4 filter rules to jump through the blocklist
        # check first, before any ACCEPT rules run
        iptables_v4_tables:
          filter:
            policies:
              INPUT: DROP
              FORWARD: DROP
              OUTPUT: ACCEPT
            rules:
              - "-A INPUT -i lo -s 127.0.0.0/8 -j ACCEPT"
              - "-A INPUT ! -i lo -s 127.0.0.0/8 -j DROP"
              - "-A INPUT -m conntrack --ctstate INVALID -j DROP"
              - "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
              - "-A INPUT -p icmp --icmp-type echo-request -j ACCEPT"
              # blocklist DROP and admin_hosts ACCEPT rules are appended here
              # automatically from the ipset match blocks above
```

The blocklist `DROP` and admin `ACCEPT` rules are injected into the filter table automatically from the `match` blocks — no need to write the `-m set --match-set` lines by hand.

## Examples

### Basic: open SSH and HTTP/HTTPS

```yaml
- hosts: servers
  become: true
  roles:
    - role: iptables
      vars:
        iptables_open_ports:
          - { port: 22,  proto: tcp }
          - { port: 80,  proto: tcp }
          - { port: 443, proto: tcp }
```

### Add a custom chain and extra table

```yaml
iptables_v4_tables:
  filter:
    policies:
      INPUT: DROP
      FORWARD: DROP
      OUTPUT: ACCEPT
    chains:
      - LOGDROP
    rules:
      - "-A INPUT -i lo -s 127.0.0.0/8 -j ACCEPT"
      - "-A INPUT ! -i lo -s 127.0.0.0/8 -j DROP"
      - "-A INPUT -m conntrack --ctstate INVALID -j DROP"
      - "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
      - "-A LOGDROP -j LOG --log-prefix 'DROPPED: '"
      - "-A LOGDROP -j DROP"
      - "-A INPUT -j LOGDROP"
```

### Log dropped packets

```yaml
iptables_log_enable: true
iptables_log_prefix: "iptables-drop: "   # optional, this is the default
iptables_log_limit: "5/min"              # optional, this is the default
```

This appends a rule like the following to each filter chain with a `DROP` policy (by default `INPUT` and `FORWARD`):

```
-A INPUT   -m limit --limit 5/min -j LOG --log-prefix "iptables-drop: "
-A FORWARD -m limit --limit 5/min -j LOG --log-prefix "iptables-drop: "
```

Packets then continue to the chain policy and are dropped as normal. The rate limit prevents the kernel log from being flooded by a scan or burst of traffic.

### Block a dynamic IP list with ipset

```yaml
iptables_ipsets:
  - name: blocklist
    type: hash:ip
    family: inet
    entries:
      - 198.51.100.5
      - 203.0.113.0/24
    match:
      target: DROP

iptables_v4_open_ports:
  - { port: 22, proto: tcp }
```

### Allowlist with ipset (allow only specific IPs on a port)

```yaml
iptables_ipsets:
  - name: admin_hosts
    type: hash:ip
    family: inet
    entries:
      - 10.0.0.10
      - 10.0.0.11
    match:
      chain: INPUT
      direction: src
      proto: tcp
      ports: [8080]
      target: ACCEPT

iptables_v4_tables:
  filter:
    policies:
      INPUT: DROP
      FORWARD: DROP
      OUTPUT: ACCEPT
    rules:
      - "-A INPUT -i lo -s 127.0.0.0/8 -j ACCEPT"
      - "-A INPUT ! -i lo -s 127.0.0.0/8 -j DROP"
      - "-A INPUT -m conntrack --ctstate INVALID -j DROP"
      - "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
      # ipset match rule for admin_hosts is appended automatically
      - "-A INPUT -p tcp --dport 8080 -j DROP"  # drop all other access
```
