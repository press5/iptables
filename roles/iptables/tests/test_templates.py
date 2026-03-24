"""
Unit tests for the iptables role Jinja2 templates.

Tests render templates directly with controlled variable inputs and assert
on the produced iptables-restore / ipset-restore text. No Ansible or target
host is required.

Run:
    pip install -r requirements.txt
    pytest -v
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FILTER_TABLE = {
    "policies": {"INPUT": "DROP", "FORWARD": "DROP", "OUTPUT": "ACCEPT"},
    "chains": [],
    "rules": [],
}


def _ipset(name, *, match=None, family=None, entries=None, **kwargs):
    """Build a minimal ipset dict for use in tests."""
    s = {"name": name, "type": "hash:ip", "entries": entries or []}
    if family is not None:
        s["family"] = family
    if match is not None:
        s["match"] = match
    s.update(kwargs)
    return s


# ---------------------------------------------------------------------------
# Filter table structure
# ---------------------------------------------------------------------------


class TestFilterTableStructure:
    def test_star_filter_present(self, render_v4):
        assert "*filter" in render_v4()

    def test_policies_rendered(self, render_v4):
        out = render_v4()
        assert ":INPUT DROP [0:0]" in out
        assert ":FORWARD DROP [0:0]" in out
        assert ":OUTPUT ACCEPT [0:0]" in out

    def test_commit_present(self, render_v4):
        assert "COMMIT" in render_v4()

    def test_v6_filter_policies(self, render_v6):
        out = render_v6()
        assert "*filter" in out
        assert ":INPUT DROP [0:0]" in out
        assert "COMMIT" in out

    def test_custom_chain_declared(self, render_v4):
        tables = {
            "filter": {
                **_FILTER_TABLE,
                "chains": ["LOGDROP"],
                "rules": [
                    "-A LOGDROP -j LOG --log-prefix 'DROPPED: '",
                    "-A LOGDROP -j DROP",
                ],
            }
        }
        out = render_v4(iptables_v4_tables=tables)
        assert ":LOGDROP - [0:0]" in out
        assert "-A LOGDROP -j DROP" in out

    def test_default_rules_present(self, render_v4):
        out = render_v4()
        assert "-A INPUT -i lo -s 127.0.0.0/8 -j ACCEPT" in out
        assert "-A INPUT ! -i lo -s 127.0.0.0/8 -j DROP" in out
        assert "--ctstate INVALID -j DROP" in out
        assert "--ctstate ESTABLISHED,RELATED -j ACCEPT" in out


# ---------------------------------------------------------------------------
# Table ordering and presence
# ---------------------------------------------------------------------------


class TestTableOrdering:
    def test_raw_before_filter(self, render_v4):
        tables = {
            "raw": {"rules": ["-A PREROUTING -j ACCEPT"]},
            "filter": _FILTER_TABLE,
        }
        out = render_v4(iptables_v4_tables=tables)
        assert out.index("*raw") < out.index("*filter")

    def test_absent_tables_not_rendered(self, render_v4):
        # Default var only defines filter; mangle and nat must be absent
        out = render_v4()
        assert "*mangle" not in out
        assert "*nat" not in out

    def test_all_four_tables_rendered_when_defined(self, render_v4):
        tables = {
            "raw": {"rules": []},
            "mangle": {"rules": []},
            "nat": {"rules": []},
            "filter": _FILTER_TABLE,
        }
        out = render_v4(iptables_v4_tables=tables)
        for name in ["*raw", "*mangle", "*nat", "*filter"]:
            assert name in out
        # Verify ordering
        positions = [out.index(f"*{t}") for t in ["raw", "mangle", "nat", "filter"]]
        assert positions == sorted(positions)


# ---------------------------------------------------------------------------
# Open ports (convenience rules)
# ---------------------------------------------------------------------------


class TestOpenPorts:
    def test_open_ports_both_appear_in_v4(self, render_v4):
        out = render_v4(iptables_open_ports=[{"port": 22, "proto": "tcp"}])
        assert "-A INPUT -p tcp --dport 22 -j ACCEPT" in out

    def test_open_ports_both_appear_in_v6(self, render_v6):
        out = render_v6(iptables_open_ports=[{"port": 22, "proto": "tcp"}])
        assert "-A INPUT -p tcp --dport 22 -j ACCEPT" in out

    def test_v4_open_ports_not_in_v6(self, render_v6):
        out = render_v6(iptables_v4_open_ports=[{"port": 9090, "proto": "tcp"}])
        assert "--dport 9090" not in out

    def test_v6_open_ports_not_in_v4(self, render_v4):
        out = render_v4(iptables_v6_open_ports=[{"port": 9090, "proto": "tcp"}])
        assert "--dport 9090" not in out

    def test_open_ports_appear_after_custom_rules(self, render_v4):
        out = render_v4(iptables_open_ports=[{"port": 22, "proto": "tcp"}])
        # Default rules include loopback accept; port rule must come after
        custom_pos = out.index("-A INPUT -i lo")
        port_pos = out.index("-A INPUT -p tcp --dport 22")
        assert port_pos > custom_pos


# ---------------------------------------------------------------------------
# ipset match rule generation
# ---------------------------------------------------------------------------


class TestIpsetMatchRules:
    def test_no_match_key_produces_no_rule(self, render_v4):
        out = render_v4(iptables_ipsets=[_ipset("notrule")])
        assert "--match-set notrule" not in out

    def test_default_direction_src_chain_input_target_accept(self, render_v4):
        out = render_v4(iptables_ipsets=[_ipset("myset", match={})])
        assert "-A INPUT -m set --match-set myset src -j ACCEPT" in out

    def test_direction_dst(self, render_v4):
        out = render_v4(iptables_ipsets=[_ipset("myset", match={"direction": "dst"})])
        assert "--match-set myset dst" in out

    def test_target_drop(self, render_v4):
        out = render_v4(iptables_ipsets=[_ipset("bl", match={"target": "DROP"})])
        assert "-j DROP" in out
        assert "--match-set bl src -j DROP" in out

    def test_chain_forward(self, render_v4):
        out = render_v4(
            iptables_ipsets=[_ipset("myset", match={"chain": "FORWARD"})]
        )
        assert "-A FORWARD -m set --match-set myset src" in out

    def test_single_port_uses_dport(self, render_v4):
        out = render_v4(
            iptables_ipsets=[
                _ipset("myset", match={"proto": "tcp", "ports": [22]})
            ]
        )
        assert "-p tcp --dport 22 -m set --match-set myset src -j ACCEPT" in out
        assert "multiport" not in out

    def test_multiport_uses_multiport_module(self, render_v4):
        out = render_v4(
            iptables_ipsets=[
                _ipset("myset", match={"proto": "tcp", "ports": [80, 443]})
            ]
        )
        assert "-p tcp -m multiport --dports 80,443 -m set --match-set myset" in out

    def test_three_ports_comma_separated(self, render_v4):
        out = render_v4(
            iptables_ipsets=[
                _ipset("myset", match={"proto": "tcp", "ports": [53, 443, 853]})
            ]
        )
        assert "--dports 53,443,853" in out

    def test_proto_both_expands_to_two_rules(self, render_v4):
        out = render_v4(
            iptables_ipsets=[
                _ipset("myset", match={"proto": "both", "ports": [53]})
            ]
        )
        assert "-p tcp" in out
        assert "-p udp" in out
        assert out.count("--match-set myset") == 2

    def test_no_proto_no_ports_produces_no_p_flag(self, render_v4):
        out = render_v4(iptables_ipsets=[_ipset("myset", match={"target": "DROP"})])
        rule_lines = [l for l in out.splitlines() if "--match-set myset" in l]
        assert len(rule_lines) == 1
        assert "-p " not in rule_lines[0]

    def test_ports_without_proto_defaults_to_tcp(self, render_v4):
        # When ports are given but proto is omitted, tcp is assumed (multiport
        # requires a protocol, so the template defaults _protos to ['tcp'])
        out = render_v4(
            iptables_ipsets=[_ipset("myset", match={"ports": [80, 443]})]
        )
        assert "-p tcp" in out
        assert "--dports 80,443" in out

    def test_ipset_match_rules_appear_before_open_ports(self, render_v4):
        out = render_v4(
            iptables_ipsets=[_ipset("myset", match={"target": "DROP"})],
            iptables_open_ports=[{"port": 22, "proto": "tcp"}],
        )
        port_pos = out.index("--dport 22")
        ipset_pos = out.index("--match-set myset")
        assert ipset_pos < port_pos


# ---------------------------------------------------------------------------
# IP version scoping of ipset match rules
# ---------------------------------------------------------------------------


class TestIpsetIpVersionScoping:
    def test_family_inet_only_in_v4(self, render_v4, render_v6):
        sets = [_ipset("v4set", family="inet", match={"target": "DROP"})]
        assert "--match-set v4set" in render_v4(iptables_ipsets=sets)
        assert "--match-set v4set" not in render_v6(iptables_ipsets=sets)

    def test_family_inet6_only_in_v6(self, render_v4, render_v6):
        sets = [_ipset("v6set", family="inet6", match={"target": "DROP"})]
        assert "--match-set v6set" not in render_v4(iptables_ipsets=sets)
        assert "--match-set v6set" in render_v6(iptables_ipsets=sets)

    def test_no_family_appears_in_both(self, render_v4, render_v6):
        sets = [_ipset("dualset", match={"target": "DROP"})]
        assert "--match-set dualset" in render_v4(iptables_ipsets=sets)
        assert "--match-set dualset" in render_v6(iptables_ipsets=sets)

    def test_explicit_ipversion_list_overrides_family(self, render_v4, render_v6):
        # family=inet would normally restrict to v4, but ipversion=[4,6] forces both
        sets = [
            _ipset(
                "myset",
                family="inet",
                match={"target": "DROP", "ipversion": [4, 6]},
            )
        ]
        assert "--match-set myset" in render_v4(iptables_ipsets=sets)
        assert "--match-set myset" in render_v6(iptables_ipsets=sets)

    def test_explicit_ipversion_4_only(self, render_v4, render_v6):
        sets = [_ipset("myset", match={"target": "DROP", "ipversion": [4]})]
        assert "--match-set myset" in render_v4(iptables_ipsets=sets)
        assert "--match-set myset" not in render_v6(iptables_ipsets=sets)

    def test_explicit_ipversion_6_only(self, render_v4, render_v6):
        sets = [_ipset("myset", match={"target": "DROP", "ipversion": [6]})]
        assert "--match-set myset" not in render_v4(iptables_ipsets=sets)
        assert "--match-set myset" in render_v6(iptables_ipsets=sets)


# ---------------------------------------------------------------------------
# ipset.conf rendering
# ---------------------------------------------------------------------------


class TestIpsetConf:
    def test_create_line_basic(self, render_ipset):
        sets = [_ipset("bl", family="inet", entries=["1.2.3.4", "5.6.7.8"])]
        out = render_ipset(iptables_ipsets=sets)
        assert "create -exist bl hash:ip family inet" in out

    def test_add_entries(self, render_ipset):
        sets = [_ipset("bl", entries=["1.2.3.4", "10.0.0.0/8"])]
        out = render_ipset(iptables_ipsets=sets)
        assert "add -exist bl 1.2.3.4" in out
        assert "add -exist bl 10.0.0.0/8" in out

    def test_no_optional_fields_in_create_line(self, render_ipset):
        sets = [_ipset("bl")]
        out = render_ipset(iptables_ipsets=sets)
        line = next(l for l in out.splitlines() if l.startswith("create"))
        assert "hashsize" not in line
        assert "maxelem" not in line
        assert "timeout" not in line
        assert "comment" not in line

    def test_optional_fields_appear_when_set(self, render_ipset):
        sets = [
            {
                "name": "bl",
                "type": "hash:ip",
                "hashsize": 4096,
                "maxelem": 65536,
                "timeout": 300,
                "comment": True,
                "entries": [],
            }
        ]
        out = render_ipset(iptables_ipsets=sets)
        assert "hashsize 4096" in out
        assert "maxelem 65536" in out
        assert "timeout 300" in out
        assert "comment" in out

    def test_multiple_sets_all_present(self, render_ipset):
        sets = [
            _ipset("first", entries=["1.1.1.1"]),
            _ipset("second", entries=["2.2.2.2"]),
        ]
        out = render_ipset(iptables_ipsets=sets)
        assert "create -exist first" in out
        assert "add -exist first 1.1.1.1" in out
        assert "create -exist second" in out
        assert "add -exist second 2.2.2.2" in out

    def test_empty_ipsets_produces_no_create_lines(self, render_ipset):
        out = render_ipset(iptables_ipsets=[])
        assert "create" not in out


# ---------------------------------------------------------------------------
# Drop logging
# ---------------------------------------------------------------------------


class TestDropLogging:
    def test_log_disabled_by_default(self, render_v4):
        out = render_v4()
        assert "-j LOG" not in out

    def test_log_enabled_v4(self, render_v4):
        out = render_v4(iptables_log_enable=True)
        assert "-j LOG" in out

    def test_log_enabled_v6(self, render_v6):
        out = render_v6(iptables_log_enable=True)
        assert "-j LOG" in out

    def test_log_rules_for_drop_chains_only(self, render_v4):
        out = render_v4(iptables_log_enable=True)
        lines = [l for l in out.splitlines() if "-j LOG" in l]
        # Default policies: INPUT DROP, FORWARD DROP, OUTPUT ACCEPT
        chains = {l.split()[1] for l in lines}
        assert "INPUT" in chains
        assert "FORWARD" in chains
        assert "OUTPUT" not in chains

    def test_log_uses_default_prefix(self, render_v4):
        out = render_v4(iptables_log_enable=True)
        assert '--log-prefix "iptables-drop: "' in out

    def test_log_custom_prefix(self, render_v4):
        out = render_v4(iptables_log_enable=True, iptables_log_prefix="fw: ")
        assert '--log-prefix "fw: "' in out
        assert "iptables-drop" not in out

    def test_log_uses_default_limit(self, render_v4):
        out = render_v4(iptables_log_enable=True)
        assert "--limit 5/min" in out

    def test_log_custom_limit(self, render_v4):
        out = render_v4(iptables_log_enable=True, iptables_log_limit="1/sec")
        assert "--limit 1/sec" in out

    def test_log_rules_appear_after_open_ports_and_ipset(self, render_v4):
        out = render_v4(
            iptables_log_enable=True,
            iptables_open_ports=[{"port": 22, "proto": "tcp"}],
            iptables_ipsets=[
                {"name": "bl", "type": "hash:ip", "entries": [], "match": {"target": "DROP"}}
            ],
        )
        port_pos = out.index("--dport 22")
        ipset_pos = out.index("--match-set bl")
        log_pos = out.index("-j LOG")
        assert log_pos > port_pos
        assert log_pos > ipset_pos

    def test_log_absent_when_no_drop_policies(self, render_v4):
        tables = {
            "filter": {
                "policies": {"INPUT": "ACCEPT", "FORWARD": "ACCEPT", "OUTPUT": "ACCEPT"},
                "rules": [],
            }
        }
        out = render_v4(iptables_log_enable=True, iptables_v4_tables=tables)
        assert "-j LOG" not in out
