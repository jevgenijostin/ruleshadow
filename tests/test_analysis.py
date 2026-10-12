from dataclasses import replace
import pytest
from ruleshadow.analysis import SENSITIVE, analyze
from ruleshadow.model import Rule, contains


def rule(ident="a", **kwargs):
    return Rule(ident, **({"action":"allow", "protocol":"tcp", "src_cidr":"10.0.0.0/8", "port_min":80, "port_max":80} | kwargs))


@pytest.mark.parametrize("first,second,kind,severity", [
    ("deny","allow","shadowed","MEDIUM"), ("allow","deny","shadowed","MEDIUM"),
    ("allow","allow","redundant","LOW"), ("deny","deny","redundant","LOW")])
def test_action_combinations(first, second, kind, severity):
    findings = analyze([rule(action=first), rule("b", action=second)])
    assert [(f.kind,f.severity,f.rule_id,f.related_rule_id) for f in findings] == [(kind,severity,"b","a")]


@pytest.mark.parametrize("network", ["0.0.0.0/0", "::/0"])
@pytest.mark.parametrize("port", sorted(SENSITIVE))
@pytest.mark.parametrize("proto", ["tcp","udp"])
def test_all_sensitive_ports(network, port, proto):
    findings = analyze([rule(src_cidr=network, protocol=proto, port_min=port, port_max=port)])
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert f"{port} ({SENSITIVE[port]})" in findings[0].explanation


@pytest.mark.parametrize("change", [
    {"action":"deny"}, {"src_cidr":"0.0.0.0/1"}, {"src_cidr":"::/1"},
    {"protocol":"icmp","port_min":0,"port_max":65535}, {"port_min":24,"port_max":24}])
def test_no_sensitive_exposure(change):
    values = {"src_cidr":"0.0.0.0/0", "port_min":22,"port_max":22} | change
    assert analyze([rule(**values)]) == []


def test_any_protocol_exposure_and_containment():
    broad = rule(protocol="any", src_cidr="::/0", port_min=0, port_max=65535)
    narrow = rule("b", protocol="udp", src_cidr="2001:db8::/32")
    assert contains(broad, narrow)
    assert not contains(narrow, broad)
    assert all(str(port) in analyze([broad])[0].explanation for port in SENSITIVE)


def test_unordered_later_superset_and_duplicate_survivor():
    narrow = rule(src_cidr="10.1.0.0/16")
    broad = rule("b")
    duplicate = replace(broad, id="c")
    assert [(f.rule_id,f.related_rule_id) for f in analyze([narrow,broad,duplicate], ordered=False)] == [("a","b"),("c","b")]
    assert analyze([narrow,broad]) == []


@pytest.mark.parametrize("a,b", [("tcp","udp"),("icmp","tcp"),("udp","icmp")])
def test_protocol_disjointness(a,b):
    first = rule(protocol=a, port_min=0,port_max=65535)
    second = rule("b",protocol=b,port_min=0,port_max=65535)
    assert not contains(first,second)


def test_partial_overlap_and_union_are_not_single_rule_containment():
    left = rule(port_min=0,port_max=49)
    right = rule("b",port_min=50,port_max=100)
    combined = rule("c",port_min=0,port_max=100)
    assert analyze([left,right,combined]) == []


def test_priority_order_and_stable_ties():
    late = rule(priority=20)
    early = rule("b",priority=10,action="deny")
    assert analyze([late,early])[0].rule_id == "a"
    assert analyze([late,replace(early,priority=20)])[0].rule_id == "b"


@pytest.mark.parametrize("changes", [{"action":"reject"},{"protocol":"sctp"},
    {"src_cidr":"invalid"},{"port_min":-1},{"port_max":65536},
    {"port_min":90,"port_max":80},{"protocol":"icmp"},{"protocol":"any"}])
def test_model_validation(changes):
    with pytest.raises(ValueError):
        rule(**changes)


def test_analyzer_validation():
    with pytest.raises(ValueError):
        analyze([rule(),rule()])
    with pytest.raises(ValueError):
        analyze([rule(action="deny")],ordered=False)


def test_cidr_normalization():
    assert str(rule(src_cidr="10.1.2.3/8").src_cidr) == "10.0.0.0/8"


def test_empty():
    assert analyze([]) == []
