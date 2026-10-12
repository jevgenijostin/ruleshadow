"""Independent packet enumeration oracle, including all small-domain packets.

No random sampling is used to infer containment: every packet is checked.
Full-size networks are additionally checked via critical boundary packets.
"""
from ipaddress import ip_address, ip_network
from itertools import product
from hypothesis import given, settings, strategies as st
from ruleshadow.model import Rule, contains
from ruleshadow.analysis import analyze

PROTOCOLS = ("tcp", "udp", "icmp", "other")


def matches(rule, packet):
    address, protocol, port = packet
    return (address in rule.src_cidr and (rule.protocol == "any" or rule.protocol == protocol)
            and rule.port_min <= port <= rule.port_max)


@st.composite
def small_rule(draw, ident="r"):
    version = draw(st.sampled_from([4, 6]))
    base = int(ip_address("10.0.0.0" if version == 4 else "2001:db8::"))
    width = 32 if version == 4 else 128
    net = ip_network((ip_address(base + draw(st.integers(0, 7))), draw(st.integers(width - 3, width))), strict=False)
    proto = draw(st.sampled_from(["tcp", "udp", "icmp", "any"]))
    lo, hi = sorted(draw(st.tuples(st.integers(0, 3), st.integers(0, 3))))
    if proto in {"icmp", "any"}:
        lo, hi = 0, 65535
    return Rule(ident, draw(st.sampled_from(["allow", "deny"])), proto, net, lo, hi,
                draw(st.integers(0, 10)), draw(st.sampled_from(["INPUT", "OUTPUT"])))


def packet_set(rule):
    # 0..3 plus 4 and 65535 represent all port equivalence classes here.
    return {p for p in product(rule.src_cidr, PROTOCOLS, [0, 1, 2, 3, 4, 65535]) if matches(rule, p)}


@settings(max_examples=700, deadline=None, derandomize=True)
@given(small_rule(), small_rule())
def test_small_containment_exhaustive(a, b):
    expected = a.domain == b.domain and packet_set(b) <= packet_set(a)
    assert contains(a, b) == expected


@settings(max_examples=600, deadline=None, derandomize=True)
@given(st.lists(small_rule(), min_size=0, max_size=9), st.booleans())
def test_findings_against_quadratic_packet_reference(raw, ordered):
    from dataclasses import replace
    rules = [replace(r, id=str(i), action=r.action if ordered else "allow") for i, r in enumerate(raw)]
    effective = sorted(rules, key=lambda r: r.priority) if ordered else rules
    packets = {r.id: packet_set(r) for r in rules}
    expected = []
    for i, b in enumerate(effective):
        for j, a in enumerate(effective[:i] if ordered else effective):
            if a.id == b.id or a.domain != b.domain or not packets[b.id] <= packets[a.id]:
                continue
            if not ordered and packets[a.id] == packets[b.id] and j > i:
                continue
            expected.append(("redundant" if a.action == b.action else "shadowed", b.id, a.id))
            break
    actual = [(f.kind, f.rule_id, f.related_rule_id) for f in analyze(rules, ordered=ordered)]
    assert actual == expected


@st.composite
def large_rule(draw):
    version = draw(st.sampled_from([4, 6]))
    width = 32 if version == 4 else 128
    from ipaddress import IPv4Address, IPv6Address
    address = (IPv4Address if version == 4 else IPv6Address)(draw(st.integers(0, 2**width - 1)))
    network = ip_network((address, draw(st.integers(0, width))), strict=False)
    lo, hi = sorted(draw(st.tuples(st.integers(0, 65535), st.integers(0, 65535))))
    proto = draw(st.sampled_from(["tcp", "udp", "icmp", "any"]))
    return Rule("r", "allow", proto, network, *( (0, 65535) if proto in {"icmp", "any"} else (lo, hi)))


@settings(max_examples=1000, deadline=None, derandomize=True)
@given(large_rule(), large_rule())
def test_full_width_boundary_oracle(a, b):
    # Rectangular scopes: endpoints suffice for every address and port between them.
    packets = product([b.src_cidr.network_address, b.src_cidr.broadcast_address],
                      PROTOCOLS if b.protocol == "any" else [b.protocol], [b.port_min, b.port_max])
    assert contains(a, b) == all(matches(a, p) for p in packets)
    assert contains(a, a)


@settings(max_examples=500, deadline=None, derandomize=True)
@given(large_rule(), st.integers(0, 128))
def test_nested_networks(a, offset):
    from dataclasses import replace
    prefix = min(a.src_cidr.max_prefixlen, a.src_cidr.prefixlen + offset)
    child = ip_network((a.src_cidr.network_address, prefix))
    b = replace(a, src_cidr=child, port_max=a.port_min if a.protocol in {"tcp", "udp"} else 65535)
    assert contains(a, b)
    assert contains(b, a) == (a.src_cidr == b.src_cidr and a.port_max == b.port_max)
