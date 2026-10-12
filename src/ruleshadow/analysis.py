from dataclasses import asdict, dataclass
from .model import Rule, contains

SENSITIVE = {22: "ssh", 23: "telnet", 3389: "rdp", 3306: "mysql",
             5432: "postgres", 6379: "redis", 27017: "mongodb",
             9200: "elasticsearch", 2375: "docker"}


@dataclass(frozen=True)
class Finding:
    kind: str
    severity: str
    rule_id: str
    related_rule_id: str | None
    explanation: str

    def to_dict(self):
        return asdict(self)


def analyze(rules: list[Rule], *, ordered: bool = True) -> list[Finding]:
    if len({r.id for r in rules}) != len(rules):
        raise ValueError("rule IDs must be unique")
    if not ordered and any(r.action != "allow" for r in rules):
        raise ValueError("unordered rule sets must be allow-only")
    effective = sorted(rules, key=lambda r: r.priority) if ordered else list(rules)
    findings = []
    for i, rule in enumerate(effective):
        if rule.action == "allow" and rule.src_cidr.prefixlen == 0 and rule.protocol != "icmp":
            ports = [f"{p} ({SENSITIVE[p]})" for p in sorted(SENSITIVE)
                     if rule.port_min <= p <= rule.port_max]
            if ports:
                findings.append(Finding("overly-permissive", "HIGH", rule.id, None,
                                        "Allows internet-wide access to " + ", ".join(ports) + "."))
        candidates = effective[:i] if ordered else effective
        for j, earlier in enumerate(candidates):
            if earlier.id == rule.id or not contains(earlier, rule):
                continue
            # Keep the first representative of identical unordered scopes.
            if not ordered and contains(rule, earlier) and j > i:
                continue
            same = earlier.action == rule.action
            kind, severity = ("redundant", "LOW") if same else ("shadowed", "MEDIUM")
            findings.append(Finding(kind, severity, rule.id, earlier.id,
                                    f"{earlier.id} fully covers {rule.id} with "
                                    f"{'the same' if same else 'a different'} action."))
            break
    return findings
