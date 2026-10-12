from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_network


@dataclass(frozen=True)
class Rule:
    id: str
    action: str
    protocol: str
    src_cidr: IPv4Network | IPv6Network | str
    port_min: int = 0
    port_max: int = 65535
    priority: int = 0
    domain: str = "default"

    def __post_init__(self):
        if self.action not in {"allow", "deny"}:
            raise ValueError("action must be allow or deny")
        if self.protocol not in {"tcp", "udp", "icmp", "any"}:
            raise ValueError("unsupported protocol")
        object.__setattr__(self, "src_cidr", ip_network(self.src_cidr, strict=False))
        if not 0 <= self.port_min <= self.port_max <= 65535:
            raise ValueError("invalid port interval")
        if self.protocol in {"any", "icmp"} and (self.port_min, self.port_max) != (0, 65535):
            raise ValueError("any/icmp rules must use the full port interval")


def contains(a: Rule, b: Rule) -> bool:
    """Whether a single rule contains all of another rule's scope."""
    return (
        a.domain == b.domain
        and (a.protocol == "any" or a.protocol == b.protocol)
        and a.src_cidr.version == b.src_cidr.version
        and b.src_cidr.subnet_of(a.src_cidr)
        and a.port_min <= b.port_min <= b.port_max <= a.port_max
    )
