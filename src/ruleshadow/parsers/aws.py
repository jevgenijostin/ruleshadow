import json
from ..model import Rule
from .common import protocol


def parse(text):
    data = json.loads(text)
    groups = data.get("SecurityGroups", [data]) if isinstance(data, dict) else None
    if not isinstance(groups, list):
        raise ValueError("expected AWS SecurityGroups object")
    rules = []
    for gi, group in enumerate(groups):
        domain = f"aws:{gi}:{group.get('GroupId', 'group')}"
        for pi, permission in enumerate(group["IpPermissions"]):
            if permission.get("UserIdGroupPairs") or permission.get("PrefixListIds"):
                raise ValueError("AWS group references and prefix lists are unsupported")
            proto = protocol(permission["IpProtocol"])
            if proto == "icmp" and (permission.get("FromPort", -1), permission.get("ToPort", -1)) != (-1, -1):
                raise ValueError("ICMP type/code constraints are unsupported")
            lo, hi = (int(permission["FromPort"]), int(permission["ToPort"])) if proto in {"tcp", "udp"} else (0, 65535)
            sources = [r["CidrIp"] for r in permission.get("IpRanges", [])]
            sources += [r["CidrIpv6"] for r in permission.get("Ipv6Ranges", [])]
            for si, source in enumerate(sources):
                rules.append(Rule(f"aws:{gi}:{pi}:{si}", "allow", proto, source, lo, hi, len(rules), domain))
    return rules
