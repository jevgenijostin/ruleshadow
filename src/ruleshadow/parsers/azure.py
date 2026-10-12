import json
from ..model import Rule
from .common import ports, protocol


def parse(text):
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("expected an Azure rule array")
    rules, priorities = [], set()
    for i, item in enumerate(data):
        item = item.get("properties", item)
        for key in ("sourceAddressPrefixes", "destinationAddressPrefixes", "destinationPortRanges", "sourcePortRanges"):
            if item.get(key):
                raise ValueError(f"Azure {key} is unsupported")
        if item.get("destinationAddressPrefix", "*") != "*" or item.get("sourcePortRange", "*") != "*":
            raise ValueError("Azure destination/source-port constraints are unsupported")
        direction = item.get("direction", "Inbound")
        if direction not in {"Inbound", "Outbound"}:
            raise ValueError("unsupported Azure direction")
        priority = int(item["priority"])
        if (direction, priority) in priorities:
            raise ValueError("duplicate Azure priority within direction")
        priorities.add((direction, priority))
        proto = protocol(item["protocol"])
        lo, hi = ports(item["destinationPortRange"])
        source = item["sourceAddressPrefix"]
        sources = ["0.0.0.0/0", "::/0"] if source == "*" else [source]
        for si, source in enumerate(sources):
            rules.append(Rule(f"azure:{i}:{si}", item["access"].lower(), proto, source, lo, hi, priority, direction))
    return rules
