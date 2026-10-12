def protocol(value):
    mapping = {"-1": "any", "*": "any", "all": "any", "6": "tcp", "17": "udp", "1": "icmp", "58": "icmp", "icmpv6": "icmp", "ipv6-icmp": "icmp"}
    value = str(value).lower()
    value = mapping.get(value, value)
    if value not in {"tcp", "udp", "icmp", "any"}:
        raise ValueError(f"unsupported protocol: {value}")
    return value


def ports(value):
    if str(value) == "*":
        return 0, 65535
    parts = str(value).replace(":", "-").split("-")
    if len(parts) == 1:
        return int(parts[0]), int(parts[0])
    if len(parts) == 2:
        return int(parts[0]), int(parts[1])
    raise ValueError(f"unsupported port range: {value}")
