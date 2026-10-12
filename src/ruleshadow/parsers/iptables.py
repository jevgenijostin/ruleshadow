import shlex
from ..model import Rule
from .common import ports, protocol


def parse(text):
    rules = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#") or line == "COMMIT":
            continue
        if line.startswith("*"):
            if line != "*filter":
                raise ValueError(f"line {number}: only filter tables are supported")
            continue
        if line.startswith(":"):
            continue  # Chain policies are metadata, not explicit rules.
        tokens = shlex.split(line)
        values = {}
        aliases = {"--protocol": "-p", "--source": "-s", "--jump": "-j", "--append": "-A"}
        while tokens:
            flag = aliases.get(tokens[0], tokens[0])
            tokens.pop(0)
            if flag not in {"-A", "-p", "-s", "-j", "--dport"} or not tokens or flag in values:
                raise ValueError(f"line {number}: unsupported or duplicate option {flag}")
            values[flag] = tokens.pop(0)
        if values.get("-A") not in {"INPUT", "OUTPUT", "FORWARD"}:
            raise ValueError(f"line {number}: unsupported chain")
        if values.get("-j") not in {"ACCEPT", "DROP", "REJECT"}:
            raise ValueError(f"line {number}: unsupported target")
        proto = protocol(values.get("-p", "any"))
        if "--dport" in values and proto not in {"tcp", "udp"}:
            raise ValueError(f"line {number}: ports require tcp or udp")
        lo, hi = ports(values.get("--dport", "*"))
        rules.append(Rule(f"iptables:{number}", "allow" if values["-j"] == "ACCEPT" else "deny",
                          proto, values.get("-s", "0.0.0.0/0"), lo, hi, number, values["-A"]))
    return rules
