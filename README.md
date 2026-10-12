# RuleShadow

RuleShadow is a Python 3.10+ CLI that analyzes local firewall exports for dead
rules, redundant scopes, and internet-wide access to sensitive service ports.
It supports AWS Security Groups, simplified iptables-save, and Azure NSG JSON.
It does not connect to a firewall or change its configuration.

## Install

```sh
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# PowerShell: .venv\Scripts\Activate.ps1
pip install -e .
```

The installed `ruleshadow` command and `python -m ruleshadow` are equivalent.
There are no runtime dependencies beyond the Python standard library.

## Usage

Analyze a saved `aws ec2 describe-security-groups` response:

```sh
ruleshadow tests/fixtures/aws.json --format aws
```

Analyze a simplified iptables-save filter table:

```sh
ruleshadow tests/fixtures/iptables.txt --format iptables
```

Analyze an array of Azure NSG rules, with lower priorities evaluated first:

```sh
ruleshadow tests/fixtures/azure.json --format azure --json
```

Example text output from the iptables fixture:

```text
RuleShadow: 5 rules, 3 findings
MEDIUM shadowed [iptables:7]: iptables:6 fully covers iptables:7 with a different action.
LOW redundant [iptables:9]: iptables:8 fully covers iptables:9 with the same action.
HIGH overly-permissive [iptables:10]: Allows internet-wide access to 22 (ssh).
```

JSON output is an object with `format`, `rule_count`, and a `findings` array.
Each finding contains `kind`, `severity`, `rule_id`, `related_rule_id` (null for
exposure findings), and `explanation`. IDs locate the original input:
`iptables:<1-based-line>`, `aws:<0-based-group>:<permission>:<source>`, or
`azure:<0-based-array-index>:<expanded-source>`. AWS sources list IPv4 before
IPv6; Azure wildcard sources expand to IPv4 then IPv6.

Exit status is 0 for successful analysis, including reports with findings, and
2 for input or command-line errors. Errors go to stderr; JSON stdout stays clean.

## Detection semantics

Each rule is normalized to an action, protocol, `ipaddress` network, inclusive
port interval, effective order, and an independent evaluation domain.
Containment requires CIDR containment within one address family, port interval
containment, and matching protocols (or a containing `any` protocol).
Host bits in CIDRs are normalized. TCP/UDP ports range from 0 through 65535.
ICMP has no service ports and uses a full-range placeholder internally.

* **MEDIUM shadowed:** an earlier rule of the opposite action completely covers
  the rule. This includes DENY before ALLOW and ALLOW before DENY.
* **LOW redundant:** a covering rule has the same action, including identical
  scopes and repeated DENYs. Under first-match semantics these rules are also
  unreachable; the LOW classification distinguishes same-action duplication.
* **HIGH overly-permissive:** an ALLOW from exactly `0.0.0.0/0` or `::/0` includes
  sensitive ports: 22 SSH, 23 Telnet, 3389 RDP, 3306 MySQL, 5432 PostgreSQL,
  6379 Redis, 27017 MongoDB, 9200 Elasticsearch, or 2375 Docker. This is a
  configured-scope heuristic for TCP, UDP, and `any`; ICMP is excluded. It is
  reported even if the rule is also shadowed.

For ordered formats, the first earlier fully containing rule is the witness.
Azure priorities sort ascending; iptables preserves file order. Rules in
different chains or Azure directions never cover each other.

AWS is allow-only and unordered: a broader rule anywhere in the same group can
make another redundant. Equal scopes retain the first input representative,
avoiding reports that suggest deleting every duplicate. Separate security
groups are analyzed independently. Findings describe individual rules; do not
treat the whole report as an automatically safe deletion plan.

The MVP uses **single-rule containment**, as opposed to combining several
partial scopes into a covering union. Its time complexity is O(n²), with O(n)
auxiliary storage. It is deterministic and does not sample packets in production.

## Supported input boundaries

* AWS: a `SecurityGroups` response or one object containing `IpPermissions`.
  IPv4 and IPv6 CIDR sources expand into separate normalized rules. Ingress is
  analyzed; `IpPermissionsEgress` is not analyzed. Group references, managed
  prefix lists, unsupported protocols, and ICMP type/code restrictions are
  rejected. Empty CIDR lists yield no rules. Protocol `-1` means any protocol.
* iptables: `-A INPUT|OUTPUT|FORWARD`, `-p`, `-s`, `--dport` (single port or
  colon range), and `-j ACCEPT|DROP|REJECT`. Long aliases for append, protocol,
  source, and jump are accepted. The filter-table header, comments, chain
  declarations/policies, and COMMIT are metadata. Default protocol is `any`;
  omitted source means IPv4 `0.0.0.0/0`; provide an explicit IPv6 source for
  IPv6 rules. Unsupported matches, extensions, jumps, tables, and negation
  fail explicitly. Chain policies are not synthesized into rules.
* Azure: an array of objects with `access`, `protocol`, `sourceAddressPrefix`,
  `destinationPortRange`, and `priority`; `properties` wrappers are accepted.
  Optional direction defaults to Inbound. `*` source expands to both families;
  `*` protocol/ports means any/full range. CIDRs and individual IPs work;
  service tags, plural constraints, specific destination addresses, and source
  port restrictions are rejected. Priorities must be unique per direction.
  Analyze one NSG per file; implicit platform rules are not synthesized.

The tool models the supplied simplified scopes, not complete stateful network
reachability, routing, or the effects of multiple attached policies.

## Tests and privacy

```sh
pip install -e ".[test]"
python -m pytest -q
```

The suite includes realistic fixtures for all formats, exact finding assertions,
CLI checks, validation cases, and 2,800 deterministic Hypothesis examples across
four properties. An independent quadratic reference compares enumerated packet
sets for random rules and priorities. Small CIDRs enumerate every address and
every relevant port equivalence class; full IPv4/IPv6 domains use exact boundary
checks plus generated nested networks. This avoids mistaking random packet
sampling for a proof of containment. GitHub Actions runs pytest on push and PR
for Python 3.10, 3.12, and 3.13; the local build was tested on Python 3.12.

**Privacy:** analysis is entirely local. The tool performs no network calls,
telemetry, credential discovery, or cloud API access. A source scan for network
libraries and process execution APIs was run during delivery and found no
matches. Reproduce the scan with ripgrep (exit 1 means no matches):

```sh
rg -n -i 'requests|urllib|httpx|aiohttp|socket|boto3|botocore|subprocess|os\.system|https?://' src/ruleshadow
```

Installing development dependencies and running GitHub Actions may access
package registries; analyzing an export never does.

## Planned commercial direction

The proposed product has a free CLI for up to 50 rules and one format, with a
paid tier unlocking larger rule sets, more formats, and CI integration that
fails a pipeline on **new** shadowed or overly-permissive findings relative to
a baseline. This MVP enables all three formats without limits. Licensing,
payments, commercial gates, baseline storage, and CI failure mode are future
work; no payment or licensing infrastructure is implemented.

MIT licensed. See [TODO.md](TODO.md) for scope and follow-up work.
