import json
from pathlib import Path
import pytest
from ruleshadow.analysis import analyze
from ruleshadow.cli import main
from ruleshadow.parsers import aws, azure, iptables

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("module,file,count", [(aws,"aws.json",4), (azure,"azure.json",6), (iptables,"iptables.txt",5)])
def test_fixture_normalization(module, file, count):
    rules = module.parse((FIXTURES / file).read_text())
    assert len(rules) == count
    assert all(r.src_cidr.version in (4, 6) for r in rules)
    assert all(r.port_min <= r.port_max for r in rules)


@pytest.mark.parametrize("module,file,expected", [
    (iptables, "iptables.txt", [("shadowed","MEDIUM","iptables:7","iptables:6"),
                               ("redundant","LOW","iptables:9","iptables:8"),
                               ("overly-permissive","HIGH","iptables:10",None)]),
    (azure, "azure.json", [("shadowed","MEDIUM","azure:2:0","azure:1:0"),
                          ("redundant","LOW","azure:0:0","azure:3:0"),
                          ("overly-permissive","HIGH","azure:4:0",None),
                          ("overly-permissive","HIGH","azure:4:1",None)]),
    (aws, "aws.json", [("redundant","LOW","aws:0:1:0","aws:0:0:0"),
                      ("overly-permissive","HIGH","aws:0:2:0",None),
                      ("overly-permissive","HIGH","aws:0:2:1",None)])])
def test_exact_findings(module, file, expected):
    findings = analyze(module.parse((FIXTURES / file).read_text()), ordered=module != aws)
    assert [(f.kind, f.severity, f.rule_id, f.related_rule_id) for f in findings] == expected


@pytest.mark.parametrize("fmt,file", [("aws","aws.json"),("azure","azure.json"),("iptables","iptables.txt")])
@pytest.mark.parametrize("as_json", [True, False])
def test_cli(fmt, file, as_json, capsys):
    args = [str(FIXTURES / file), "--format", fmt] + (["--json"] if as_json else [])
    assert main(args) == 0
    output = capsys.readouterr().out
    if as_json:
        result = json.loads(output)
        assert result["format"] == fmt
        assert result["findings"][0]["rule_id"]
    else:
        assert "RuleShadow:" in output and "HIGH" in output


@pytest.mark.parametrize("line", [
    "-A INPUT -p tcp --dport 22 -d 10.0.0.0/8 -j ACCEPT",
    "-A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT",
    "-A INPUT ! -s 10.0.0.0/8 -j DROP",
    "-A INPUT -j CUSTOM", "-A CUSTOM -j ACCEPT", "*nat",
    "-A INPUT -p icmp --dport 22 -j ACCEPT",
    "-A INPUT -p tcp --dport 70000 -j ACCEPT",
    "-A INPUT -p tcp --dport 80:22 -j ACCEPT",
    "-A INPUT -p tcp -p udp -j ACCEPT"])
def test_iptables_unsupported(line):
    with pytest.raises(ValueError):
        iptables.parse(line)


def test_chains_do_not_interact():
    rules = iptables.parse("-A INPUT -j DROP\n-A OUTPUT -p tcp --dport 80 -j ACCEPT")
    assert analyze(rules) == []


@pytest.mark.parametrize("permission", [
    {"IpProtocol":"tcp", "UserIdGroupPairs":[{"GroupId":"sg-x"}]},
    {"IpProtocol":"tcp", "PrefixListIds":[{"PrefixListId":"pl-x"}]},
    {"IpProtocol":"icmp", "FromPort":8,"ToPort":-1},
    {"IpProtocol":"50"}])
def test_aws_rejects_unmodeled_scope(permission):
    with pytest.raises(ValueError):
        aws.parse(json.dumps({"IpPermissions":[permission]}))


def test_aws_group_isolation():
    permission = {"IpProtocol":"tcp","FromPort":80,"ToPort":80,"IpRanges":[{"CidrIp":"10.0.0.0/8"}]}
    rules = aws.parse(json.dumps({"SecurityGroups":[{"IpPermissions":[permission]}, {"IpPermissions":[permission]}]}))
    assert analyze(rules, ordered=False) == []


@pytest.mark.parametrize("field,value", [("sourceAddressPrefix","Internet"), ("sourcePortRange","22"),
    ("destinationAddressPrefix","10.0.0.0/8"), ("destinationPortRanges",["22","80"]), ("direction","Sideways")])
def test_azure_rejects_unmodeled_scope(field, value):
    item = json.loads((FIXTURES / "azure.json").read_text())[0]
    item[field] = value
    with pytest.raises(ValueError):
        azure.parse(json.dumps([item]))


def test_azure_duplicate_priority():
    item = json.loads((FIXTURES / "azure.json").read_text())[0]
    with pytest.raises(ValueError):
        azure.parse(json.dumps([item, item]))


@pytest.mark.parametrize("content", ["{", "[]", '{"SecurityGroups":null}'])
def test_cli_invalid_json(tmp_path, capsys, content):
    file = tmp_path / "bad.json"
    file.write_text(content)
    assert main([str(file), "--format", "aws", "--json"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "invalid input" in output.err


def test_cli_missing_file(tmp_path, capsys):
    assert main([str(tmp_path / "missing"), "--format", "aws"]) == 2
    assert "invalid input" in capsys.readouterr().err
