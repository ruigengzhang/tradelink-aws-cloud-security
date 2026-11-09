import re
from dataclasses import dataclass
from ipaddress import ip_network


BPA_FLAGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)
RESOURCE_GROUPS = ("s3_buckets", "iam_policies", "security_groups")


class SnapshotError(ValueError):
    """The snapshot is incomplete or outside the supported fixture format."""


@dataclass(frozen=True)
class Finding:
    rule: str
    resource: str
    severity: str
    owner: str
    title: str
    evidence: str
    remediation: str


@dataclass(frozen=True)
class Assessment:
    inventory: frozenset[str]
    findings: tuple[Finding, ...]


def require_type(value, expected, location):
    if type(value) is not expected:
        raise SnapshotError(f"{location} must be {expected.__name__}")
    return value


def field(obj, name, expected, location):
    return require_type(obj.get(name), expected, f"{location}.{name}")


def block_flags(obj, name, location):
    settings = field(obj, name, dict, location)
    return {
        key: field(settings, key, bool, f"{location}.{name}")
        for key in BPA_FLAGS
    }


def inspect_bucket(bucket, resource, account_flags):
    local_flags = block_flags(bucket, "public_access_block", resource)
    missing = [key for key in BPA_FLAGS if not (local_flags[key] or account_flags[key])]
    if missing:
        return Finding(
            "TL-S3-01", resource, "Medium", "Storage",
            "S3 public access safeguards incomplete",
            "Disabled at both modeled levels: " + ", ".join(missing),
            "Enable all four Block Public Access safeguards and review existing policies and ACLs.",
        )
    return None


def policy_values(statement, key, location):
    value = statement.get(key)
    values = [value] if isinstance(value, str) else require_type(value, list, f"{location}.{key}")
    if not values or any(not isinstance(item, str) or not item.strip() for item in values):
        raise SnapshotError(f"{location}.{key} must contain one or more nonempty strings")
    return values


def inspect_policy(policy, resource):
    statements = field(policy, "Statement", list, resource)
    broad_statements = []
    for index, statement in enumerate(statements):
        location = f"{resource}.Statement[{index}]"
        require_type(statement, dict, location)
        effect = field(statement, "Effect", str, location)
        if effect not in {"Allow", "Deny"}:
            raise SnapshotError(f"{location}.Effect must be Allow or Deny")
        values = {}
        for positive, negative in (("Action", "NotAction"), ("Resource", "NotResource")):
            keys = statement.keys() & {positive, negative}
            if len(keys) != 1:
                raise SnapshotError(f"{location} must specify exactly one of {positive} or {negative}")
            key = keys.pop()
            values[key] = policy_values(statement, key, location)
        if "Condition" in statement:
            field(statement, "Condition", dict, location)
        if (
            effect == "Allow"
            and not statement.get("Condition")
            and "*" in values.get("Action", [])
            and "*" in values.get("Resource", [])
        ):
            broad_statements.append(str(index + 1))
    if broad_statements:
        return Finding(
            "TL-IAM-01", resource, "High", "Identity",
            "Unconditional wildcard IAM Allow",
            "Action and Resource are both '*' in statement(s) " + ", ".join(broad_statements),
            "Replace wildcard actions and resources with the workload's required operations and ARNs.",
        )
    return None


def inspect_group(group, resource):
    ingress = field(group, "ingress", list, resource)
    open_ssh = []
    for index, rule in enumerate(ingress):
        location = f"{resource}.ingress[{index}]"
        require_type(rule, dict, location)
        protocol = field(rule, "protocol", str, location)
        if protocol not in {"tcp", "udp", "-1"}:
            raise SnapshotError(f"{location}.protocol must be tcp, udp or -1")
        includes_ssh = protocol == "-1"
        if protocol != "-1":
            first = field(rule, "from_port", int, location)
            last = field(rule, "to_port", int, location)
            if not 0 <= first <= last <= 65535:
                raise SnapshotError(f"{location} has an invalid port range")
            includes_ssh = protocol == "tcp" and first <= 22 <= last
        for source in field(rule, "sources", list, location):
            require_type(source, str, f"{location}.sources[]")
            try:
                network = ip_network(source)
            except ValueError as exc:
                raise SnapshotError(f"{location} has an invalid CIDR") from exc
            if includes_ssh and network.prefixlen == 0:
                open_ssh.append(str(network))
    if open_ssh:
        return Finding(
            "TL-EC2-01", resource, "High", "Network",
            "Security group allows SSH from the internet",
            "Ingress covers TCP 22 from " + ", ".join(sorted(set(open_ssh))),
            "Remove the unrestricted SSH rule or limit its sources to the approved admin network.",
        )
    return None


def scan(snapshot):
    require_type(snapshot, dict, "snapshot")
    if field(snapshot, "schema_version", int, "snapshot") != 1:
        raise SnapshotError("snapshot.schema_version must be 1")
    account_flags = block_flags(snapshot, "account_public_access_block", "snapshot")
    inventory = set()
    findings = []
    for group in RESOURCE_GROUPS:
        for entry in field(snapshot, group, list, "snapshot"):
            require_type(entry, dict, group)
            name = field(entry, "id", str, group)
            if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
                raise SnapshotError(f"{group}.id must contain only letters, digits, dots, underscores or hyphens")
            resource = f"{group}/{name}"
            if resource in inventory:
                raise SnapshotError(f"Duplicate resource ID: {resource}")
            inventory.add(resource)

            if group == "s3_buckets":
                finding = inspect_bucket(entry, resource, account_flags)
            elif group == "iam_policies":
                finding = inspect_policy(entry, resource)
            else:
                finding = inspect_group(entry, resource)
            if finding is not None:
                findings.append(finding)

    priority = {"High": 0, "Medium": 1}
    findings.sort(key=lambda finding: (priority[finding.severity], finding.rule, finding.resource))
    return Assessment(frozenset(inventory), tuple(findings))


def compare(before, after):
    if before.inventory != after.inventory:
        missing = ", ".join(sorted(before.inventory - after.inventory)) or "none"
        added = ", ".join(sorted(after.inventory - before.inventory)) or "none"
        raise SnapshotError(f"Retest inventory changed. Missing: {missing}. Added: {added}.")
    baseline = {(item.rule, item.resource): item for item in before.findings}
    retest = {(item.rule, item.resource): item for item in after.findings}
    return {
        "resolved": [item for key, item in baseline.items() if key not in retest],
        "still_open": [item for key, item in retest.items() if key in baseline],
        "new": [item for key, item in retest.items() if key not in baseline],
    }
