# Snapshot format

The scanner accepts a normalized JSON fixture rather than a raw AWS API response. The top-level object contains `schema_version` (integer 1), an `account_public_access_block` object, and three arrays named `s3_buckets`, `iam_policies`, and `security_groups`. See the [baseline snapshot](../fixtures/baseline.json) for a full example.

Each resource has an `id` that is unique within its group. IDs use ASCII letters, digits, dots, underscores and hyphens. Retests compare the same resource IDs in both snapshots.

| Group | Required fields after `id` | Rule |
| --- | --- | --- |
| `s3_buckets` | `public_access_block` object with four explicit boolean flags. The account object uses the same flags | Flag any safeguard disabled at both levels |
| `iam_policies` | `Statement` array. Each statement specifies `Effect`, `Action` or `NotAction`, and `Resource` or `NotResource`. Actions and resources are strings or arrays of strings. `Condition` is optional | Flag an unconditional `Allow` statement with the literal wildcard on both `Action` and `Resource` |
| `security_groups` | `ingress` array. Each rule has a `protocol` of `tcp`, `udp` or `-1` for all protocols, plus a `sources` array of IP networks. TCP and UDP entries require integer `from_port` and `to_port` | Flag a rule permitting TCP 22 from all IPv4 or all IPv6 addresses |

This format deliberately omits AWS organization settings, IAM policy attachments and effective authorization, S3 policies and ACLs, network routes, and other contextual details that a live assessment would need.
