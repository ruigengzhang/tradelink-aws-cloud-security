# TradeLink AWS Cloud Security & Vulnerability Management

Project 3 is an offline cloud security assessment for the fictional TradeLink cross-border trading platform. It models a trade-document bucket, an audit archive, a worker IAM policy and an EC2 security group. A small Python scanner identifies configuration risks, records evidence and checks whether a remediation resolves each finding.

The lab reads synthetic JSON fixtures. It makes no AWS API calls and provisions no resources. Python 3.13 or 3.14 is enough to run it. No AWS credentials, network access, or Python package installs are required.

## Run the assessment

Open a terminal in this repository. On the Mac used for this project, run:

```sh
python3.14 -m cloudlab scan fixtures/baseline.json
python3.14 -m cloudlab scan fixtures/remediated.json
python3.14 -m cloudlab compare fixtures/baseline.json fixtures/remediated.json
python3.14 -m unittest discover -s tests -v
```

Use `python3.13` instead if that is the version installed. The baseline scan reports three findings across four resources. The remediated scan has zero findings under these three rules. The comparison reports:

```text
TradeLink remediation retest
Resolved: 3
  TL-EC2-01 [High] security_groups/sg-demo-trade-worker
  TL-IAM-01 [High] iam_policies/TradeDocumentsWorker
  TL-S3-01 [Medium] s3_buckets/tradelink-trade-documents
Still Open: 0
New: 0
```

## Reproduce one repair yourself

Copy the baseline to a scratch file and remove the inbound SSH rule whose source includes `0.0.0.0/0` and `::/0`. Keep the HTTPS rule and the original resource ID. The reference repair is in `fixtures/remediated.json`.

```sh
mkdir -p evidence
cp fixtures/baseline.json evidence/my-retest.json
```

After editing `evidence/my-retest.json`, run:

```sh
python3.14 -m cloudlab compare fixtures/baseline.json evidence/my-retest.json
```

Expect **1 resolved** and **2 still open**. A comparison exits with code 1 while findings remain or new findings appear. Invalid or unmatched inventories return code 2. An inventory change is rejected so an omitted resource cannot be mistaken for a verified repair.

## Scope and files

| Path | Purpose |
| --- | --- |
| `cloudlab/` | Offline scanner and comparison command |
| `fixtures/` | Synthetic baseline and remediated snapshots |
| `docs/assessment-report.md` | Findings, risk ratings, owners, fixes and retest evidence |
| `docs/snapshot-format.md` | Supported input shape and control coverage |
| `tests/` | Regression tests for scanner rules, malformed inputs and CLI |
| `.github/workflows/security.yml` | Tests and fixture retest on Python 3.13 and 3.14 after upload |

The checks assess configuration patterns. They cannot establish effective IAM permissions, live network reachability, or S3 object exposure. The report records these limits and links to the relevant AWS controls.
