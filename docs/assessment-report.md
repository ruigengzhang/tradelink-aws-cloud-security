# TradeLink cloud security assessment

The offline baseline covered four modeled resources supporting trade-document intake and audit storage. The assessment identified two high-priority configuration risks and one medium-priority control gap. After the example remediations, the same inventory yielded three resolved findings, zero still open and zero new.

## Findings and remediation

| ID | Severity | Owner | Baseline evidence | Change verified in retest |
| --- | --- | --- | --- | --- |
| TL-EC2-01 | High | Network | `sg-demo-trade-worker` allows TCP 22 from `0.0.0.0/0` and `::/0` | Removed unrestricted SSH ingress. Private HTTPS ingress remained |
| TL-IAM-01 | High | Identity | `TradeDocumentsWorker` grants unconditional `Allow` with `Action: "*"` and `Resource: "*"` | Restricted the policy to `s3:GetObject` and `s3:PutObject` on the demo bucket's `incoming/` object prefix |
| TL-S3-01 | Medium | Storage | `BlockPublicPolicy` and `RestrictPublicBuckets` are disabled at both modeled levels for the trade-document bucket | Enabled both settings at bucket level. The bucket has all four safeguards under the model |

The Network finding prioritizes reducing the possible remote administration attack surface. A live investigation would confirm that the group is attached, a network path exists and a host listens on port 22. [AWS Security Hub EC2 controls](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-13)

The Identity finding prioritizes limiting the impact of a compromised worker. The example scope assumes the worker only reads and writes incoming objects. Effective AWS permissions also depend on policy attachments, explicit denies and other applicable policy layers. [AWS IAM evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)

The Storage finding concerns incomplete safeguards. This evidence cannot establish that documents were publicly accessible. A live investigation would also review bucket policies, ACLs and applicable organization settings. [Amazon S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)

## Retest evidence

```sh
python3.14 -m cloudlab compare fixtures/baseline.json fixtures/remediated.json
```

| Baseline resources | Retest resources | Resolved | Still open | New |
| --- | --- | --- | --- | --- |
| 4 | 4 | 3 | 0 | 0 |

Both snapshots are synthetic. The ratings are qualitative and apply to the modeled workload. This assessment covers cloud configuration findings. Host package CVEs, exploitation, compliance certification, and live account enumeration are outside scope.
