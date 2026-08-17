# Checkov Security Exceptions

Findings remediated: IMDSv2 (CKV_AWS_79), SG descriptions (CKV_AWS_23),
EC2 IAM role (CKV2_AWS_41), Default SG restricted (CKV2_AWS_12)

## Intentional Exceptions

| ID | Finding | Decision | Justification |
|---|---|---|---|
| CKV_AWS_130 | Subnet auto-assigns public IP | Architecture | Intentional public EC2 with Elastic IP attached |
| CKV_AWS_382 | Unrestricted egress | Accepted | Required for threat feed API calls to external sources |
| CKV_AWS_260 | Port 80 public ingress | Architecture | Required for future nginx reverse proxy |
| CKV_AWS_126 | Detailed monitoring disabled | Accepted | Prometheus/Grafana provide equivalent observability at no cost |
| CKV_AWS_135 | EBS not optimized | Not applicable | t3.micro does not support EBS optimization |
| CKV2_AWS_11 | VPC flow logging disabled | Deferred | Cost constraint; Prometheus/Grafana provide application and system observability |