# Checkov Security Exceptions

| Finding | Decision | Justification |
|---|---|---|
| VPC Flow Logs disabled | Accepted | Cost constraint; CloudTrail used as compensating control |
| Detailed EC2 monitoring | Accepted | Prometheus provides equivalent observability at no cost |
| Subnet auto-assigns public IP | Architecture decision | Intentional public EC2 with Elastic IP attached |
| Unrestricted egress | Accepted | Required for threat feed API calls to external sources |
| EBS not optimized | Not applicable | t3.micro does not support EBS optimization |
| Port 80 public | Architecture decision | Required for future nginx reverse proxy |
