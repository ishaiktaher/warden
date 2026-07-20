# Optional AWS reference deployment

This module provisions the Warden baseline on private ECS Fargate tasks with an
HTTPS ALB, Multi-AZ RDS PostgreSQL, encrypted multi-node Redis, asymmetric KMS
signing, Secrets Manager, an Object-Lock audit bucket, least-privilege task
roles, and CloudWatch logs.

AWS is not required by Warden core. This module selects the optional `aws_kms`,
`aws_secrets_manager`, and `aws_s3` provider adapters. Build its image with:

```bash
docker build --build-arg REQUIREMENTS_FILE=requirements/providers/aws.txt -t warden .
```

Other deployments use the core `requirements.txt` and select the portable HTTP
providers or native plugins. See `docs/PROVIDERS.md`.

Supply an existing VPC with public ALB subnets, private application/data
subnets, an ACM certificate, an immutable container image digest, and the OIDC
issuer/audience. Run `terraform plan` in a staging account before apply. The
required `public_url` input is the canonical HTTPS URL exposed by your DNS and
certificate configuration.
private subnets require NAT or VPC endpoints for ECR, CloudWatch, KMS, Secrets
Manager, S3, and approved connector traffic.

Do not put wildcard hosts in `allowed_egress_hosts`. Production connector
traffic should additionally pass through AWS Network Firewall or an explicit
egress proxy; application allowlisting is defense in depth, not a firewall.
