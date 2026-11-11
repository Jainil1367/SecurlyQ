# Phase 6 Lesson Notes: Infrastructure as Code on AWS

## 1. Why Terraform
Clicking through the AWS console can't be reviewed, repeated or undone cleanly. Terraform files describe the desired end state; `terraform plan` shows exactly what would change; `apply` makes it so; `destroy` removes it (and the bill). The files live in git like any code.

## 2. The pieces and why each exists (`infra/`)
| File | What it builds | Why |
|---|---|---|
| `network.tf` | VPC with two private subnets, security groups | The database must not be reachable from the internet |
| `database.tf` | RDS PostgreSQL 16, encrypted, 7-day backups | Managed Postgres: patches and backups are AWS's job |
| `secrets.tf` | Secrets Manager entries (DB URL, JWT secret) | Secrets never go in code, images or git |
| `ecr.tf` | Container registry with image scanning | Where App Runner pulls the image from |
| `iam.tf` | Two roles (pull image; app runtime) | Least privilege: the app can read 2 secrets and call Bedrock, nothing else |
| `apprunner.tf` | The API service + VPC connector | Runs the container, scales, health checks, zero servers to manage |
| `frontend.tf` | Private S3 bucket + CloudFront | Static dashboard over HTTPS; `/api/*` forwarded to the API (one origin, no CORS) |
| `monitoring.tf` | Alarms, SNS email, monthly budget | You hear about problems and surprise bills |
| `github_oidc.tf` | Role GitHub Actions can assume | Deploys with no long-lived AWS keys |

## 3. Ideas worth remembering
- **Least privilege & network isolation:** DB security group accepts only the app's security group on port 5432. No public IP, no internet gateway.
- **Cost-aware design:** no NAT gateway (~$32/mo); the app reaches Bedrock through a VPC endpoint instead. Cost is a design constraint, not an afterthought.
- **Secrets flow:** Terraform generates the passwords (`random_password`), stores them in Secrets Manager, and App Runner injects them at start. They do exist in the Terraform *state file*, so state must be protected (git-ignored; S3 + encryption later).
- **OIDC federation:** GitHub presents a signed token; AWS trusts it only for repo `Jainil1367/SecurlyQ` on `main`. A stolen key can't exist because there is no key.
- **Migrations at start-up** (`entrypoint.sh`): `set -e` means a failed migration stops the container instead of serving a broken schema.
- **Fail-safe defaults:** `ENVIRONMENT=production` makes the app refuse a weak JWT secret; `OPEN_REGISTRATION=false` stops strangers creating accounts.

## 4. A security bug found while designing this
The API allowed anyone to register as an analyst. Locally that is convenient; on the internet it lets strangers ingest data and run analysis. Fix: a setting that closes self-signup after the first admin exists, plus an admin-only `POST /users`. Seven tests cover it. Lesson: *deployment changes your threat model; re-read your own endpoints from an attacker's seat.*

## 5. What is not verified
Terraform could not be run in the build sandbox and Docker had no daemon, so neither `terraform validate` nor the image build has run. Expect small fixes on your first `plan`. Live AWS behaviour (App Runner VPC networking, Bedrock access) is untested until you deploy.

## Exercises
1. Run `terraform plan` and find the security-group rule that lets the app reach the database. What would break if you removed it?
2. Why does CloudFront use a *function* for single-page-app routing rather than a custom 404 page?
3. Estimate the monthly cost of adding a read replica. Which file changes?
4. Add an alarm for "no successful logins in 24 hours". Which metric would you need to emit first?
