# Deploying SecurlyQ to AWS (us-east-2, Ohio)

Everything is defined in `infra/` as Terraform, so the whole environment can be created, reviewed and destroyed with a few commands.

> **Status:** the Terraform was written without being able to run `terraform validate` or `apply` (no AWS access from the build sandbox). Expect to fix a typo or two on the first `plan`; the plan output is your safety net, so read it before typing `yes`.

## What gets created

```
Browser --HTTPS--> CloudFront --/*------> S3 (private bucket: the React dashboard)
                       |
                       +------/api/*---> App Runner (FastAPI container, from ECR)
                                              |  VPC connector (private network, no NAT, no internet)
                                              +--> RDS PostgreSQL 16 (private, encrypted, backups)
                                              +--> Bedrock via VPC endpoint (only when enabled)
Secrets Manager: database URL + JWT secret.   CloudWatch: logs, 3 alarms.   Budget: email alerts.
```

The browser talks to one address. CloudFront sends `/api/*` to the API and everything else to the static site, so no CORS setup is needed.

Estimated cost: about **$20-25/month** with explanations in template mode, **$28-35/month** with Bedrock enabled (the private endpoint is about $7.50 of that, plus a few cents per explanation). The biggest items are the database (~$13) and App Runner (~$7-10). A budget alert is created for you.

## One-time setup on your computer

1. **Create a non-root AWS user.** Never use the root login for daily work. In the AWS console open *IAM Identity Center* (recommended) or *IAM > Users*, create an administrator for yourself, turn on MFA, then run `aws configure sso` (or `aws configure` with access keys). Confirm with `aws sts get-caller-identity`.
2. **Install tools:** [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html), [Terraform 1.6+](https://developer.hashicorp.com/terraform/install), Docker Desktop, Node 22.
3. **Region:** all commands below assume `us-east-2`. Set `export AWS_REGION=us-east-2`.

## First deploy

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars    # set alert_email
terraform init

# 1. Create only the image registry first (App Runner needs an image to exist).
terraform apply -target=aws_ecr_repository.backend

# 2. Build and push the backend image.
REPO=$(terraform output -raw ecr_repository_url)
aws ecr get-login-password | docker login --username AWS --password-stdin "${REPO%%/*}"
docker build -t "$REPO:latest" ../backend          # trains the anomaly model during the build
docker push "$REPO:latest"

# 3. Create everything else (RDS takes ~10 minutes). READ the plan first.
terraform plan
terraform apply

# 4. Build and upload the dashboard.
(cd ../frontend && npm ci && npm run build)
aws s3 sync ../frontend/dist "s3://$(terraform output -raw frontend_bucket)" --delete
aws cloudfront create-invalidation --distribution-id "$(terraform output -raw cloudfront_distribution_id)" --paths "/*"

terraform output app_url        # open this
```

5. **Confirm the alert email.** AWS sends a subscription confirmation for alarms and one for the budget; alarms stay silent until you click the link.
6. **Create your admin account immediately.** Registration is closed after the first account, so whoever registers first becomes the admin. Do it right away:

```bash
APP=$(terraform output -raw app_url)
curl -X POST "$APP/api/v1/auth/register" -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"a-long-passphrase"}'
```

Teammates are added by an admin (CloudFront only forwards `/api/*`, so use curl):

```bash
TOKEN=$(curl -s -X POST "$APP/api/v1/auth/login" -d 'username=you@example.com&password=a-long-passphrase' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -X POST "$APP/api/v1/users" -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"email":"teammate@example.com","password":"another-long-passphrase","role":"analyst"}'
```

7. **Load demo data (optional).** The database is private, so seed it through the API instead of a script: sign in, then `POST /api/v1/events` with a batch of events and press **Run analysis** in the dashboard.

## Turning on Bedrock explanations

1. In the AWS console switch the region to **Ohio (us-east-2)** > *Amazon Bedrock* > *Model access* and request access to a model (an Anthropic Claude model is a good fit). Approval can take minutes.
2. Open *Model catalog*, copy the exact **model ID or inference profile ID** (see [bedrock-setup.md](bedrock-setup.md)).
3. In `terraform.tfvars` set:
   ```hcl
   llm_provider     = "bedrock"
   bedrock_model_id = "<the exact ID>"
   ```
4. `terraform apply`. This adds the VPC endpoint and the `bedrock:InvokeModel` permission, then restarts the service. Click **Explain this alert** on an alert; the badge reads "Amazon Bedrock · validated" when the real model answered, and "Template" when it fell back.

## Deploying changes later

Locally: repeat steps 2 and 4 above, then `aws apprunner start-deployment --service-arn "$(terraform output -raw apprunner_service_arn)"`.

Or with GitHub Actions (no AWS keys stored in GitHub): run `terraform apply` once, then in the repo's *Settings > Secrets and variables > Actions* add

| Kind | Name | Value from |
|---|---|---|
| Secret | `AWS_DEPLOY_ROLE_ARN` | `terraform output github_deploy_role_arn` |
| Variable | `AWS_REGION` | `us-east-2` |
| Variable | `ECR_REPOSITORY` | `securlyq-backend` |
| Variable | `FRONTEND_BUCKET` | `terraform output frontend_bucket` |
| Variable | `CLOUDFRONT_DISTRIBUTION_ID` | `terraform output cloudfront_distribution_id` |
| Variable | `APPRUNNER_SERVICE_ARN` | `terraform output apprunner_service_arn` |

Then *Actions > Deploy > Run workflow*. Only the `main` branch is allowed to assume the deploy role. If your AWS account already has the GitHub OIDC provider, set `create_github_oidc_provider = false`.

## Checking it works

- Open the app URL, sign in, ingest some events, and press **Run analysis**.
- App Runner probes `/health` on the container itself; the dashboard only needs `/api/*` routed.
- Logs: CloudWatch > Log groups > `/aws/apprunner/securlyq-prod-api/...`.
- The migration runs at container start (`backend/entrypoint.sh`). If it fails the container exits and the deployment rolls back, so look at the logs first.

## Tearing it all down (stops the charges)

```bash
cd infra
# Deletion protection blocks destroying the database; turn it off first.
terraform apply -var enable_deletion_protection=false
terraform destroy -var enable_deletion_protection=false
```

## Known gaps (tracked for Phase 7)

- Terraform state is local. Move it to S3 with locking before more than one person runs Terraform.
- No custom domain yet (the default `*.cloudfront.net` HTTPS address is used). Add Route 53 and an ACM certificate (in us-east-1 for CloudFront).
- The App Runner address itself is public, so a determined caller can bypass CloudFront; the API still requires sign-in. Phase 7 adds a shared secret header and rate limiting at CloudFront/WAF.
- Single-AZ database and no read replica. Turn on `multi_az` for real production.
- The API's interactive docs (`/docs`) are not routed through CloudFront, but they are served by the app at its App Runner address; consider disabling them in production.
- If two App Runner instances start at once during a scale-out, both run `alembic upgrade head`; harmless today because migrations are idempotent per revision, but a one-off migration task is cleaner.
