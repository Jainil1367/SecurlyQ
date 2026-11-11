# Enabling Bedrock explanations

SecurlyQ works without this: with `LLM_PROVIDER=disabled` (the default) alerts get template explanations. Follow these steps to switch on model-written ones.

> I could not call Bedrock from the build environment, so the Bedrock client is tested only against a stubbed AWS client. Your first live call is the real integration test. Model IDs, regional availability, and pricing change; **verify each item below in the AWS console and current AWS documentation.**

## 1. Pick a region and model
1. In the AWS console open **Amazon Bedrock** in the region you will deploy to.
2. Choose a text model that supports the **Converse** API and follow the console's steps to get access to it (some models require enabling access or accepting terms).
3. Copy the **exact model ID or inference profile ID** shown in the console. Do not type it from memory.

## 2. Configure the app
```
LLM_PROVIDER=bedrock
BEDROCK_MODEL_ID=<id copied from the console>
AWS_REGION=<same region>
```
Locally, boto3 uses your AWS CLI credentials (`aws configure`, or SSO). On AWS (App Runner/ECS) it uses the service's **IAM role**; never put access keys in `.env`, the image, or the repository.

## 3. Least-privilege IAM policy
Attach to the role that runs the API. Replace the placeholders.
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokeOnlyTheConfiguredModel",
      "Effect": "Allow",
      "Action": ["bedrock:InvokeModel"],
      "Resource": ["arn:aws:bedrock:<region>::foundation-model/<model-id>"]
    }
  ]
}
```
The Converse API is authorized by the `bedrock:InvokeModel` action. If you use a cross-region **inference profile**, the policy must also allow the inference-profile ARN and the underlying foundation-model ARNs in each region it can route to; check the current Bedrock documentation for the exact resources.

## 4. Control cost
- Create an **AWS Budget** with an alert before the first real call.
- Every request is capped by `LLM_MAX_OUTPUT_TOKENS` (default 700), at most `LLM_MAX_EVIDENCE_EVENTS` (default 25) events are sent, results are cached on the alert, and each user is limited to `LLM_REQUESTS_PER_HOUR` (default 30) model calls.
- Check the current per-token price for your chosen model on the Bedrock pricing page.

## 5. Smoke test
```bash
# with a token from /api/v1/auth/login and an existing alert id
curl -X POST localhost:8000/api/v1/alerts/1/explain -H "Authorization: Bearer $TOKEN"
```
`"source": "llm"` means the model answered and passed validation. `"source": "fallback"` plus `fallback_reason` tells you why not: `llm_unavailable` (check credentials, region, model access, IAM) or `invalid_output:<reason>` (the model answered but validation rejected it). Details are in the API logs (`securlyq.llm`), which never contain prompts or completions.
