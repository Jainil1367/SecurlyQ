# ADR 0003: Alert explanations with Amazon Bedrock

**Status:** Accepted

## Context
Analysts need a plain-English reason an alert fired. We want this inside AWS (no third-party API key to manage, IAM-based access, data stays in our AWS account's boundary), and we must assume log content is attacker-controlled.

## Decision
- Call models through **Amazon Bedrock's Converse API**, behind a one-method `TextGenerator` interface. Credentials come from the AWS default chain (IAM role on AWS), never from our config.
- The model **explains, never decides**. It receives only a sanitized *incident record*: usernames pseudonymized, raw event attributes omitted, field text neutralized, at most 25 events (head and tail), data fenced and labelled as untrusted.
- Output must be one JSON object matching a strict schema, and is rejected if it contains URLs, commands or code, automated-action advice, affirmative "confirmed attack" claims, or any IP/account not present in the input.
- On *any* failure (provider disabled, timeout, throttling, rejected output) return a **deterministic template explanation** marked `source: "fallback"` with a reason.
- Explanations are generated **on demand** (`POST /alerts/{id}/explain`), stored on the alert, rate limited per user, and capped in tokens, to control cost.
- Logs record metadata only (outcome, latency, token counts), never prompts or completions.
- Fail fast at startup if `LLM_PROVIDER=bedrock` without `BEDROCK_MODEL_ID`.

## Consequences
+ Works with no AWS access (tests, local dev, outages). Provider is swappable in one file.
+ Prompt injection is defended in layers; the worst case (model obeys an attacker) is caught by output validation and, ultimately, is text a human reads.
- The overclaim filter is deliberately conservative and sometimes rejects honest wording, which costs only a fallback.
- The request holds a database connection while waiting for the model (up to the timeout). Acceptable at MVP scale; move generation to the background worker (SQS) at Level 3.
- Explanation quality is not yet measured against analyst judgement; see known limitations.
