# Phase 3 Lesson Notes: Data Science and Machine Learning

All numbers below come from `docs/ml/evaluation.md` (seed 7, the held-out **test** split). They are measured on **synthetic data we generated ourselves**, so treat them as a comparison between approaches, not a claim about real-world accuracy.

## 1. The workflow, in order
```
simulate -> explore -> engineer features -> split honestly -> train -> tune threshold -> evaluate once -> deploy
```
Run it yourself: `cd backend && python -m app.ml.train` (about 5 seconds).

## 2. Why synthetic data, and its honest limits (`ml/simulate.py`)
Real labeled attack logs are rare and often private. We simulate normal behaviour (workday login patterns, shared office NAT IPs, a service account logging in every 5 minutes, users who mistype passwords) plus five attacks: `brute_force`, `credential_stuffing`, `compromise`, `low_and_slow`, `multi_ip_takeover`.
Limit: we wrote the attacks *and* the detectors, so results flatter us. That is why every report says so at the top.

## 3. Exploration found two important facts
- **Class imbalance:** attacks are about 3 to 6 percent of rows. A model that never alerts is ~95% "accurate" and worthless. This is why we report precision, recall, and false-alarm rate instead of accuracy (`ml/evaluate.py`, and a test that proves the trap).
- **Unit of analysis matters:** one slow attack spans about 12 ten-minute buckets, so counting buckets over-weights it. We therefore also report **incident recall**: "was each attack caught at least once?", which is how an analyst thinks.

## 4. Feature engineering (`ml/features.py`)
One row = one source IP in one 10-minute window. Features: attempts, failures, failure ratio, distinct accounts, successes, peak attempts per minute, time of day, and how many other IPs touched the same accounts.
- **Circular time:** hour is encoded as sin/cos so 23:55 is near 00:05. (Test: `test_hour_encoding_is_circular`.)
- Each feature answers a question a human analyst would ask. Features you can explain make alerts you can explain.

## 5. Isolation Forest (`ml/detector.py`)
Intuition: split data with random questions ("failures > 7?"). Odd points get isolated in a few splits; ordinary points take many. Short path = anomaly. No labels needed, which is why it suits security.
- Tree models only use the *order* of values, so **no scaling** is required.
- **Rank-normalized scores:** we convert each raw score to its percentile among training scores. 0.99 means "more unusual than 99% of training buckets", and the threshold becomes an **alert budget**.
- **Explanations:** we keep training means and standard deviations, so an alert can say "14 failed logins (+11.2 sigma)" instead of a mystery number.

## 6. Splitting without leaking (`simulate_dataset`)
| Split | Purpose | Rule |
|---|---|---|
| train | fit the model | earliest days |
| validation | choose the alert threshold | next days, **different attacker IPs** |
| test | report final numbers once | latest days, **different attacker IPs again** |

Leakage = information from test data sneaking into training so scores look better than reality. Three tests enforce it: no time overlap, no shared attacker IPs, attacker IPs never appear in normal traffic.

## 7. Results (test split)
| Approach | Precision | Recall | Incident recall | False alerts/day |
|---|---:|---:|---:|---:|
| Rules only | 0.74 | 0.41 | 0.89 | 2.07 |
| Isolation Forest only | 0.78 | 0.82 | 0.98 | 3.21 |
| Hybrid (rules OR model) | 0.76 | 0.89 | 1.00 | 3.93 |
| Logistic regression (supervised) | 0.96 | 0.88 | 0.98 | 0.57 |

What to learn from it:
1. **Rules and the model catch different things.** `low_and_slow` guessing (one attempt every few minutes) slips under every rule window: rules caught 3 of 8, the model 8 of 8. Rules were better-behaved on `multi_ip_takeover`. Hybrid beats either alone, at the cost of more alerts.
2. **Rule false positives are a threshold trade-off, not a bug.** Investigating the 29 false-positive buckets showed ordinary users who typed a wrong password 5 or 6 times and then succeeded, which trips `failure_then_success` at its threshold of 5. Raise it to 8 and false alarms drop but real compromises with 5-7 failures are missed. Every threshold is a choice between the two error types.
3. **The supervised model wins here, and you should be suspicious of that.** It learned from labels produced by the same simulator that created the test attacks. Real deployments lack labels, and a supervised model only recognizes attack shapes it has seen. The Isolation Forest needs no labels and can flag shapes nobody anticipated. We keep logistic regression as a *reference point*, not the product.
4. **Few incidents means noisy numbers.** 46 test incidents: a difference of 2 or 3 points is noise. Re-run with `--seed 8` and watch the table move.

## 8. Combining signals in production (`services/anomaly.py`)
- **Enrich:** a rule alert gets the model's score; risk = severity base + evidence bonus + up to 10 points for anomaly score.
- **Discover:** unusual buckets that no rule explains become their own alerts.
- **Episode merging again:** our first version raised one alert per bucket and turned 2 slow attacks into 27 alerts. Merging consecutive buckets gave 1 alert per incident (36 alerts became 11 on the demo data). *Alert fatigue is a product bug, not a tuning detail.*

## 9. Safety and engineering practice
- **Never unpickle files you don't control.** Model files can run code when loaded. We verify a SHA-256 sidecar before loading; in production the real defense is a private, versioned S3 bucket.
- **Graceful degradation:** missing or corrupt model means rules-only mode, with a log warning; analysis never crashes. (Tested.)
- **Reproducibility:** fixed seeds, versioned model name, training metadata stored inside the artifact, and the Docker image trains its own model at build time.
- Tests use a **stub detector** for the merging logic so they don't depend on ML randomness.

## 10. Known limitations (also in the README)
- Alerts are not updated after creation: an attack still in progress when analysis runs gets one alert, and later evidence is not appended.
- The model sees login activity only, and thresholds are fixed at training time (no drift monitoring yet; planned for Level 3).
- Synthetic data only.

## Bugs and surprises this phase
1. Our first hybrid test failed because at the untuned 0.99 threshold everything the model flagged was already covered by rules. The *code* was right; the test's assumption was data-dependent. Fix: test with a realistic, validation-tuned threshold.
2. Per-bucket model alerts flooded the demo (above).

## Exercises
1. Change `MERGE_GAP_BUCKETS` to 1 and 6. What happens to alert counts on `python -m app.ml.seed_demo`?
2. Add a feature (`distinct_user_agents` is not logged yet, so try `failure_streak`: longest run of consecutive failures). Does PR-AUC improve? Check on **validation**, not test.
3. Run training with seeds 1 through 5 and record the range of hybrid F1. What does that tell you about how much to trust one number?
4. Why must the alert threshold be chosen on validation data, never test data?
