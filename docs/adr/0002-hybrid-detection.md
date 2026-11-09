# ADR 0002: Hybrid detection (rules + Isolation Forest)

**Status:** Accepted

## Context
Deterministic rules are explainable but only catch patterns someone anticipated. Anomaly models catch unanticipated patterns but are harder to explain and noisier. We have no labeled real-world attack data.

## Decision
- Keep rules as the primary, explainable signal.
- Add an **unsupervised Isolation Forest** over per-(IP, 10-minute) features as a second signal. It enriches rule alerts (anomaly score feeds the risk score) and raises its own alerts only for activity no rule explains. Consecutive anomalous buckets merge into one episode alert.
- Convert raw model scores to training-set percentiles so the threshold is an interpretable alert budget; choose the threshold on a validation split.
- Evaluate rules-only, model-only, and hybrid on a held-out test split with disjoint attacker IPs, and report a supervised logistic regression only as a reference.
- The model never takes action and never closes alerts. If the model file is missing, corrupt, or fails its checksum, analysis falls back to rules-only.

## Consequences
+ Catches stealthy activity that rules miss (low-and-slow), at the cost of more alerts.
+ Every model alert is traceable to events and states which features drove it.
- Detection quality is demonstrated on synthetic data only.
- Model files are pickles: they must come from a trusted, access-controlled location.
- Alerts are immutable after creation; evidence for a still-in-progress episode is not appended on later runs.
