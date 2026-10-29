# SecurlyQ Product Brief

## Problem
Small IT teams and student developers generate security logs but have no security operations center. Raw logs are noisy and hard to interpret, so suspicious activity goes unnoticed or unexplained.

## Target customer
Small IT teams (2-20 people) and student developers who need a simple way to explore security events and understand *why* something looks suspicious.

## Core user story
> As an IT analyst, I want to understand why an alert was triggered so I can decide whether it needs further investigation.

## Additional user stories
- As an analyst, I can send authentication/application/network events to an API so they are stored and analyzed.
- As an analyst, I can filter alerts by severity and status so I work on the riskiest ones first.
- As an analyst, I can acknowledge an alert and leave notes so my team knows it was reviewed.
- As an admin, I can manage who has access so analysts and viewers only see what they should.
- As a team lead, I can see detection-quality metrics (precision, recall) so I know whether to trust the tool.

## Principles
1. Findings are *potentially suspicious*, never "confirmed attacks".
2. The LLM explains evidence; it never decides maliciousness and never triggers actions.
3. Every alert links to the events that caused it (traceable evidence).

## MVP success metrics
- Time from event ingestion to alert availability.
- Precision and recall on labeled test events.
- % of alerts with traceable supporting evidence.
- Time for a user to understand an alert.
- API availability and error rate.

## Out of scope (for now)
Automated remediation, multi-tenant billing, agent-based log collection, custom-trained LLMs.
