# Product
SOC Triage Guardrails: a small serverless AWS pipeline.
A GuardDuty finding triggers a Lambda that asks Amazon Bedrock (Claude) for a plain-English
summary, a MITRE ATT&CK technique, a severity, and a recommended action, then posts it to Slack.
The project then attacks its own prompt with prompt-injection payloads (v1, naive) and hardens it (v2).

# Context
- Solo personal portfolio project for a new-grad security professional. Not production.
- The owner must understand every line. Explain what you build and why, in plain English.
- No custom frontend. Slack is the output surface.
- SPEC.md in the repo root is the source of truth for scope, phases, and design.
