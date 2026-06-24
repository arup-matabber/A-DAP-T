# A-DAP-T Scoring Methodology

## Purpose

A-DAP-T gives an AI-agent safety score to help developers understand the risk level of a GenAI or agentic project before deployment.

The score is not a certification. It is an explainable heuristic score based on detected risk patterns.

## Score Direction

A-DAP-T uses a safety score from 0 to 100.

- Higher score means lower detected risk.
- Lower score means higher detected risk.

Example:

```text
A-DAP-T Safety Score: 34/100 — Critical Risk
```

## Risk Categories

The scanner evaluates six categories:

1. Prompt Injection Risk
2. Secret Exposure Risk
3. Tool Permission Risk
4. Human Approval Risk
5. Data Exposure Risk
6. Auditability Risk

## Category Risk Weights

```text
Overall Risk =
25% Prompt Injection Risk
20% Secret Exposure Risk
20% Tool Permission Risk
15% Human Approval Risk
10% Data Exposure Risk
10% Auditability Risk
```

Final score:

```text
Safety Score = 100 - Overall Risk
```

## Status Mapping

```text
0-25 safety score   = Critical Risk
26-50 safety score  = High Risk
51-75 safety score  = Moderate Risk
76-90 safety score  = Low Risk
91-100 safety score = Strong
```

## Severity Levels

Findings use the following severity levels:

- Critical
- High
- Medium
- Low
- Info

## Why This Scoring Is Defendable

A-DAP-T uses transparent risk categories instead of a black-box score. Each finding is linked to a category, severity, affected file, explanation, and suggested fix.

The score is meant to support developer decision-making. It should not be presented as a complete security certification.

## Known Limitations

- The scanner may produce false positives.
- It may miss risks hidden behind unusual code patterns.
- It does not execute uploaded code.
- It does not fully validate runtime behavior.
- It should be paired with manual review before production deployment.
