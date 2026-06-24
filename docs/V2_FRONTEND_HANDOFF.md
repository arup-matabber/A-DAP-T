# A-DAP-T V2 Frontend Handoff

## Current Priority

Frontend must now show the V2 report artifacts that backend already returns:

- deployment gate
- attack simulations / prove mode
- patch previews
- DAP assistant answers using V2 context

The old report page only showing score + findings is no longer enough for this hackathon version.

## Product Flow To Support

```text
Scan → Prove Risk → Generate Fix → Re-scan → Block Unsafe Deployment
```

Pavit owns re-scan / compare work. The current frontend work should focus on displaying the backend artifacts cleanly.

## Report Page Required Sections

1. Score and severity summary
2. Scan metadata
3. Findings
4. Deployment Gate
5. Prove Mode / Attack Simulations
6. Generated Fixes / Patch Previews
7. AI Analysis
8. DAP assistant
9. Raw JSON export
10. PDF export

## Deployment Gate UI

Use `report.deployment_gate`.

Important fields:

```text
decision
summary
decision_badge
decision_reason
required_action
minimum_safety_score
safety_score
gate_score
blockers
next_actions
workflow_filename
policy_filename
github_actions_yaml
policy_json
ci_secret_requirements
download_assets
severity_counts
```

UI should show:

```text
Decision: BLOCK / REVIEW / ALLOW
Gate score
Blockers
Next actions
Copy workflow
Download workflow.yml
Download policy.json
```

## Attack Simulation UI

Use `report.attack_simulations`.

Important fields:

```text
finding_id
title
simulation_type
risk_level
priority_score
file
line
location
evidence
attack_goal
malicious_input
weakness_exploited
preconditions
attack_steps
expected_behavior
impact
detection_signal
required_fix
guardrail
safe_test_note
```

UI should show:

```text
Attack goal
Malicious prompt / trigger
Attack steps
Expected unsafe behavior
Detection signal
Required guardrail
Safe test note
```

Important: This is static proof-of-risk. Do not imply that A-DAP-T actively attacks live systems.

## Patch Preview UI

Use `report.patches`.

Important fields:

```text
finding_id
title
file
line
patch_type
patch_filename
copy_label
download_label
before
after
diff
explanation
confidence
manual_review_required
apply_strategy
review_notes
estimated_effort
risk_reduction
affected_controls
validation_steps
language
```

UI should show:

```text
Patch title
Linked finding
File
Patch type
Risk reduction
Estimated effort
Validation steps
Diff preview
Copy patch
Download patch
Manual review required
```

Do not show patches as auto-applied fixes. They are preview-only.

## DAP Assistant

DAP endpoint is unchanged:

```text
POST /assistant/chat
```

Request body:

```json
{
  "question": "What should I fix first?",
  "scan_result": { "...current report...": true }
}
```

DAP now understands V2 fields. Good demo questions:

```text
What should I fix first?
Can I deploy this?
Prove how this can be attacked.
Which patch should I use?
What does the deployment gate block?
```

## Auth

Protected API calls still need:

```text
Authorization: Bearer <firebase_id_token>
```

Frontend auth state still uses:

```text
adpt_auth
```

Required behavior:

```text
refresh token before protected API calls
retry once after refresh
redirect to signin only when refresh fails
```

## Current Static Frontend Safety Net

The static `frontend/pages/report.html` now displays:

- deployment gate
- attack simulations
- patch previews
- patch download
- workflow/policy download

This gives us a working fallback while the Next.js frontend is being rebuilt.
