# A-DAP-T Limitations

A-DAP-T is a pre-deployment AI-agent risk visibility tool. It is designed to help developers identify common safety and security issues early.

## What A-DAP-T Does

- Reads project files as text.
- Detects common secret exposure patterns.
- Detects risky tool/function names.
- Detects missing approval patterns.
- Detects missing audit/logging patterns.
- Simulates prompt injection scenarios in a controlled way.
- Produces a safety score, findings, graph data, attack replay, and remediation guidance.

## What A-DAP-T Does Not Do

- It does not execute uploaded code.
- It does not run a full penetration test.
- It does not replace professional security review.
- It does not detect every possible vulnerability.
- It does not fully prove runtime agent safety.
- It does not inspect private external services unless code/config references are present.

## Why Static Scanning Is Used

Running arbitrary uploaded code is unsafe. A-DAP-T avoids that risk by using static scanning and controlled simulation.

This keeps the scanning workflow safer and more predictable.

## False Positives

Some findings may be conservative. For example, a function named `issue_refund` may be flagged even if it is not currently exposed to an LLM at runtime.

This is acceptable because the tool is meant to highlight risk patterns that deserve review.

## False Negatives

Some issues may not be detected if:

- risky logic uses unusual names
- tool execution is hidden behind abstractions
- project files are too large or unsupported
- risk exists only at runtime
- external services are not represented in code

## Correct Usage

A-DAP-T should be used as an early review layer for AI-agent projects. It is best used before deployment to identify issues that developers should inspect and improve.
