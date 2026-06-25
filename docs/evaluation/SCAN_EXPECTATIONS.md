\# A-DAP-T Scanner Expectations



\## Purpose



This document defines what the A-DAP-T scanner should detect in the demo projects.



It helps keep backend scanner logic, mock responses, frontend UI, and demo story aligned.



\## Scanner Goal



The scanner should identify common AI-agent deployment risks before the project is deployed.



It should focus on:



\- exposed secrets

\- unsafe tool permissions

\- missing human approval

\- weak auditability

\- sensitive data exposure

\- prompt injection risk



\## Expected Vulnerable Agent Findings



The vulnerable support agent should trigger findings for:



\- hardcoded Gemini API key pattern

\- hardcoded JWT secret

\- refund tool callable without approval

\- customer record returned without masking

\- internal policy exposed through agent tools

\- email sending without confirmation

\- missing audit log for tool calls

\- prompt injection phrases not blocked

\- user input influencing privileged actions



\## Expected Secured Agent Findings



The secured support agent should show reduced risk because it includes:



\- environment-based secret loading

\- human approval path for refund actions

\- audit logging for tool actions

\- masked customer data

\- prompt injection detection

\- refusal or routing for suspicious instructions

\- safer separation between user input and privileged actions



\## Risk Categories



Scanner findings should map to one of these categories:



\- Prompt Injection Risk

\- Secret Exposure Risk

\- Tool Permission Risk

\- Human Approval Risk

\- Data Exposure Risk

\- Auditability Risk



\## Severity Levels



Findings should use these severity levels:



\- Critical

\- High

\- Medium

\- Low

\- Info



\## Expected Output Shape



The scanner output should match the mock response shape in:



\- docs/mock\_responses/vulnerable\_scan\_response.json

\- docs/mock\_responses/secured\_scan\_response.json



Required top-level fields:



\- project\_name

\- scan\_type

\- safety\_score

\- status

\- summary

\- category\_scores

\- findings

\- graph

\- attack\_replay

\- remediation\_checklist



\## Backend Implementation Rule



The backend can start with hardcoded mock responses.



Later, scanner-generated findings should replace mock findings without changing the final response shape.



\## Gemini Usage Rule



Gemini can be used for:



\- scan summaries

\- remediation explanation

\- report wording

\- developer-friendly next steps



Gemini should not be the only detection mechanism. Core detection should remain rule-based and explainable.



\## Safety Rule



Uploaded code must never be executed.



The scanner should read uploaded project files as text and analyze patterns safely.

