\# A-DAP-T Gemini Integration Plan



\## Purpose



Gemini will be used in A-DAP-T to improve explanation quality, report wording, remediation guidance, and developer-friendly next steps.



Gemini should not be the primary detection mechanism.



Core detection should remain rule-based, explainable, and reproducible.



\## What Gemini Should Do



Gemini can generate:



\- executive scan summary

\- finding explanations

\- remediation plan

\- report summary

\- developer next steps



\## What Gemini Should Not Do



Gemini should not:



\- invent findings

\- replace scanner logic

\- execute uploaded code

\- decide safety score alone

\- claim the scan is a complete security audit

\- claim the project is production-safe

\- override rule-based scanner output



\## Integration Location



Prompt templates are stored in:



\- backend/app/content/gemini\_prompt\_templates.py



Future Gemini service code can import these templates and use them after scanner output is generated.



\## Suggested Backend Flow



1\. Scanner reads files safely as text.

2\. Rule-based scanners generate findings.

3\. Scoring logic calculates category risk and safety score.

4\. Backend builds final scan response.

5\. Gemini receives the scan response only for explanation and summary generation.

6\. If Gemini fails, backend returns static fallback text.



\## Suggested Output Fields



Future Gemini output can be added under:



\- ai\_summary

\- ai\_remediation\_plan

\- ai\_report\_summary

\- ai\_next\_steps



Do not remove existing fields:



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



\## Safety Rule



Uploaded code must never be sent blindly to Gemini.



Gemini should receive structured scan results and selected findings, not the full uploaded project by default.



\## API Key Rule



Gemini API key should be loaded from environment variables.



Expected variable:



\- GEMINI\_API\_KEY



The key must never be hardcoded in source files.



\## Fallback Rule



The application should work even if Gemini is unavailable.



If Gemini fails, use existing static templates from:



\- backend/app/content/remediation\_templates.py

\- backend/app/content/report\_sections.py



\## Demo Value



Gemini makes the project stronger because it shows A-DAP-T is not only detecting risks but also helping developers understand and fix them.



The system remains defendable because detection is rule-based and Gemini is used only for explanation.

