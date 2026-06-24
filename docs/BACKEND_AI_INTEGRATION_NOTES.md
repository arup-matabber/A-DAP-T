\# Backend + AI Integration Notes



\## Purpose



This document explains how the AI-risk content connects with the backend scanner.



\## Owned Content



Dhruv's branch provides:



\- attack cases

\- attack replay timelines

\- remediation templates

\- report section helpers

\- threat model

\- scoring methodology

\- limitations

\- demo script



These files support scanner output and frontend presentation.



\## Key Backend Files



\- backend/app/attack\_lab/attack\_cases.py

\- backend/app/attack\_lab/replay\_builder.py

\- backend/app/content/remediation\_templates.py

\- backend/app/content/report\_sections.py



\## How Scanner Should Use This Content



When scanner findings are generated, each finding should map to one of these categories:



\- Prompt Injection Risk

\- Secret Exposure Risk

\- Tool Permission Risk

\- Human Approval Risk

\- Data Exposure Risk

\- Auditability Risk



For each finding, the backend should attach:



\- title

\- severity

\- category

\- file

\- line

\- why\_it\_matters

\- suggested\_fix



If the scanner does not have a custom explanation, it can use remediation templates from:



\- backend/app/content/remediation\_templates.py



\## Attack Replay



The dashboard should receive attack replay content from:



\- backend/app/attack\_lab/replay\_builder.py



Expected usage:



\- get\_attack\_replay("demo\_vulnerable")

\- get\_attack\_replay("demo\_secured")



\## Report Summary



Report text can use:



\- backend/app/content/report\_sections.py



This keeps generated reports consistent and avoids hardcoding all report text in the frontend.



\## Required Scan Response Fields



Do not change the final scan response fields without coordinating with frontend.



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



\## Integration Rule



Scanner logic should remain rule-based and explainable. Gemini should be used for explanation, remediation, summaries, and report wording, not as the only detection mechanism.



\## Safety Rule



Uploaded code must never be executed. The backend should only read uploaded project files as text.

