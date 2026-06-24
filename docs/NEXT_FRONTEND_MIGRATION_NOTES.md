# Next.js Frontend Migration Notes

## Scope of this patch

This patch starts the full frontend migration from static HTML/CSS/JS to Next.js.

It adds a new Next.js app inside `frontend/` while keeping the old static files in place for fallback/reference.

## Current implemented routes

```text
/
/signin
/signup
/scanner
/report/current
/profile
/methodology
```

## Design direction

The new frontend uses a charcoal editorial-security style:

```text
- charcoal / near-black background
- controlled emerald accent
- Newsreader for large headings
- Inter for readable text
- Space Grotesk for technical labels
- glass panels
- large rounded cards
- no neon-green overload
```

## Current functional flow

```text
1. User signs in or signs up through backend auth endpoints.
2. Auth metadata is stored under adpt_auth.
3. Scanner page runs demo, GitHub, or ZIP scans.
4. Latest scan result is saved to session/local storage.
5. /report/current renders the V2 report workspace.
6. Report workspace shows verdict, category risks, findings, Prove Mode, patch previews, deployment gate, and DAP.
7. Profile page loads saved reports and reopens them into /report/current.
```

## Backend dependency

The frontend expects the V2 response contract from:

```text
docs/A-DAP-T-V2-API-CONTRACT.md
```

Important fields:

```text
findings
attack_simulations
patches
deployment_gate
category_scores
summary
safety_score
```

## Background video

The landing page is ready to use:

```text
frontend/public/hero-bg.mp4
```

If the file is missing, the page falls back to the existing gradient/poster and CSS atmosphere.

## Next work

```text
1. Add /report/[id] route for direct saved report loading.
2. Add /compare route after Pavit finalizes score-delta work.
3. Improve mobile layouts after real testing.
4. Add final visual polish once all V2 flows work.
```
