# ClaimCheck (Java prototype)
AI assistant that pre-checks influencer scripts for risky claims, missing disclosures and English/Hindi claim drift. Decision support only - every approval stays with a human.

## Run (needs JDK 11+; no Maven, no libraries)
    java ClaimCheck.java            # offline demo mode (keyword "model")

Real AI mode (Google AI Studio key; never put it in code):

    export GEMINI_API_KEY=your_key        # PowerShell: $env:GEMINI_API_KEY="your_key"
    java ClaimCheck.java

Open http://localhost:8080

## Files
- ClaimCheck.java - backend (HTTP server, pipeline, guards, escalation, audit log)
- index.html - front end (input, verdicts, human review, compliance, sign-off, dashboard)
- rules.json - version-dated rules library. FILL IN the exact ASCI clause in each "source" field from the official ASCI documents.
- audit_log.jsonl - created at runtime; export CSV from the dashboard.

## Pipeline (matches the proposal)
input check -> rule retrieval -> claim extraction + judging (Gemini or offline heuristic) -> guards (quote must appear in script; only retrieved rules citable) -> fixed floors (missing tag / risky words / drift => at least Amber) -> escalation (Red, low confidence, unverifiable quote, AI failure, misuse wording, drift) -> Brand Manager accept/edit/override (reason mandatory) -> compliance (if escalated) -> sign-off -> audit log.

Use only synthetic data. Fictional brands and influencers only.
"# Claimcheck" 
