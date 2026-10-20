# NigraniAI

**Real-time DPDP compliance, proven from what your systems actually do.**

NigraniAI is an AI compliance agent for India's Digital Personal Data Protection Act, 2023 and the
DPDP Rules, 2025. It reads a company's live logs and database, read-only, and shows in real time where
it stands, why, and what to fix: personal data discovery, consent and purpose, retention and erasure,
breach response with Rule 7 and CERT-In clocks, explainable anomaly detection, an AI assistant, a
readiness score and tamper-evident evidence for auditors.

## Repository layout

| Folder | What it is |
|---|---|
| [`dashboard/`](dashboard/) | The compliance system each client gets: browser dashboard (plain HTML, CSS, JS), the Python service (standard library only) with detectors, the anomaly model, PII detection, billing and the evidence ledger. |
| [`website/`](website/) | The public NigraniAI website. |

Each folder has its own README with setup steps.

## Secrets

No secrets are in this repository. Each part reads its keys from a local `.env` file that is never
committed (see the READMEs for the setting names). Public Supabase *anon* keys appear in browser code
by design; access is limited by Row Level Security.
