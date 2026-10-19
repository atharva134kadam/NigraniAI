// Single Supabase project (vozxvzjzfcodgljlztis), schema `guardrail`.
// Public anon key only. Data is readable after sign-in via the
// "signed-in read" RLS policies; the service_role key stays in ../.env.
window.COMPLIANCE_CONFIG = {
  DASHBOARD_URL: "https://vozxvzjzfcodgljlztis.supabase.co",
  DASHBOARD_ANON_KEY: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZvenh2emp6ZmNvZGdsamx6dGlzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTE5ODQ1MjIsImV4cCI6MjEwNzU2MDUyMn0.tp-5nwq2KDhUzb5VZgY330kw7EJVyntjnW9sda0jSds",
  DB_SCHEMA: "guardrail",
  // Consent & Purpose service (consent_service/server.py); keeps the shop DB key server-side.
  // Local development: the service on :8091. Deployed: the same address as the page (nginx sends /api to it).
  CONSENT_API: /^(localhost|127\.0\.0\.1)$/.test(location.hostname) ? "http://localhost:8091" : location.origin
};
