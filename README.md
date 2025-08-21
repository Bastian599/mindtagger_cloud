# Jira Stichwort-Zuordnung — PRO v6.1 (SSO-Fix + PIN) — Full
- Enthält den **Confidential-Client Fix** und den **PKCE-State-Workaround**.
- Features: klickbare Ticket-Links, P-Label Dry-Run/Bulk, Worklog (Einzeln + CSV), Timesheet, Health-Check+.

## Secrets (Streamlit Settings → Secrets)
```toml
FERNET_KEY = "<32-byte Base64>"
DATABASE_URL = "postgresql+psycopg2://USER:PASS@HOST/DB?sslmode=require"
ATLASSIAN_CLIENT_ID = "<…>"
ATLASSIAN_REDIRECT_URI = "https://<deine-app>.streamlit.app"
ATLASSIAN_CLIENT_SECRET = "<…>"  # empfohlen
ATLASSIAN_SCOPES = "read:jira-user read:jira-work write:jira-work offline_access"
```
