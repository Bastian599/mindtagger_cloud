# Jira Stichwort-Zuordnung — PRO v6.2
Änderungen:
- Übersicht: Schnellaktionen entfernt
- P-Labels: 2-Schritt mit Vorschau & Bestätigung, Tabellen-Auswahl
- CSV-Import: Vorschau & Bestätigung
- Reports: Pie Chart Aufwände nach P-Label
- Health-Check+: DB-Check, Token-Expiry, Permissions

## Secrets
```toml
FERNET_KEY = "<32-byte Base64>"
DATABASE_URL = "postgresql+psycopg2://USER:PASS@HOST/DB?sslmode=require"
ATLASSIAN_CLIENT_ID = "<…>"
ATLASSIAN_CLIENT_SECRET = "<…>"  # optional, empfohlen
ATLASSIAN_REDIRECT_URI = "https://<deine-app>.streamlit.app"
ATLASSIAN_SCOPES = "read:jira-user read:jira-work write:jira-work offline_access"
```
