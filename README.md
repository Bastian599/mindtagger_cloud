# Jira Stichwort-Zuordnung — PRO v6 (Jira SSO + PIN)

## Login-Optionen
- **Jira SSO (Atlassian OAuth 2.0 3LO)** mit PKCE (falls kein Secret hinterlegt). Optional Client Secret möglich.
- **E-Mail + PIN** (kein Client-Speicher; Token verschlüsselt via scrypt+Fernet).

## Secrets (Streamlit Settings → Secrets)
```toml
FERNET_KEY = "<32-byte Base64>"
DATABASE_URL = "postgresql+psycopg2://USER:PASS@HOST/DB?sslmode=require"

# SSO (mindestens diese zwei):
ATLASSIAN_CLIENT_ID = "<dein Client ID>"
ATLASSIAN_REDIRECT_URI = "https://<deine-app-url>"   # exakt so in der Atlassian Developer Console eintragen
# optional (Confidential Client):
# ATLASSIAN_CLIENT_SECRET = "<dein Client Secret>"
# optional: Scopes anpassen
# ATLASSIAN_SCOPES = "read:jira-user read:jira-work write:jira-work offline_access"
```

## Atlassian App (Developer Console)
1. https://developer.atlassian.com/console/myapps → **Create** → OAuth 2.0 (3LO)
2. **Scopes**: `read:jira-user read:jira-work write:jira-work offline_access`
3. **Redirect URL**: exakt die URL deiner Streamlit-App (ohne /callback), z. B.: `https://your-app.streamlit.app`
4. **Client ID** (und Secret, falls genutzt) in Secrets eintragen.

## Hinweise
- Nach der Redirect-Rückkehr liest die App `code/state` aus der URL, tauscht ein Token und speichert `access/refresh` + `cloud_id` + `site_url` in `user_oauth`.
- Bei mehreren Jira-Sites kannst du im Login-Schritt die gewünschte auswählen.
- Tokens werden automatisch **refresh**t.
