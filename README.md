# Jira Stichwort-Zuordnung — PRO v4.2 (Cloud)

**Neu in v4.2**
- Client-Speicher ist robust: zuerst `extra_streamlit_components.CookieManager`, bei Problemen **Fallback auf Browser LocalStorage** via `streamlit_js_eval`.
- Kein „component not loading“-Abbruch mehr – die App arbeitet weiter.

## Deploy
1) Dateien ins Repo übernehmen (app.py, requirements.txt, README.md)
2) Streamlit Cloud → New app → `app.py`
3) **Secrets**:
```toml
FERNET_KEY = "<32-byte-base64>"
DATABASE_URL = "postgresql+psycopg2://USER:PASS@HOST/DB?sslmode=require"
```
4) Erster Login → „Auf diesem Gerät merken“ → Cookie oder LocalStorage wird gespeichert (nur `accountId`). Tokens liegen verschlüsselt in der DB.

## Hinweis
- In Firmen-Netzen können Komponenten geblockt sein. Dann nutzt die App automatisch LocalStorage.
