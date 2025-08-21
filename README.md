# Jira Stichwort-Zuordnung — PRO v5 (E-Mail + PIN)

**Login ohne Cookies:** Nutzer melden sich mit **E-Mail + PIN** an.
- Erstkonfiguration: E-Mail, Jira-URL, API-Token, PIN setzen → wird mit `scrypt`+Fernet verschlüsselt in DB gespeichert.
- Login: E-Mail + PIN → Token wird entschlüsselt und Verbindung hergestellt.

## Secrets
```toml
FERNET_KEY = "<32-byte-base64>"  # globaler Key (für optionale zukünftige Features reserviert)
DATABASE_URL = "postgresql+psycopg2://USER:PASS@HOST/DB?sslmode=require"
```

## Tabelle
```sql
CREATE TABLE IF NOT EXISTS user_pin (
  email TEXT PRIMARY KEY,
  salt  BYTEA NOT NULL,
  enc_token TEXT NOT NULL,
  jira_base_url TEXT NOT NULL,
  account_id TEXT NOT NULL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Sicherheit
- Im Client wird nichts persistiert (kein Cookie/LocalStorage).
- In der DB liegt der Token **nur** Fernet-verschlüsselt mit einem Schlüssel, der aus der **PIN + Salt (scrypt)** abgeleitet wird.
- PIN vergessen ⇒ Token neu hinterlegen (Reset über „Erstkonfiguration“).
