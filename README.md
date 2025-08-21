
# Jira Stichwort‑Zuordnung — PRO v6.3 (SSO + PIN)

Produktiv‑Tool zur Pflege von **P‑Labels (Salesforce‑Projektnummern „PXXXXXX“)** in Jira‑Tickets, zur **Zeiterfassung** (Einzeln + CSV), **Auswertung** (Reports, Timesheet) und **Systemgesundheit** (Health‑Check+).

> **TL;DR**: Wähle Projekt(e) → weise P‑Labels mit **Vorschau & Bestätigung** zu → erfasste Zeiten pflegen/importieren → **Reports & Timesheet** auswerten → alles sicher mit **PIN‑Verschlüsselung** oder **Jira SSO (OAuth)**.

---

## ⭐ Features

- **P‑Labels** (Hauptbereich): Tickets gezielt oder **alle in Ansicht** beschriften — immer **genau ein** P‑Label pro Ticket; _Änderungen zuerst als Vorschau_, dann **explizit bestätigen**.
- **Übersicht**: Filter (Status, Suche, Projekt), **klickbare Ticket‑Links**, Status „Erledigt“ wird **mit** angezeigt (ab v6.3).
- **Worklog (Einzeln)**: Tag, Startzeit, Dauer (Vielfache von 15 min), Beschreibung.
- **CSV‑Import** (Zeiterfassung): Validierung → **Vorschau** → **Import bestätigen**; Fehlerliste; **Undo** für erzeugte Worklogs.
- **Reports & Export**:
  - Projektsicht: Verteilung der Aufwände nach P‑Label (Tabelle + **Tortendiagramm**).
  - **Global**: „**Eigene** Zeiterfassungen“ über **alle Projekte** in Zeitraum, **ohne Projektauswahl** (ab v6.3).
- **Timesheet**: Wochenansicht (Summen/Tag + Woche), nur eigene Worklogs (optional), CSV‑Export.
- **Health‑Check+**: API‑Reachability, RateLimit/Clock‑Skew, Berechtigungen, **DB‑Verbindungstest**, Token‑Restlaufzeit.
- **Login‑Optionen**: 
  - **Schnell‑Login** via **E‑Mail + PIN** (API‑Token verschlüsselt gespeichert).
  - **Jira SSO** (OAuth 2.0; PKCE oder Confidential Client, inkl. Refresh).

---

## 🧠 Funktionsprinzip & Architektur

- **Frontend**: Streamlit (schnell, interaktiv, serverseitiges Rendering).
- **Jira‑Zugriff**: Jira Cloud REST API v3 (Basic mit API‑Token **oder** OAuth über `api.atlassian.com`).  
- **Security & Storage**
  - **PIN‑Login**: API‑Token wird mit **scrypt + Fernet** verschlüsselt und in DB abgelegt. PIN ist **nicht** gespeichert (nur zur Entschlüsselung).
  - **SSO**: Access/Refresh Token in DB; automatische **Token‑Erneuerung**.
  - **DB**: `DATABASE_URL` (empfohlen: **Neon Postgres** mit `sslmode=require`).
  - **FERNET_KEY**: 32‑Byte Base64; **Server‑Secret** (nicht einchecken!).

---

## 🧩 Voraussetzungen

- Python 3.11+ (getestet mit 3.12)  
- Pakete:
  ```txt
  streamlit, requests, pandas, SQLAlchemy, cryptography, psycopg2-binary, matplotlib, openpyxl
  ```
- Jira Cloud mit Berechtigungen (**Browse Projects, Edit Issues, Worklog Add**).  
- Optional: Atlassian OAuth App (für SSO).  
- Datenbank (z. B. **Neon**).

---

## ⚙️ Installation & Start (lokal)

1. **Repo/ZIP** entpacken, in den Ordner wechseln.
2. Abhängigkeiten installieren:
   ```bash
   pip install -r requirements.txt
   ```
3. **Secrets** anlegen: `.streamlit/secrets.toml` (lokal) oder Streamlit Cloud → **Settings → Secrets**:
   ```toml
   # Sicherheit
   FERNET_KEY = "BASE64_32_BYTE_KEY"        # siehe unten „Key erzeugen“

   # Datenbank
   DATABASE_URL = "postgresql+psycopg2://USER:PASS@HOST:PORT/DB?sslmode=require"

   # (Optional) Jira SSO (OAuth)
   ATLASSIAN_CLIENT_ID = "…"
   ATLASSIAN_CLIENT_SECRET = "…"            # empfohlen (Confidential Client)
   ATLASSIAN_REDIRECT_URI = "http(s)://<deine-app>/"
   ATLASSIAN_SCOPES = "read:jira-user read:jira-work write:jira-work offline_access"
   ```
4. **FERNET_KEY erzeugen** (einmalig):
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
5. Start:
   ```bash
   streamlit run app.py
   ```

---

## ☁️ Deployment (Streamlit Cloud)

1. Repo (z. B. GitHub) verbinden, App deployen.  
2. Unter **App → Settings → Secrets** die gleichen Secrets wie oben setzen.  
3. Für **OAuth**: `ATLASSIAN_REDIRECT_URI` = deine Cloud‑URL (z. B. `https://deine-app.streamlit.app`).  
4. **Neon**: Connection String als `DATABASE_URL` hinterlegen.

---

## 🗄️ Neon‑Datenbank einrichten (Kurz)

1. Auf [neon.tech](https://neon.tech) Projekt + Datenbank erstellen.  
2. **Connection string** im Format:
   ```
   postgresql://USER:PASS@HOST/DB
   ```
   → in `DATABASE_URL` als
   ```
   postgresql+psycopg2://USER:PASS@HOST/DB?sslmode=require
   ```
   eintragen.
3. Tabellen werden beim ersten Start automatisch angelegt (`user_pin`, `user_oauth`).

---

## 🔐 Anmelden & Sicherheit

### 1) Schnell‑Login (E‑Mail + PIN + API‑Token)
- Tab **„Erstkonfiguration / Token ändern“**:
  - E‑Mail, **Jira‑Base‑URL** (z. B. `https://<tenant>.atlassian.net`), **API‑Token** (Jira), **PIN** vergeben → „Speichern“.
  - Token wird mit deiner **PIN** verschlüsselt in DB abgelegt.
- Tab **„Schnell‑Login (E‑Mail + PIN)“**: E‑Mail + PIN → „Verbinden“.

> **Hinweis**: Die PIN wird **nicht** gespeichert; ohne PIN kann dein Token **nicht** entschlüsselt werden.

### 2) Jira SSO (OAuth 2.0)
- Button **„Mit Jira anmelden“** → Consent‑Flow → Workspace wählen.  
- Token‑Refresh läuft automatisch.  
- **Scopes**: `read:jira-user read:jira-work write:jira-work offline_access`

---

## 🧭 Bedienung (Tabs)

### 📋 Übersicht
- Projekte wählen (einzeln oder **Multi‑Projekt‑Modus**).  
- **Status „Erledigt“** wird mit angezeigt (ab v6.3).  
- Filter: Textsuche, Status, Projekt, „Nur ohne P‑Label“.  
- **Ticket**‑Spalte ist klickbar → öffnet Jira.

### 🏷️ P‑Labels (Hauptbereich)
- Tabelle mit Checkbox‑Spalte **„Auswählen“** oder **„Alle in aktueller Ansicht verwenden“**.  
- **Projektnummer (PXXXXXX)** eingeben → **„Änderungen prüfen“**.  
- **Vorschau** zeigt **Alt/Neu** pro Ticket und ob sich etwas ändert.  
- **„Bestätigen & Anwenden“** führt Updates durch (bestehende P‑Nummer wird **ersetzt**, es bleibt **genau eine**).  
- **Undo** möglich (letzte Label‑Aktion).

### ⏱️ Worklog (Einzeln)
- Ticket auswählen oder Key eingeben (z. B. `PROJ-123`).  
- Datum, Startzeit, **Dauer (Vielfache von 15 min)**, Beschreibung.  
- Erstellen → optional **Undo** (letztes Worklog löschen).

### 📥 CSV‑Import (Worklogs)
- **Spalten**: `Ticketnummer;Datum;benötigte Zeit in h` (z. B. `1,5` oder `0.25`)  
  Optional: `Uhrzeit;Beschreibung`.  
- Upload → **Vorschau** (inkl. Fehlerliste) → **Import bestätigen**.  
- Nach Import: Status + **Undo** für erzeugte Worklogs.  
- Button: **Beispiel‑CSV herunterladen**.

### 📊 Reports & Export
- **Projektsicht**: Zeitraum + (optional) „Nur eigene Worklogs“.  
  - Tabelle und **Tortendiagramm** der Minuten nach **P‑Label**.  
- **Global (neu in v6.3)**: „**Eigene Zeiterfassungen** (ohne Projektauswahl)“ über alle Projekte via JQL  
  (`worklogAuthor = currentUser() AND worklogDate between …`).  
- Export: **Tickets‑CSV**, **Worklogs‑CSV**.

### 🗓️ Timesheet
- Wochenauswahl (Vor/Nächste Woche), **Nur eigene** (optional).  
- Tages‑ und Wochensummen pro Ticket, **Export CSV**.

### 🩺 Health‑Check+
- `/myself`, `/project/search`, Header (RateLimit, Clock Skew).  
- **DB‑Verbindung** (SELECT 1).  
- Token‑Restlaufzeit (OAuth) bzw. Basic‑Auth‑Hinweis.  
- Berechtigungen: `BROWSE_PROJECTS`, `WORKLOG_ADD`, `EDIT_ISSUES`.

---

## 🔧 Konfiguration in der App

- **Nur Projekte, bei denen ich Lead bin** (Toggle).  
- **Multi‑Projekt‑Modus** (gleichzeitig mehrere Projekte anzeigen).  
- Auto‑Refresh nach Updates (Labels/Worklogs) mit aktualisierten Daten.

---

## 🔑 Erforderliche Rechte & Scopes

- **Jira Rechte**: Browse Projects, Edit Issues (Labels), Worklog Add/Delete.  
- **OAuth Scopes**: `read:jira-user read:jira-work write:jira-work offline_access`.

---

## 🧪 Troubleshooting

- **401 Unauthorized**: Base‑URL / Token prüfen; bei SSO `redirect_uri` exakt registrieren; Scopes vorhanden?  
- **„redirect_uri not registered“**: OAuth‑App (Atlassian) → Callback URL eintragen.  
- **DB‑Fehler**: `DATABASE_URL`/SSL prüfen; Neon‑IP Whitelist (falls aktiv).  
- **Pandas/Meson Build** auf Windows: nutze offizielle Python + `pip install -r requirements.txt` (vorzugsweise Wheels).

---

## 📝 Beispiel‑CSV

```csv
Ticketnummer;Datum;benötigte Zeit in h;Uhrzeit;Beschreibung
PROJ-101;21.08.2025;0,25;12:30;Daily Standup
PROJ-202;21.08.2025;1.5;09:00;Konzept & Abstimmung
```

---

## 📦 Changelog (Auszug)

- **v6.3**: „Erledigt“ standardmäßig sichtbar; **Globaler Report eigener Worklogs** ohne Projektauswahl.  
- **v6.2**: P‑Labels & CSV mit **Vorschau + Bestätigung**; **Tortendiagramm**; Health‑Check+ (DB, Scopes, Token).  
- **v6.1**: SSO‑Verbesserungen, Speicherung, UI‑Aufräumungen.

---

## 🔮 Roadmap‑Ideen

- P‑Label‑Vorlagen je Kunde / Auto‑Erkennung aus Ticketfeldern.  
- Worklog‑Validierungsregeln (z. B. max/Tag).  
- Admin‑Dashboard (Nutzungsmetriken).

---

## ⚖️ Lizenz

Interne Nutzung. Falls Open‑Source gewünscht, Lizenz ergänzen (z. B. MIT).

---

## 🙌 Support

Fragen/Ideen? Einfach melden – kurze Beschreibung + Screenshot hilft bei der Einordnung.
