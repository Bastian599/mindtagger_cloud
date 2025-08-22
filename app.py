

# ---- Cached Jira client factory ----
@st.cache_resource(show_spinner=False)
def get_jira_client(base_url: str, email: str, api_token: str):
    # Caches the client per unique credential tuple to avoid repeated logins
    return JiraClientBasic(base_url, email, api_token)
# app.py — Jira Stichwort-Zuordnung PRO v6.2
# Änderungen ggü. v6.1:
# - Übersicht: "Schnellaktionen" entfernt
# - P-Labels: neu als klarer 2‑Schritt (Vorschau → Bestätigen), Tabellenbasierte Auswahl
# - CSV-Import: ebenfalls Vorschau → "Import bestätigen"
# - Reports: Tortendiagramm Aufwände nach P‑Label (Zeitraum, eigene/alle)
# - Health-Check+: DB-Verbindung, Token-Expiry, Berechtigungen/Scopes

import os, re, io, time, json, base64, hashlib, urllib.parse
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, date, time as dtime, timedelta, timezone

import requests
import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text
from cryptography.fernet import Fernet
import streamlit.components.v1 as components
import matplotlib.pyplot as plt

st.set_page_config(page_title="Jira Stichwort-Zuordnung — PRO v6.2 (SSO+PIN)", layout="wide")

# ----------------------------- Secrets & DB -----------------------------
def _sec(name: str, default: str = "") -> str:
    try: return st.secrets.get(name, default)  # type: ignore[attr-defined]
    except Exception: return os.getenv(name, default)

DB_URL = _sec("DATABASE_URL", "sqlite:///./creds.db")
FERNET_KEY = _sec("FERNET_KEY", "")
ATL_CLIENT_ID = _sec("ATLASSIAN_CLIENT_ID", "")
ATL_CLIENT_SECRET = _sec("ATLASSIAN_CLIENT_SECRET", "")  # optional; wenn gesetzt ⇒ Confidential Client
ATL_REDIRECT_URI = _sec("ATLASSIAN_REDIRECT_URI", "")
ATL_SCOPES = _sec("ATLASSIAN_SCOPES", "read:jira-user read:jira-work write:jira-work offline_access")

if not FERNET_KEY:
    st.error("Admin-Hinweis: FERNET_KEY fehlt in Secrets.")
    st.stop()

engine = create_engine(DB_URL, pool_pre_ping=True)
global_cipher = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)

# Crypto helpers (PIN)
def kdf_from_pin(pin: str, salt: bytes) -> bytes:
    return hashlib.scrypt(pin.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
def fernet_from_pin(pin: str, salt: bytes) -> Fernet:
    key = base64.urlsafe_b64encode(kdf_from_pin(pin, salt)); return Fernet(key)

# DB init
def db_init():
    with engine.begin() as con:
        con.execute(text("""
        CREATE TABLE IF NOT EXISTS user_pin (
          email TEXT PRIMARY KEY,
          salt  BYTEA NOT NULL,
          enc_token TEXT NOT NULL,
          jira_base_url TEXT NOT NULL,
          account_id TEXT NOT NULL,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"""))
        con.execute(text("""
        CREATE TABLE IF NOT EXISTS user_oauth (
          email TEXT PRIMARY KEY,
          atlassian_account_id TEXT,
          cloud_id TEXT NOT NULL,
          site_url TEXT NOT NULL,
          access_token TEXT NOT NULL,
          refresh_token TEXT NOT NULL,
          expires_at TIMESTAMP NOT NULL,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"""))
db_init()

# ----------------------------- Jira Clients -----------------------------
def normalize_base_url(url: str) -> str:
    url=(url or "").strip()
    return url[:-1] if url.endswith("/") else url

class JiraError(Exception): pass

    def batch_update_issue_labels(self, updates: Dict[str, List[str]], chunk_size: int = 20):
        """Update Labels für mehrere Tickets, in Chunks (schont RateLimit)."""
        errs = []
        keys = list(updates.keys())
        for i in range(0, len(keys), chunk_size):
            for k in keys[i:i+chunk_size]:
                try:
                    self.update_issue_labels(k, updates[k])
                except Exception as e:
                    errs.append(f"{k}: {e}")
            if i+chunk_size < len(keys):
                time.sleep(1)  # kleine Pause zwischen Chunks
        return errs

class JiraClientBasic:
    def __init__(self, base_url, email, api_token, timeout=30):
        self.base_url=normalize_base_url(base_url); self.timeout=timeout
        self.s=requests.Session(); self.s.auth=(email, api_token)
        self.s.headers.update({"Accept":"application/json","Content-Type":"application/json"})
    def _req(self, method, path, params=None, data=None, retries=3):
        url=f"{self.base_url}{path}"
        for attempt in range(retries):
            r=self.s.request(method,url,params=params,data=data,timeout=self.timeout)
            if r.status_code in (429,502,503,504):
                time.sleep(1.5*(attempt+1)); continue
            if r.status_code>=400:
                try: detail=r.json()
                except Exception: detail=r.text
                raise JiraError(f"HTTP {r.status_code} für {path}: {detail}")
            try: return r.json()
            except Exception: return None
        raise JiraError(f"Failed after retries: {method} {path}")
    def get_myself(self): return self._req("GET","/rest/api/3/myself")
    def list_projects(self, only_led_by: Optional[str] = None):
        start_at=0; max_results=50; out=[]
        while True:
            d=self._req("GET","/rest/api/3/project/search", params={"expand":"lead","startAt":start_at,"maxResults":max_results})
            for p in d.get("values",[]):
                if only_led_by:
                    if (p.get("lead") or {}).get("accountId")==only_led_by: out.append(p)
                else: out.append(p)
            if start_at+max_results>=d.get("total",0): break
            start_at+=max_results
        return out
    def search_issues(self, jql, fields, batch_size=100):
        start_at=0; out=[]
        while True:
            d=self._req("POST","/rest/api/3/search", data=json.dumps({"jql":jql,"startAt":start_at,"maxResults":batch_size,"fields":fields}))
            out.extend(d.get("issues",[])); 
            if start_at+batch_size>=d.get("total",0): break
            start_at+=batch_size
        return out
    def update_issue_labels(self, issue_key, new_labels):
        self._req("PUT", f"/rest/api/3/issue/{issue_key}", data=json.dumps({"fields":{"labels":new_labels}}))
    def add_worklog(self, issue_key, started_iso, seconds, comment_text):
        d=self._req("POST", f"/rest/api/3/issue/{issue_key}/worklog", data=json.dumps({"started":started_iso,"timeSpentSeconds":seconds,"comment":adf_comment(comment_text)}))
        return d.get("id")
    def list_worklogs(self, issue_key):
        out=[]; startAt=0; maxResults=100
        while True:
            d=self._req("GET", f"/rest/api/3/issue/{issue_key}/worklog", params={"startAt":startAt,"maxResults":maxResults})
            out.extend(d.get("worklogs",[]))
            if startAt+maxResults>=d.get("total",len(out)): break
            startAt+=maxResults
        return {"worklogs": out}
    def delete_worklog(self, issue_key, worklog_id):
        self._req("DELETE", f"/rest/api/3/issue/{issue_key}/worklog/{worklog_id}")
    def my_permissions(self):
        return self._req("GET", "/rest/api/3/mypermissions", params={"projectKey": ""})

    def list_status_names(self):
        d = self._req("GET", "/rest/api/3/status") or []
        return {s.get("name") for s in d if s.get("name")}

    def list_status_names_for_projects(self, project_keys):
        names=set()
        for k in project_keys:
            try:
                d=self._req("GET", f"/rest/api/3/project/{k}/statuses") or []
                for st in d:
                    for s in st.get("statuses", []):
                        n=s.get("name");
                        if n: names.add(n)
            except Exception:
                pass
        return names

    def list_status_names(self):
        d = self._req("GET", "/rest/api/3/status") or []
        return {s.get("name") for s in d if s.get("name")}

class JiraClientOAuth:
    AUTH_BASE = "https://auth.atlassian.com"
    API_BASE  = "https://api.atlassian.com"

    def __init__(self, cloud_id: str, site_url: str, access_token: str, refresh_token: str, expires_at: datetime, client_id: str, client_secret: str = ""):
        self.cloud_id=cloud_id; self.site_url=site_url
        self.access_token=access_token; self.refresh_token=refresh_token; self.expires_at=expires_at
        self.client_id=client_id; self.client_secret=client_secret
        self.timeout=30

    def _ensure_token(self):
        if datetime.now(timezone.utc) + timedelta(seconds=60) < self.expires_at:
            return
        data = {"grant_type":"refresh_token","client_id": self.client_id,"refresh_token": self.refresh_token}
        if self.client_secret: data["client_secret"] = self.client_secret
        r=requests.post(f"{self.AUTH_BASE}/oauth/token", json=data, timeout=30, headers={"Content-Type":"application/json"})
        if r.status_code>=400: raise JiraError(f"Token-Refresh fehlgeschlagen: {r.status_code} {r.text}")
        j=r.json()
        self.access_token=j["access_token"]; self.refresh_token=j.get("refresh_token", self.refresh_token)
        self.expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(j.get("expires_in", 3600)))

    def _req(self, method, path, params=None, data=None, retries=3):
        self._ensure_token()
        url=f"{self.API_BASE}/ex/jira/{self.cloud_id}{path}"
        headers={"Authorization": f"Bearer {self.access_token}", "Accept":"application/json","Content-Type":"application/json"}
        for attempt in range(retries):
            r=requests.request(method,url,params=params,data=data,headers=headers,timeout=self.timeout)
            if r.status_code in (429,502,503,504):
                time.sleep(1.5*(attempt+1)); continue
            if r.status_code==401 and attempt==0:
                self.expires_at = datetime.now(timezone.utc)  # force refresh
                self._ensure_token(); headers["Authorization"]=f"Bearer {self.access_token}"; continue
            if r.status_code>=400:
                try: detail=r.json()
                except Exception: detail=r.text
                raise JiraError(f"HTTP {r.status_code} für {path}: {detail}")
            try: return r.json()
            except Exception: return None
        raise JiraError(f"Failed after retries: {method} {path}")

    def get_myself(self):   return self._req("GET","/rest/api/3/myself")
    def list_projects(self, only_led_by: Optional[str] = None):
        start_at=0; max_results=50; out=[]
        while True:
            d=self._req("GET","/rest/api/3/project/search", params={"expand":"lead","startAt":start_at,"maxResults":max_results})
            for p in d.get("values",[]):
                if only_led_by:
                    if (p.get("lead") or {}).get("accountId")==only_led_by: out.append(p)
                else: out.append(p)
            if start_at+max_results>=d.get("total",0): break
            start_at+=max_results
        return out
    def search_issues(self, jql, fields, batch_size=100):
        start_at=0; out=[]
        while True:
            d=self._req("POST","/rest/api/3/search", data=json.dumps({"jql":jql,"startAt":start_at,"maxResults":batch_size,"fields":fields}))
            out.extend(d.get("issues",[])); 
            if start_at+batch_size>=d.get("total",0): break
            start_at+=batch_size  # paginator step fixed
        return out
    def update_issue_labels(self, issue_key, new_labels):
        self._req("PUT", f"/rest/api/3/issue/{issue_key}", data=json.dumps({"fields":{"labels":new_labels}}))
    def add_worklog(self, issue_key, started_iso, seconds, comment_text):
        d=self._req("POST", f"/rest/api/3/issue/{issue_key}/worklog", data=json.dumps({"started":started_iso,"timeSpentSeconds":seconds,"comment":adf_comment(comment_text)}))
        return d.get("id")
    def list_worklogs(self, issue_key):
        out=[]; startAt=0; maxResults=100
        while True:
            d=self._req("GET", f"/rest/api/3/issue/{issue_key}/worklog", params={"startAt":startAt,"maxResults":maxResults})
            out.extend(d.get("worklogs",[]))
            if startAt+maxResults>=d.get("total",len(out)): break
            startAt+=maxResults
        return {"worklogs": out}
    def delete_worklog(self, issue_key, worklog_id):
        self._req("DELETE", f"/rest/api/3/issue/{issue_key}/worklog/{worklog_id}")
    def my_permissions(self):
        return self._req("GET", "/rest/api/3/mypermissions", params={"projectKey": ""})

    def list_status_names(self):
        d = self._req("GET", "/rest/api/3/status") or []
        return {s.get("name") for s in d if s.get("name")}

    def list_status_names_for_projects(self, project_keys):
        names=set()
        for k in project_keys:
            try:
                d=self._req("GET", f"/rest/api/3/project/{k}/statuses") or []
                for st in d:
                    for s in st.get("statuses", []):
                        n=s.get("name");
                        if n: names.add(n)
            except Exception:
                pass
        return names

    def list_status_names(self):
        d = self._req("GET", "/rest/api/3/status") or []
        return {s.get("name") for s in d if s.get("name")}

# ----------------------------- Jira utilities -----------------------------
P_PATTERN = re.compile(r"^P\d{6}$")
def is_p_label(label: str) -> bool: return bool(P_PATTERN.match(label or ""))
def extract_p_label(labels: List[str]) -> Optional[str]:
    for l in labels or []:
        if is_p_label(l): return l
    return None
def to_started_iso(d: date, t: dtime) -> str:
    local_tz = datetime.now().astimezone().tzinfo
    return datetime.combine(d, t).replace(tzinfo=local_tz).strftime("%Y-%m-%dT%H:%M:%S.000%z")
def ensure_15min(seconds: int) -> bool: return seconds % 900 == 0 and seconds > 0
def adf_comment(text: str) -> Dict[str, Any]:
    txt=(text or "").strip() or "Zeiterfassung über Stichwort-Tool"
    return {"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":txt}]}]}
def fill_template(tpl: str, p: str, key: str, summary: str, d: date) -> str:
    if not tpl: return ""
    return tpl.replace("{P}", p or "").replace("{ISSUE}", key or "").replace("{SUMMARY}", summary or "").replace("{DATE}", d.isoformat())
def week_bounds_from(d: date) -> Tuple[date,date]:
    monday = d - timedelta(days=d.weekday())
    return monday, monday+timedelta(days=7)

# ----------------------------- PIN credentials helpers -----------------------------
def set_pin_credentials(email: str, base_url: str, api_token: str, account_id: str, pin: str):
    salt = os.urandom(16)
    f = fernet_from_pin(pin, salt)
    enc_token = f.encrypt(api_token.encode()).decode()
    with engine.begin() as con:
        con.execute(text("""
        INSERT INTO user_pin (email, salt, enc_token, jira_base_url, account_id, updated_at)
        VALUES (:email, :salt, :enc, :url, :acc, CURRENT_TIMESTAMP)
        ON CONFLICT (email) DO UPDATE SET
          salt = EXCLUDED.salt,
          enc_token = EXCLUDED.enc_token,
          jira_base_url = EXCLUDED.jira_base_url,
          account_id = EXCLUDED.account_id,
          updated_at = CURRENT_TIMESTAMP
        """), {"email": email, "salt": salt, "enc": enc_token, "url": base_url, "acc": account_id})

def load_pin_row(email: str):
    with engine.begin() as con:
        row = con.execute(text("""
        SELECT salt, enc_token, jira_base_url, account_id FROM user_pin WHERE email=:email
        """), {"email": email}).fetchone()
    return row

def delete_pin_row(email: str):
    with engine.begin() as con:
        con.execute(text("DELETE FROM user_pin WHERE email=:email"), {"email": email})

# ----------------------------- OAuth helpers -----------------------------
def pkce_pair() -> Tuple[str, str]:
    verifier = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge

def build_authorize_url(state: str, code_challenge: Optional[str]) -> str:
    q = {
        "audience": "api.atlassian.com",
        "client_id": ATL_CLIENT_ID,
        "scope": ATL_SCOPES,
        "redirect_uri": ATL_REDIRECT_URI,
        "state": state,
        "response_type": "code",
        "prompt": "consent",
    }
    if not ATL_CLIENT_SECRET:  # PKCE public client
        q["code_challenge"] = code_challenge or ""
        q["code_challenge_method"] = "S256"
    return "https://auth.atlassian.com/authorize?" + urllib.parse.urlencode(q)

def oauth_exchange_code(code: str, code_verifier: Optional[str]) -> Dict[str, Any]:
    data = {
        "grant_type": "authorization_code",
        "client_id": ATL_CLIENT_ID,
        "code": code,
        "redirect_uri": ATL_REDIRECT_URI,
    }
    if ATL_CLIENT_SECRET:
        data["client_secret"] = ATL_CLIENT_SECRET
    else:
        data["code_verifier"] = code_verifier or ""
    r=requests.post("https://auth.atlassian.com/oauth/token", json=data, headers={"Content-Type":"application/json"}, timeout=30)
    if r.status_code>=400:
        raise JiraError(f"Token-Austausch fehlgeschlagen: {r.status_code} {r.text}")
    return r.json()

def oauth_accessible_resources(access_token: str) -> list:
    r=requests.get("https://api.atlassian.com/oauth/token/accessible-resources", headers={"Authorization": f"Bearer {access_token}"}, timeout=30)
    if r.status_code>=400:
        raise JiraError(f"accessible-resources fehlgeschlagen: {r.status_code} {r.text}")
    return r.json()

def save_oauth_tokens(email: str, account_id: str, cloud_id: str, site_url: str, access_token: str, refresh_token: str, expires_in: int):
    with engine.begin() as con:
        con.execute(text("""
        INSERT INTO user_oauth (email, atlassian_account_id, cloud_id, site_url, access_token, refresh_token, expires_at, updated_at)
        VALUES (:email,:acc,:cid,:url,:at,:rt,:exp,CURRENT_TIMESTAMP)
        ON CONFLICT (email) DO UPDATE SET
          atlassian_account_id = EXCLUDED.atlassian_account_id,
          cloud_id = EXCLUDED.cloud_id,
          site_url = EXCLUDED.site_url,
          access_token = EXCLUDED.access_token,
          refresh_token = EXCLUDED.refresh_token,
          expires_at = EXCLUDED.expires_at,
          updated_at = CURRENT_TIMESTAMP
        """), {
            "email": email, "acc": account_id, "cid": cloud_id, "url": site_url,
            "at": access_token, "rt": refresh_token, "exp": datetime.now(timezone.utc) + timedelta(seconds=int(expires_in or 3600))
        })

def load_oauth_row(email: str):
    with engine.begin() as con:
        row = con.execute(text("""
        SELECT atlassian_account_id, cloud_id, site_url, access_token, refresh_token, expires_at
        FROM user_oauth WHERE email=:email
        """), {"email": email}).fetchone()
    return row

def delete_oauth_row(email: str):
    with engine.begin() as con:
        con.execute(text("DELETE FROM user_oauth WHERE email=:email"), {"email": email})

# robust query param reader
def _qp(key, default=None):
    try:
        v = st.query_params.get(key)
        if isinstance(v, list):
            return v[0] if v else default
        return v if v is not None else default
    except Exception:
        v = dict(st.query_params).get(key)
        return v[0] if v else default

# ----------------------------- UI State -----------------------------
st.title("Jira Stichwort-Zuordnung — PRO v6.2 (SSO + PIN)")
st.caption("Hauptfokus: P‑Labels einfach & sicher zuweisen — mit Vorschau und Bestätigung.")

for k in ["jira","myself","site_url","sidebar_collapsed","timesheet","undo","projects_cache","own_only_prev","pl_preview","csv_preview","reports"]: 
    st.session_state.setdefault(k, None)

# ----------------------------- Login Modes -----------------------------
login_mode = st.sidebar.radio("Login-Variante", ["Jira SSO", "Schnell-Login (E-Mail + PIN)", "Erstkonfiguration / Token ändern"], index=0)

# --- Jira SSO ---
if login_mode == "Jira SSO":
    st.sidebar.subheader("Jira Single Sign-On")
    if not ATL_CLIENT_ID or not ATL_REDIRECT_URI:
        st.sidebar.warning("SSO ist noch nicht konfiguriert. Bitte Secrets setzen: ATLASSIAN_CLIENT_ID, ATLASSIAN_REDIRECT_URI (und optional ATLASSIAN_CLIENT_SECRET).")
    else:
        code  = _qp("code"); state=_qp("state")
        if code and state:
            try:
                verifier_from_state = None
                if not ATL_CLIENT_SECRET:
                    try:
                        payload = global_cipher.decrypt(base64.urlsafe_b64decode(state)).decode()
                        verifier_from_state = json.loads(payload).get("v")
                    except Exception:
                        verifier_from_state = None
                j = oauth_exchange_code(code, verifier_from_state)
                access_token=j["access_token"]; refresh_token=j.get("refresh_token"); expires_in=int(j.get("expires_in",3600))
                resources=oauth_accessible_resources(access_token)
                if not resources: st.sidebar.error("Kein Jira-Workspace gefunden.")
                else:
                    opts = [f'{r.get("name")} — {r.get("url")} ({r.get("id")})' for r in resources]
                    chosen = st.sidebar.selectbox("Workspace wählen", opts, index=0, key="sso_site_select")
                    res = resources[opts.index(chosen)]
                    cloud_id = res.get("id"); site_url = res.get("url")
                    headers={"Authorization": f"Bearer {access_token}"}
                    r_me = requests.get(f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/myself", headers=headers, timeout=30)
                    if r_me.status_code>=400:
                        st.sidebar.error(f"/myself fehlgeschlagen: {r_me.status_code} {r_me.text}")
                    else:
                        me = r_me.json(); email = me.get("emailAddress","") or st.text_input("E-Mail (für Profil-Speicherung)", value="", key="sso_email_fallback")
                        save_oauth_tokens(email or "sso-user", me.get("accountId",""), cloud_id, site_url, access_token, refresh_token, expires_in)
                        client = JiraClientOAuth(cloud_id, site_url, access_token, refresh_token, datetime.now(timezone.utc)+timedelta(seconds=expires_in), ATL_CLIENT_ID, ATL_CLIENT_SECRET or "")
                        st.session_state.jira=client; st.session_state.myself=me; st.session_state.site_url=site_url
                        st.session_state.sidebar_collapsed=True
                        try: st.query_params.clear()
                        except Exception: st.experimental_set_query_params()
                        st.sidebar.success(f"Verbunden als: {me.get('displayName')}")
            except Exception as e:
                st.sidebar.error(f"SSO Fehler: {e}")
        if st.session_state.get("jira") is None:
            colA, colB = st.sidebar.columns([1,1])
            if colA.button("Mit Jira anmelden", key="btn_sso"):
                if ATL_CLIENT_SECRET:
                    state_payload = json.dumps({"ts": int(time.time())})
                    state = base64.urlsafe_b64encode(global_cipher.encrypt(state_payload.encode())).decode()
                    verifier, challenge = None, None
                else:
                    verifier, challenge = pkce_pair()
                    payload = json.dumps({"v": verifier, "ts": int(time.time())})
                    state = base64.urlsafe_b64encode(global_cipher.encrypt(payload.encode())).decode()
                url = build_authorize_url(state, challenge)
                components.html(f'<script>window.top.location.href="{url}";</script>', height=0)
                st.link_button("Falls keine Weiterleitung startet: Hier klicken", url, type="primary")
            if colB.button("Abmelden (SSO)", key="btn_sso_logout"):
                for k in ["jira","myself","site_url","projects_cache","own_only_prev"]:
                    st.session_state[k]=None
                st.sidebar.success("Abgemeldet.")

# --- PIN Schnell-Login ---
if login_mode == "Schnell-Login (E-Mail + PIN)":
    st.sidebar.subheader("Schnell-Login")
    email = st.sidebar.text_input("E-Mail", value="", key="pin_email")
    pin   = st.sidebar.text_input("PIN (6+ Zeichen empfohlen)", type="password", key="pin_login")
    colL, colR = st.sidebar.columns(2)
    if colL.button("Verbinden", key="btn_login"):
        row = load_pin_row(email)
        if not row: st.sidebar.error("Kein Datensatz für diese E-Mail. Bitte zuerst unter 'Erstkonfiguration' einrichten.")
        else:
            salt, enc_token, base_url, account_id = row
            try:
                f = fernet_from_pin(pin, salt); api_token = f.decrypt(enc_token.encode()).decode()
                @st.cache_resource(ttl=3600)
def get_jira(base_url, email, api_token):
    return JiraClientBasic(base_url, email, api_token)

jira = get_jira(base_url, email, api_token); me = jira.get_myself()
                st.session_state.jira, st.session_state.myself, st.session_state.site_url = jira, me, base_url
                st.session_state.sidebar_collapsed=True; st.sidebar.success(f"Verbunden als: {me.get('displayName')}")
            except Exception as e: st.sidebar.error(f"PIN oder Daten ungültig: {e}")
    if colR.button("Logout", key="btn_logout"):
        for k in ["jira","myself","site_url","projects_cache","own_only_prev"]:
            st.session_state[k]=None
        st.sidebar.success("Abgemeldet.")

# --- PIN Erstkonfiguration ---
if login_mode == "Erstkonfiguration / Token ändern":
    st.sidebar.subheader("Erstkonfiguration / Token ändern")
    email    = st.sidebar.text_input("E-Mail", value="", key="setup_email")
    base_url = st.sidebar.text_input("Jira Base-URL", value="", key="setup_url")
    api_tok  = st.sidebar.text_input("API Token", type="password", key="setup_token")
    pin1     = st.sidebar.text_input("PIN neu", type="password", key="setup_pin1")
    pin2     = st.sidebar.text_input("PIN bestätigen", type="password", key="setup_pin2")
    colS1, colS2 = st.sidebar.columns(2)
    if colS1.button("Speichern / Aktualisieren", key="btn_save"):
        if pin1 != pin2 or not pin1: st.sidebar.error("PINs stimmen nicht überein oder leer.")
        else:
            try:
                test = JiraClientBasic(base_url, email, api_tok).get_myself()
                account_id = test.get("accountId","")
                set_pin_credentials(email, base_url, api_tok, account_id, pin1)
                st.sidebar.success("Gespeichert. Du kannst nun mit E-Mail+PIN einloggen.")
            except Exception as e: st.sidebar.error(f"Konnte nicht speichern: {e}")
    if colS2.button("Datensatz löschen", key="btn_del"):
        try: delete_pin_row(st.session_state.get("setup_email","")); st.sidebar.success("Datensatz gelöscht.")
        except Exception as e: st.sidebar.error(f"Konnte nicht löschen: {e}")

# --- Stop, wenn keine Verbindung vorhanden ---
if not st.session_state.get("jira"):
    st.stop()

# Sidebar einklappen
def hide_sidebar_css():
    st.markdown("""<style>[data-testid="stSidebar"]{display:none!important}.block-container{padding-top:1rem}</style>""", unsafe_allow_html=True)
if st.session_state.get("sidebar_collapsed", False):
    hide_sidebar_css()
    if st.button("⚙️ Einstellungen anzeigen"): st.session_state.sidebar_collapsed=False
else:
    st.sidebar.button("↩︎ Sidebar einklappen", on_click=lambda: st.session_state.update({"sidebar_collapsed": True}))

jira=st.session_state.jira; me=st.session_state.myself; site_url=st.session_state.site_url

# ----------------------------- Projekte & Daten -----------------------------
def _invalidate_projects():
    st.session_state.projects_cache=None

own_only = st.toggle("Nur Projekte, bei denen ich Lead bin", value=bool(st.session_state.get("own_only_prev") or False), key="own_only_toggle", on_change=_invalidate_projects)
if st.session_state.own_only_prev is None or st.session_state.own_only_prev != own_only:
    st.session_state.projects_cache=None
st.session_state.own_only_prev = own_only

with st.spinner("Lade Projekte…"):
    if not st.session_state.get("projects_cache"):
        projs = jira.list_projects(me.get("accountId") if own_only else None)
        if own_only and not projs:
            st.info("Keine Projekte mit dir als Lead gefunden – zeige alle Projekte.")
            projs = jira.list_projects(None)
        st.session_state.projects_cache = sorted(projs, key=lambda p: p.get("key",""))

projects = st.session_state.projects_cache or []
proj_labels=[f"{p.get('key')} — {p.get('name')}" for p in projects]
proj_key_by_label={f"{p.get('key')} — {p.get('name')}": p.get("key") for p in projects}

st.toggle("Multi-Projekt-Modus", value=False, key="multi_proj", help="Mehrere Projekte gleichzeitig anzeigen/bearbeiten")
if st.session_state.multi_proj and projects:
    selected_labels = st.multiselect("Projekte auswählen", proj_labels, default=proj_labels[:1], key="proj_multi")
    selected_keys = [proj_key_by_label[l] for l in selected_labels]
else:
    selected_label = st.selectbox("Projekt auswählen", proj_labels, index=0 if proj_labels else None, key="proj_single")
    selected_keys = [proj_key_by_label[selected_label]] if proj_labels else []

st.markdown("—")

@st.cache_data(ttl=120, show_spinner=False)


# ---- Chunked label updater to be gentle on API limits ----
def apply_labels_chunked(jira, rows, *, chunk_size: int = 25, delay_sec: float = 0.1):
    """rows: list of dicts with keys 'Key', 'Neu', 'Alt' (strings with comma-separated labels)."""
    errs = []
    prev_state = {}
    total = max(len(rows), 1)
    prog = st.progress(0, text="Änderungen werden angewendet…")
    for i, row in enumerate(rows, start=1):
        k = row.get('Key')
        old = [x.strip() for x in (row.get('Alt') or '').split(',') if x.strip()]
        new = [x.strip() for x in (row.get('Neu') or '').split(',') if x.strip()]
        prev_state[k] = old
        try:
            jira.update_issue_labels(k, new)
        except Exception as e:
            errs.append(f"{k}: {e}")
        if i % chunk_size == 0:
            time.sleep(delay_sec)
        prog.progress(i/total, text=f"{i}/{total} aktualisiert…")
    prog.empty()
    return prev_state, errs
def fetch_issues_df(_jira_client, project_keys: List[str], site_url: str) -> pd.DataFrame:
    if isinstance(project_keys, str): project_keys=[project_keys]
    if not project_keys: 
        return pd.DataFrame(columns=["Project","Key","Ticket","Summary","Status","P_Label_Aktuell","Alle_Labels"])
    quoted = ",".join([f'"{k}"' for k in project_keys])
    # v6.3j: Exklusion pro Projekt (Team‑/Company‑managed) + Resolution "Abgebrochen"
    desired = ["Closed","Geschlossen","Abgebrochen"]
    try:
        names = _jira_client.list_status_names_for_projects(project_keys)
        if not names:
            names = _jira_client.list_status_names()
    except Exception:
        names = set()
    excludes = [s for s in desired if s in names]
    base_clause = f'project in ({quoted})'
    if excludes:
        not_in = ",".join([f'"{s}"' for s in excludes])
        jql = f'{base_clause} AND status not in ({not_in}) ORDER BY created DESC'
    else:
        jql = f'{base_clause} ORDER BY created DESC'
    fields = ["summary","status","labels","project","resolution"]
    issues = _jira_client.search_issues(jql, fields)
    rows=[]
    for it in issues:
        k=it.get("key"); f=it.get("fields",{})
        proj=(f.get("project") or {}).get("key","")
        summary=f.get("summary","")
        status=(f.get("status") or {}).get("name","")
        resolution=(f.get("resolution") or {}).get("name","")
        # Client-side safety filter
        if status in {"Abgebrochen","Geschlossen","Closed"}: continue
        labels = f.get("labels") or []
        p_label=extract_p_label(labels); link=f"{site_url}/browse/{k}" if site_url else ""
        rows.append({"Project":proj,"Key":k,"Ticket":link,"Summary":summary,"Status":status,"P_Label_Aktuell":p_label or "", "Alle_Labels":", ".join(labels) if labels else ""})
    return pd.DataFrame(rows)

def refresh_after_update():
    try:
        fetch_issues_df.clear()
    except Exception:
        pass
    st.rerun()

df = fetch_issues_df(jira, selected_keys, site_url)

# ----------------------------- Tabs -------------------------------
tab_overview, tab_plabel, tab_worklog, tab_csv, tab_reports, tab_timesheet, tab_health = st.tabs(
    ["📋 Übersicht","🏷️ P-Labels","⏱️ Worklog (Einzeln)","📥 CSV-Import","📊 Reports & Export","🗓️ Timesheet","🩺 Health-Check+"]
)

# ----------------------------- Übersicht --------------------------
with tab_overview:
    st.subheader("Übersicht & Filter")
    colf1,colf2,colf3,colf4=st.columns([2,1,1,1])
    q=colf1.text_input("Suche (Key/Summary)", "", key="ov_q")
    status_vals=sorted(df["Status"].unique().tolist()) if not df.empty else []
    chosen_status=colf2.multiselect("Status-Filter", status_vals, default=[], key="ov_status")
    only_missing=colf3.toggle("Nur ohne P-Label", value=False, key="ov_only_missing")
    proj_filter=colf4.multiselect("Projektfilter", sorted(df["Project"].unique().tolist()), default=sorted(df["Project"].unique().tolist()), key="ov_proj_filter")

    df_view=df.copy()
    if q:
        ql=q.lower(); df_view=df_view[df_view["Summary"].str.lower().str.contains(ql)|df_view["Key"].str.lower().str.contains(ql)]
    if chosen_status: df_view=df_view[df_view["Status"].isin(chosen_status)]
    if only_missing: df_view=df_view[df_view["P_Label_Aktuell"]==""]
    if proj_filter: df_view=df_view[df_view["Project"].isin(proj_filter)]

    c1,c2,c3,c4=st.columns([1,1,1,2])
    c1.metric("Tickets", len(df_view))
    c2.metric("Mit P-Label", int((df_view["P_Label_Aktuell"]!="").sum()) if not df_view.empty else 0)
    c3.metric("Ohne P-Label", int((df_view["P_Label_Aktuell"]=="").sum()) if not df_view.empty else 0)
    existing_ps=[x for x in df_view["P_Label_Aktuell"].tolist() if x]
    from collections import Counter
    suggested_p=Counter(existing_ps).most_common(1)[0][0] if existing_ps else ""
    c4.write("Empf. Projektnummer: " + (f"`{suggested_p}`" if suggested_p else "—"))

    st.dataframe(df_view, use_container_width=True, hide_index=True, column_config={
        "Ticket": st.column_config.LinkColumn("Ticket öffnen", display_text="Open"),
        "Project": st.column_config.TextColumn("Projekt"),
        "Key": st.column_config.TextColumn("Key"),
        "Summary": st.column_config.TextColumn("Summary"),
        "Status": st.column_config.TextColumn("Status"),
        "P_Label_Aktuell": st.column_config.TextColumn("P-Label"),
        "Alle_Labels": st.column_config.TextColumn("Alle Labels"),
    })
    # Schnellaktionen — ENTFERNT in v6.2

# ----------------------------- P-Labels (Hauptbereich) ------------

with tab_plabel:
    with st.form('plabel_form'):

    st.subheader("P‑Labels zuweisen")
    st.caption("Wähle Tickets in der Tabelle aus **oder** nutze 'Alle in aktueller Ansicht'. Änderungen werden zuerst als Vorschau gezeigt.")

    # Tabelle mit Auswahlspalte
    df_scope = df if st.session_state.multi_proj else (df[df["Project"]==selected_keys[0]] if selected_keys else df)
    table = df_scope[["Project","Key","Summary","Status","P_Label_Aktuell","Alle_Labels"]].copy()
    table.insert(0, "Auswählen", False)

    # Zusatz: Schnell-Selektor
    colsel1, colsel2 = st.columns([1,1])
    if colsel1.button("Alle ohne P‑Label auswählen", key="pl_select_missing"):
        st.session_state["pl_preselect"] = "missing"
    if colsel2.button("Auswahl leeren", key="pl_select_clear"):
        st.session_state["pl_preselect"] = "none"

    pre = st.session_state.get("pl_preselect")
    if pre == "missing":
        try:
            table.loc[table["P_Label_Aktuell"]=="", "Auswählen"] = True
        except Exception:
            pass
    elif pre == "none":
        table["Auswählen"] = False
    if pre:
        st.session_state["pl_preselect"] = None

    edited = st.data_editor(
        table,
        use_container_width=True,
        hide_index=True,
        num_rows="fixed",
        column_config={
            "Auswählen": st.column_config.CheckboxColumn(help="Ticket in Aktion einschließen"),
            "P_Label_Aktuell": st.column_config.TextColumn("P‑Label"),
        },
        key="pl_editor")

    selection_keys = edited.loc[edited["Auswählen"]==True, "Key"].tolist()
    colp1, colp2 = st.columns([2,1])
    p_number = colp1.text_input("Projektnummer (PXXXXXX)", value="", key="pl_p_number")
    mode_all = colp2.toggle("Alle in aktueller Ansicht verwenden", value=False, key="pl_all_mode")

    if st.button("Änderungen prüfen", key="pl_preview_btn"):
        target = df_scope["Key"].tolist() if mode_all else selection_keys
        if not target:
            st.warning("Keine Tickets ausgewählt.")
        elif not (p_number and P_PATTERN.match(p_number)):
            st.error("Ungültige Projektnummer. Format: PXXXXXX (6 Ziffern).")
        else:
            rows = []
            for k in target:
                r = df_scope.loc[df_scope["Key"]==k].iloc[0]
                old = [l.strip() for l in (r["Alle_Labels"].split(",") if r["Alle_Labels"] else []) if l.strip()]
                base = [l for l in old if not is_p_label(l)]
                new = base + [p_number]
                changed = set(old) != set(new)
                rows.append({"Key":k,"Alt":", ".join(old),"Neu":", ".join(new),"Ändert sich?":"Ja" if changed else "Nein"})
            st.session_state.pl_preview = {"p": p_number, "rows": rows}
            st.success("Vorschau erstellt. Bitte prüfen und anschließend bestätigen.")

    if st.session_state.pl_preview:
        st.markdown("#### Vorschau: P‑Label‑Änderungen")
        df_prev = pd.DataFrame(st.session_state.pl_preview["rows"])
        st.dataframe(df_prev, use_container_width=True, hide_index=True)
        cprev1, cprev2 = st.columns([1,1])
        if cprev1.button("✅ Bestätigen & Anwenden", key="pl_apply"):
            p_val = st.session_state.pl_preview["p"]; prev_state = {}; errs = []
            for row in st.session_state.pl_preview["rows"]:
                k = row["Key"]
                old = [x.strip() for x in row["Alt"].split(",")] if row["Alt"] else []
                prev_state[k] = old
                new = [x.strip() for x in row["Neu"].split(",")] if row["Neu"] else []
                try:
                    jira.update_issue_labels(k, new)
                except Exception as e:
                    errs.append(f"{k}: {e}")
            st.session_state.undo = {"type":"labels","data":prev_state}
            st.session_state.pl_preview = None
            if errs:
                st.error("Einige Tickets konnten nicht aktualisiert werden:\n- " + "\n- ".join(errs))
            else:
                st.success(f"P‑Label `{p_val}` angewandt.")
            refresh_after_update()
        if cprev2.button("Abbrechen", key="pl_cancel"):
            st.session_state.pl_preview = None
            st.info("Vorschau verworfen.")

        st.form_submit_button('Änderungen übernehmen')

with tab_worklog:
    st.subheader("Worklog (Einzel)")
    csel1,csel2=st.columns([2,1])
    issue_choice=csel1.selectbox("Ticket (aus Liste)", df["Key"].tolist() if not df.empty else [], key="wl_key_select")
    issue_direct=csel2.text_input("Oder Key direkt (z.B. PROJ-123)", value="", key="wl_key_direct")
    use_key=issue_direct.strip() or issue_choice

    c1,c2=st.columns(2)
    work_date=c1.date_input("Datum", value=datetime.now().date(), key="wl_date")
    start_time=c2.time_input("Startzeit", value=datetime.now().time().replace(second=0, microsecond=0), key="wl_start_time")
    cc1,cc2=st.columns([1,1])
    hours=cc1.number_input("Stunden", min_value=0, max_value=24, step=1, value=0, key="wl_hours")
    minutes=cc2.selectbox("Minuten", [0,15,30,45], index=1, key="wl_minutes")

    desc=st.text_area("Tätigkeitsbeschreibung", value="", placeholder="Was wurde gemacht?", key="wl_desc")
    if st.button("Zeit erfassen", key="wl_submit"):
        seconds=int(hours)*3600 + int(minutes)*60
        if seconds<=0 or seconds%900!=0: st.error("Dauer muss Vielfaches von 15min sein und >0.")
        elif not use_key: st.error("Ticket-Key angeben.")
        else:
            try:
                wid=jira.add_worklog(use_key, to_started_iso(work_date, start_time), seconds, desc)
                st.session_state.undo={"type":"worklogs","data":[(use_key,wid)]}; st.success(f"Worklog für {use_key} erfasst.")
            except Exception as e: st.error(f"Fehler: {e}")

# ----------------------------- CSV Import --------------------------
with tab_csv:
    st.subheader("CSV-Import Zeiterfassung")
    st.caption("Spalten: **Ticketnummer;Datum;benötigte Zeit in h** | optional: **Uhrzeit, Beschreibung** | Dezimal: `.` oder `,`")
    sample="Ticketnummer;Datum;benötigte Zeit in h;Uhrzeit;Beschreibung\nPROJ-101;21.08.2025;0,25;12:30;Daily Standup\nPROJ-202;21.08.2025;1.5;09:00;Konzept & Abstimmung\n"
    st.download_button("Beispiel-CSV herunterladen", data=sample.encode("utf-8"), file_name="worklog_beispiel.csv", mime="text/csv", key="csv_sample")
    default_desc=st.text_input("Standardbeschreibung (optional, wenn CSV keine Spalte 'Beschreibung' enthält)", key="csv_default_desc")
    uploaded=st.file_uploader("CSV hochladen", type=["csv"], key="csv_upload")

    if uploaded is not None:
        content=uploaded.read().decode("utf-8-sig")
        try: df_csv=pd.read_csv(io.StringIO(content), sep=None, engine="python")
        except Exception: df_csv=pd.read_csv(io.StringIO(content), sep=";")
        cols={c.lower().strip(): c for c in df_csv.columns}
        def find_col(*names):
            for n in names:
                if n in cols: return cols[n]
            return None
        col_ticket=find_col("ticketnummer","ticket","issue","key")
        col_date=find_col("datum","date")
        col_hours=find_col("benötigte zeit in h","benoetigte zeit in h","hours","dauer(h)","zeit(h)")
        col_time=find_col("uhrzeit","zeit","startzeit")
        col_desc=find_col("beschreibung","description","kommentar")

        if not (col_ticket and col_date and col_hours):
            st.error("Pflichtspalten fehlen. Erwartet: Ticketnummer; Datum; benötigte Zeit in h")
        else:
            preview_rows=[]; errors=[]
            for idx,r in df_csv.iterrows():
                key=str(r[col_ticket]).strip()
                try: d=pd.to_datetime(str(r[col_date]), dayfirst=True).date()
                except Exception: errors.append(f"Zeile {idx+1}: Ungültiges Datum '{r[col_date]}'"); continue
                raw_hours=str(r[col_hours]).replace(",", ".").strip()
                try: h_float=float(raw_hours)
                except Exception: errors.append(f"{key}: Ungültige Stunden '{raw_hours}'"); continue
                seconds=int(round(h_float*3600))
                if seconds%900!=0 or seconds<=0: errors.append(f"{key}: {h_float}h ist kein Vielfaches von 15 min (>0)"); continue
                if col_time and not pd.isna(r[col_time]):
                    try: parsed_time=pd.to_datetime(str(r[col_time])).time()
                    except Exception: parsed_time=dtime(12,0)
                else: parsed_time=dtime(12,0)
                desc_val=""
                if col_desc and not pd.isna(r[col_desc]): desc_val=str(r[col_desc]).strip()
                elif default_desc: desc_val=default_desc
                preview_rows.append({"Ticket":key,"Datum":d.isoformat(),"Startzeit":parsed_time.strftime("%H:%M"),"Dauer (min)":seconds//60,"Beschreibung":desc_val or "(leer)"})
            st.session_state.csv_preview={"rows": preview_rows, "errors": errors}

    if st.session_state.csv_preview:
        st.markdown("#### Vorschau CSV-Import")
        rows=st.session_state.csv_preview["rows"]; errs=st.session_state.csv_preview["errors"]
        df_prev=pd.DataFrame(rows)
        st.dataframe(df_prev, use_container_width=True, hide_index=True)
        if errs:
            with st.expander("Fehler in CSV"):
                for e in errs: st.write("• " + e)
        cimp1,cimp2=st.columns([1,1])
        if cimp1.button("✅ Import bestätigen", key="csv_apply"):
            if not rows:
                st.warning("Keine gültigen Zeilen vorhanden.")
            else:
                ok=0; err_list=[]; created=[]; prog=st.progress(0.0, text="Übertrage…")
                for i,row in enumerate(rows, start=1):
                    try:
                        started_iso=to_started_iso(pd.to_datetime(row["Datum"]).date(), datetime.strptime(row["Startzeit"], "%H:%M").time())
                        wid=jira.add_worklog(row["Ticket"], started_iso, int(row["Dauer (min)"])*60, None if row["Beschreibung"]=="(leer)" else row["Beschreibung"])
                        created.append((row["Ticket"],wid)); ok+=1
                    except Exception as e: err_list.append(f"{row['Ticket']}: {e}")
                    prog.progress(i/max(len(rows),1), text=f"Übertrage… ({i}/{len(rows)})")
                prog.empty(); st.success(f"Import: {ok}/{len(rows)} Worklogs erstellt.")
                if err_list:
                    with st.expander("Fehlerdetails"):
                        for e in err_list: st.write(e)
                if created: st.session_state.undo={"type":"worklogs","data":created}
            st.session_state.csv_preview=None
        if cimp2.button("Abbrechen", key="csv_cancel"):
            st.session_state.csv_preview=None
            st.info("Vorschau verworfen.")

# ----------------------------- Reports -----------------------------
with tab_reports:
    st.subheader("Aufwände nach Kunde (P‑Label)")
    today=datetime.now().date()
    colr0,colr1,colr2,colr3=st.columns([1.5,1.3,1.3,1])
    start_d=colr0.date_input("Von", value=today - timedelta(days=30), key="rep_from")
    end_d  =colr1.date_input("Bis (inkl.)", value=today, key="rep_to")
    mine_only=colr2.toggle("Nur eigene Worklogs", value=True, key="rep_mine")
    if colr3.button("Aufwände laden", key="rep_load"):
        keys=df["Key"].tolist(); logs=[]; errs=[]; total=0; prog=st.progress(0.0, text="Lade Worklogs…")
        for i,k in enumerate(keys, start=1):
            try:
                wl=jira.list_worklogs(k) or {}
                # finde P‑Label des Tickets
                p_val = df.loc[df["Key"]==k,"P_Label_Aktuell"].iloc[0] if not df.empty else ""
                p_val = p_val or "(kein P)"
                for w in wl.get("worklogs", []):
                    started=pd.to_datetime(w.get("started"))
                    if started.tzinfo is None: started=started.tz_localize("UTC").astimezone()
                    d0=started.date()
                    if start_d <= d0 <= end_d:
                        author=(w.get("author") or {}).get("accountId","")
                        if (not mine_only) or (author==me.get("accountId")):
                            mins=int(w.get("timeSpentSeconds",0))//60
                            total+=mins
                            logs.append({"P":p_val,"Ticket":k,"Date":d0,"Minutes":mins})
            except Exception as e: errs.append(f"{k}: {e}")
            prog.progress(i/max(len(keys),1), text=f"Lade Worklogs… ({i}/{len(keys)})")
        prog.empty()
        st.session_state.reports={"logs":logs,"errors":errs,"start":start_d.isoformat(),"end":end_d.isoformat(),"mine":mine_only}

    rep=st.session_state.get("reports")
    if rep and rep.get("start")==start_d.isoformat() and rep.get("end")==end_d.isoformat() and rep.get("mine")==mine_only:
        logs,errs=rep["logs"],rep["errors"]
        if errs:
            with st.expander("Fehler beim Laden"):
                for e in errs: st.write(e)
        if logs:
            df_rep=pd.DataFrame(logs)
            agg=df_rep.groupby("P", as_index=False)["Minutes"].sum().sort_values("Minutes", ascending=False)
            st.dataframe(agg.rename(columns={"Minutes":"Minuten gesamt"}), use_container_width=True, hide_index=True)
            # Pie Chart
            fig, ax = plt.subplots()
            ax.pie(agg["Minutes"], labels=agg["P"], autopct=lambda p: f"{p:.1f}%")
            ax.set_title("Verteilung Aufwände (Minuten) nach P‑Label")
            st.pyplot(fig, use_container_width=True)
        else:
            st.info("Keine Worklogs im Zeitraum gefunden.")

    
    st.markdown("---")
    st.subheader("Eigene Zeiterfassungen (global, ohne Projektauswahl)")
    today=datetime.now().date()
    colg0,colg1=st.columns([1.5,1])
    g_start=colg0.date_input("Von", value=today - timedelta(days=30), key="g_from")
    g_end  =colg1.date_input("Bis (inkl.)", value=today, key="g_to")

    if st.button("Alle eigenen Worklogs laden", key="g_load"):
        jql=f'worklogAuthor = currentUser() AND worklogDate >= "{g_start.strftime("%Y/%m/%d")}" AND worklogDate <= "{g_end.strftime("%Y/%m/%d")}" ORDER BY updated DESC'
        fields=["summary","labels","project","status"]
        issues = jira.search_issues(jql, fields, batch_size=100)
        logs=[]; errs=[]; prog=st.progress(0.0, text="Lade eigene Worklogs…")
        for i,it in enumerate(issues, start=1):
            k=it.get("key"); f=it.get("fields",{})
            labels = f.get("labels") or []; p_val=extract_p_label(labels) or "(kein P)"
            try:
                wl=jira.list_worklogs(k) or {}
                for w in wl.get("worklogs", []):
                    try: started=pd.to_datetime(w.get("started"))
                    except Exception: continue
                    if started.tzinfo is None: started=started.tz_localize("UTC").astimezone()
                    d0=started.date()
                    if g_start <= d0 <= g_end:
                        if (w.get("author") or {}).get("accountId","") == (me or {}).get("accountId",""):
                            mins=int(w.get("timeSpentSeconds",0))//60
                            logs.append({"P":p_val,"Ticket":k,"Date":d0,"Minutes":mins})
            except Exception as e:
                errs.append(f"{k}: {e}")
            prog.progress(i/max(len(issues),1), text=f"Lade eigene Worklogs… ({i}/{len(issues)})")
        prog.empty()
        st.session_state.reports_global={"logs":logs,"errors":errs,"start":g_start.isoformat(),"end":g_end.isoformat()}

    repg=st.session_state.get("reports_global")
    if repg and repg.get("start")==g_start.isoformat() and repg.get("end")==g_end.isoformat():
        logs,errs=repg["logs"], repg["errors"]
        if errs:
            with st.expander("Fehler beim Laden (global)"):
                for e in errs: st.write(e)
        if logs:
            df_rep=pd.DataFrame(logs)
            agg=df_rep.groupby("P", as_index=False)["Minutes"].sum().sort_values("Minutes", ascending=False)
            st.dataframe(agg.rename(columns={"Minutes":"Minuten gesamt"}), use_container_width=True, hide_index=True)
            fig, ax = plt.subplots()
            ax.pie(agg["Minutes"], labels=agg["P"], autopct=lambda p: f"{p:.1f}%")
            ax.set_title("Verteilung Aufwände (Minuten) nach P‑Label — Eigene global")
            st.pyplot(fig, use_container_width=True)
            st.download_button("CSV (eigene Worklogs, global)", data=df_rep.to_csv(index=False).encode("utf-8"), file_name=f"worklogs_eigene_{g_start.isoformat()}_{g_end.isoformat()}.csv", mime="text/csv", key="g_csv")
        else:
            st.info("Keine eigenen Worklogs im Zeitraum gefunden.")

    st.markdown("---")
    st.subheader("Export Übersicht")
    st.download_button("CSV herunterladen (Tickets)", data=df.to_csv(index=False).encode("utf-8"), file_name="tickets_uebersicht.csv", mime="text/csv", key="rep_csv")

# ----------------------------- Timesheet --------------------------
with tab_timesheet:
    st.subheader("Wochenansicht / Timesheet")
    today=datetime.now().date()
    colts1,colts2,colts3,colts4=st.columns([2,1,1,2])
    wk_date=colts1.date_input("Woche auswählen (beliebiges Datum der Woche)", value=today, key="ts_date")
    if colts2.button("‹ Vorwoche", key="ts_prev"): st.session_state.ts_date=wk_date - timedelta(days=7)
    if colts3.button("Nächste Woche ›", key="ts_next"): st.session_state.ts_date=wk_date + timedelta(days=7)
    mine_only=colts4.toggle("Nur eigene Worklogs", value=True, key="ts_mine")

    def week_bounds_from(d: date) -> Tuple[date,date]:
        monday = d - timedelta(days=d.weekday())
        return monday, monday+timedelta(days=7)
    week_start,_=week_bounds_from(wk_date); days=[week_start+timedelta(days=i) for i in range(7)]
    day_cols=[d.strftime("%a\n%d.%m") for d in days]; st.caption(f"Kalenderwoche: {week_start.isoformat()} bis {(week_start+timedelta(days=6)).isoformat()}")

    if st.button("Zeiten laden", key="ts_load"):
        keys=df["Key"].tolist(); logs=[]; errs=[]; prog=st.progress(0.0, text="Lade Worklogs…")
        for i,k in enumerate(keys, start=1):
            try:
                wl=jira.list_worklogs(k) or {}
                for w in wl.get("worklogs", []):
                    started=pd.to_datetime(w.get("started"))
                    if started.tzinfo is None: started=started.tz_localize("UTC").astimezone()
                    d0=started.date()
                    if week_start <= d0 < week_start+timedelta(days=7):
                        author=(w.get("author") or {}).get("accountId","")
                        if (not mine_only) or (author==me.get("accountId")):
                            logs.append({"Key":k,"Date":d0,"Minutes":int(w.get("timeSpentSeconds",0))//60})
            except Exception as e: errs.append(f"{k}: {e}")
            prog.progress(i/max(len(keys),1), text=f"Lade Worklogs… ({i}/{len(keys)})")
        prog.empty(); st.session_state.timesheet={"logs":logs,"errors":errs,"week_start":week_start.isoformat(),"mine":mine_only}

    ts=st.session_state.get("timesheet")
    if ts and ts.get("week_start")==week_start.isoformat() and ts.get("mine")==mine_only:
        logs,errs=ts["logs"], ts["errors"]
        if errs:
            with st.expander("Fehler beim Laden"):
                for e in errs: st.write(e)
        by_issue={}
        for log in logs:
            k=log["Key"]; d0=log["Date"]; m=log["Minutes"]
            by_issue.setdefault(k,{dc:0 for dc in day_cols}); col=d0.strftime("%a\n%d.%m")
            by_issue[k][col]=by_issue[k].get(col,0)+m
        rows=[]
        for k,cols in by_issue.items():
            row={"Ticket":k}; total_min=0
            for dc in day_cols:
                mins=cols.get(dc,0); total_min+=mins; row[dc]=round(mins/60,2)
            row["Summe (h)"]=round(total_min/60,2); rows.append(row)
        df_ts=pd.DataFrame(rows) if rows else pd.DataFrame(columns=["Ticket"]+day_cols+["Summe (h)"])
        totals={"Ticket":"Σ"}; week_total_min=0
        for dc,d in zip(day_cols,days):
            m=sum([log["Minutes"] for log in logs if log["Date"]==d]); totals[dc]=round(m/60,2); week_total_min+=m
        totals["Summe (h)"]=round(week_total_min/60,2)
        totals_df = pd.DataFrame([totals], columns=df_ts.columns if not df_ts.empty else ["Ticket"]+day_cols+["Summe (h)"])
        if df_ts.empty: df_ts = totals_df
        else: df_ts = pd.concat([df_ts, totals_df], ignore_index=True)
        cts1,cts2=st.columns([1,3]); cts1.metric("Wochensumme (h)", totals["Summe (h)"]); cts2.caption("Letzte Zeile: Tagessummen & Wochensumme")
        st.dataframe(df_ts, use_container_width=True, hide_index=True)
        st.download_button("Timesheet (CSV) herunterladen", data=df_ts.to_csv(index=False).encode("utf-8"), file_name=f"timesheet_{week_start.isoformat()}.csv", mime="text/csv", key="ts_export_csv")

# ----------------------------- Health-Check+ -----------------------
with tab_health:
    st.subheader("Health-Check+")
    ok_msgs=[]; warn_msgs=[]; err_msgs=[]

    def timed(fn,*a,**kw):
        t0=time.time()
        try: res=fn(*a,**kw); return time.time()-t0, res, None
        except Exception as e: return time.time()-t0, None, e

    # /myself
    t_myself,me_res,e1=timed(jira.get_myself)
    (ok_msgs if not e1 else err_msgs).append(f"/myself {'ok' if not e1 else 'Fehler'} ({t_myself*1000:.0f} ms)" + ("" if not e1 else f": {e1}"))

    # Projects
    t_proj,_,e2=timed(jira.list_projects,None)
    (ok_msgs if not e2 else err_msgs).append(f"/project/search {'ok' if not e2 else 'Fehler'} ({t_proj*1000:.0f} ms)" + ("" if not e2 else f": {e2}"))

    # Headers & Clock Skew
    try:
        stime=None; rl="n/a"; status=200
        try:
            r = requests.get(f"{st.session_state.site_url}/rest/api/3/myself", timeout=10)
            status=r.status_code; hdr=dict(r.headers); rl=hdr.get("X-RateLimit-Remaining") or hdr.get("x-ratelimit-remaining") or "n/a"
            stime=hdr.get("Date")
        except Exception:
            pass
        skew="n/a"
        if stime:
            server_dt=pd.to_datetime(stime, utc=True).to_pydatetime()
            local_dt=datetime.now(timezone.utc)
            skew=f"{abs((server_dt-local_dt).total_seconds()):.0f}s"
        ok_msgs.append(f"Headers ok (Status {status}). RateLimit-Remaining: {rl}, Clock Skew ~ {skew}")
    except Exception as e: warn_msgs.append(f"Header-Check nicht möglich: {e}")

    # DB connectivity
    try:
        with engine.begin() as con:
            con.execute(text("SELECT 1"))
        ok_msgs.append("DB-Verbindung ok (SELECT 1).")
    except Exception as e:
        err_msgs.append(f"DB-Verbindung FEHLER: {e}")

    # Token expiry (OAuth) / Basic Hinweis
    try:
        if hasattr(jira, "access_token"):
            # OAuth Client
            exp = getattr(jira, "expires_at", None)
            if isinstance(exp, datetime):
                remaining = (exp - datetime.now(timezone.utc)).total_seconds()
                ok_msgs.append(f"OAuth-Token läuft in ~{int(remaining)}s ab.")
        else:
            ok_msgs.append("Basic-Auth aktiv (API Token).")
    except Exception as e:
        warn_msgs.append(f"Token-Info nicht ermittelbar: {e}")

    # Permissions (mypermissions): BROWSE, WORKLOG_ADD, EDIT_ISSUES
    try:
        perms = jira.my_permissions() or {}
        p = (perms.get("permissions") or {})
        def pflag(name): 
            try: return "✔" if (p.get(name) or {}).get("havePermission") else "✖"
            except: return "?"

        ok_msgs.append(f"Berechtigungen: Browse {pflag('BROWSE_PROJECTS')}, Worklog_Add {pflag('WORKLOG_ADD')}, Edit_Issues {pflag('EDIT_ISSUES')}")
    except Exception as e:
        warn_msgs.append(f"Permissions nicht abrufbar: {e}")

    # Output
    if ok_msgs: st.success("✔ " + "\n\n✔ ".join(ok_msgs))
    if warn_msgs: st.warning("⚠ " + "\n\n⚠ ".join(warn_msgs))
    if err_msgs: st.error("❌ " + "\n\n❌ ".join(err_msgs))

# ----------------------------- Undo -------------------------------
st.markdown("---")
if st.session_state.get("undo"):
    u=st.session_state["undo"]
    if u["type"]=="labels":
        if st.button("↩️ Letzte Label-Änderung rückgängig machen", key="undo_labels"):
            prev=u["data"]; errs=[]
            for k,old in prev.items():
                try: jira.update_issue_labels(k, old)
                except Exception as e: errs.append(f"{k}: {e}")
            st.session_state.undo=None; st.success("Label-Änderung rückgängig gemacht."); 
            fetch_issues_df.clear(); # (removed) stale busting via query params not needed with cache
    elif u["type"]=="worklogs":
        if st.button("↩️ Letzte Worklogs rückgängig machen", key="undo_wl"):
            errs=[]
            for (k,wid) in u["data"]:
                try: jira.delete_worklog(k, wid)
                except Exception as e: errs.append(f"{k}/{wid}: {e}")
            st.session_state.undo=None
            if errs: st.error("Einige Worklogs konnten nicht gelöscht werden.")
            else: st.success("Worklogs gelöscht.")
