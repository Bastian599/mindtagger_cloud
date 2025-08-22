# app.py — Jira Stichwort-Zuordnung PRO v7.1
import os, json, time, base64, hashlib, secrets, re
from datetime import datetime, date, timedelta, timezone, time as dtime
from typing import List, Dict, Any, Optional, Tuple

import streamlit as st
import requests
import pandas as pd
import matplotlib.pyplot as plt
from sqlalchemy import create_engine, text as sql_text
from sqlalchemy.exc import SQLAlchemyError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

st.set_page_config(page_title="Jira Stichwort-Zuordnung — PRO v7.1", layout="wide")

# ============================== Utilities ==============================
def _sec(name: str, default: str = "") -> str:
    try: return st.secrets.get(name, default)  # type: ignore
    except Exception: return os.getenv(name, default)

def normalize_base_url(url: str) -> str:
    url=(url or "").strip()
    return url[:-1] if url.endswith("/") else url

STATUS_EXCLUDES_BASE = ["Closed","Geschlossen","Abgebrochen"]  # "Erledigt/Done" bleibt sichtbar
P_PATTERN = re.compile(r"^P\d{6}$")

def is_p_label(x: str) -> bool:
    return bool(P_PATTERN.match((x or "").strip()))

def extract_p_label(labels: List[str]) -> Optional[str]:
    for l in labels or []:
        if is_p_label(l): return l
    return None

def b64e(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode()
def b64d(s: str) -> bytes: return base64.urlsafe_b64decode(s.encode())

# ============================== DB (SQLAlchemy) ==============================
ENGINE = None
def get_engine():
    global ENGINE
    if ENGINE is None:
        db_url = _sec("DATABASE_URL","")
        if db_url:
            ENGINE = create_engine(db_url, pool_pre_ping=True)
    return ENGINE

def db_exec(sql: str, params: dict = None):
    eng = get_engine()
    if not eng: return None
    with eng.begin() as conn:
        return conn.execute(sql_text(sql), params or {})

def db_init():
    eng = get_engine()
    if not eng: return
    db_exec("""
    CREATE TABLE IF NOT EXISTS user_pin (
        email TEXT PRIMARY KEY,
        site_url TEXT NOT NULL,
        token_cipher TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
    );
    """)
    db_exec("""
    CREATE TABLE IF NOT EXISTS user_oauth (
        email TEXT PRIMARY KEY,
        cloud_id TEXT,
        access_token_enc TEXT,
        refresh_token_enc TEXT,
        expires_at BIGINT,
        scope TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    );
    """)

# ============================== Crypto (PIN & Fernet) ==============================
def _derive_fernet_from_pin(pin: str, salt_b: bytes) -> Fernet:
    kdf = Scrypt(salt=salt_b, length=32, n=2**14, r=8, p=1)
    key = kdf.derive(pin.encode())
    return Fernet(b64e(key).encode())

def encrypt_token_with_pin(pin: str, token: str) -> Tuple[str,str]:
    salt = secrets.token_bytes(16)
    f = _derive_fernet_from_pin(pin, salt)
    ct = f.encrypt(token.encode()).decode()
    return ct, b64e(salt)

def decrypt_token_with_pin(pin: str, token_cipher: str, salt_b64: str) -> str:
    f = _derive_fernet_from_pin(pin, b64d(salt_b64))
    return f.decrypt(token_cipher.encode()).decode()

def get_master_fernet() -> Optional[Fernet]:
    key = _sec("FERNET_KEY","")
    if not key: return None
    try:
        if isinstance(key, str): key = key.strip()
        if not key: return None
        Fernet(key)  # validate
        return Fernet(key)
    except Exception:
        return None

# ============================== OAuth (Atlassian SSO) ==============================
ATL_CLIENT_ID = _sec("ATLASSIAN_CLIENT_ID","")
ATL_CLIENT_SECRET = _sec("ATLASSIAN_CLIENT_SECRET","")
ATL_REDIRECT_URI = _sec("ATLASSIAN_REDIRECT_URI","")
ATL_SCOPES = _sec("ATLASSIAN_SCOPES","offline_access read:jira-user read:jira-work write:jira-work")

def oauth_authorize_url(state: str, code_challenge: str) -> str:
    scope = "+".join(ATL_SCOPES.split())
    return ("https://auth.atlassian.com/authorize"
            f"?audience=api.atlassian.com&client_id={ATL_CLIENT_ID}"
            f"&scope={scope}&redirect_uri={ATL_REDIRECT_URI}"
            f"&state={state}&response_type=code&prompt=consent&code_challenge={code_challenge}&code_challenge_method=S256")

def oauth_token_exchange(code: str, code_verifier: str) -> dict:
    d = {
        "grant_type":"authorization_code",
        "client_id": ATL_CLIENT_ID,
        "client_secret": ATL_CLIENT_SECRET,
        "code": code,
        "redirect_uri": ATL_REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    r = requests.post("https://auth.atlassian.com/oauth/token", json=d, timeout=30)
    if r.status_code>=400: raise Exception(f"Token-Austausch fehlgeschlagen: {r.status_code} {r.text}")
    return r.json()

def oauth_refresh(refresh_token: str) -> dict:
    d = {
        "grant_type":"refresh_token",
        "client_id": ATL_CLIENT_ID,
        "client_secret": ATL_CLIENT_SECRET,
        "refresh_token": refresh_token,
    }
    r = requests.post("https://auth.atlassian.com/oauth/token", json=d, timeout=30)
    if r.status_code>=400: raise Exception(f"Refresh fehlgeschlagen: {r.status_code} {r.text}")
    return r.json()

def oauth_resources(access_token: str) -> list:
    r = requests.get("https://api.atlassian.com/oauth/token/accessible-resources",
                     headers={"Authorization": f"Bearer {access_token}","Accept":"application/json"}, timeout=30)
    if r.status_code>=400: raise Exception(f"Ressourcenabfrage fehlgeschlagen: {r.status_code} {r.text}")
    return r.json()

def oauth_store(email: str, cloud_id: str, access_token: str, refresh_token: str, expires_in: int, scope: str):
    f = get_master_fernet()
    if not f: raise Exception("FERNET_KEY fehlt (für SSO erforderlich).")
    at = f.encrypt(access_token.encode()).decode()
    rt = f.encrypt(refresh_token.encode()).decode()
    exp = int(time.time()) + int(expires_in)
    db_exec("""INSERT INTO user_oauth(email, cloud_id, access_token_enc, refresh_token_enc, expires_at, scope)
               VALUES(:e,:c,:a,:r,:x,:s)
               ON CONFLICT(email) DO UPDATE SET cloud_id=excluded.cloud_id, access_token_enc=excluded.access_token_enc,
               refresh_token_enc=excluded.refresh_token_enc, expires_at=excluded.expires_at, scope=excluded.scope""",
            {"e":email,"c":cloud_id,"a":at,"r":rt,"x":exp,"s":scope})

def oauth_load(email: str) -> Optional[dict]:
    rows = db_exec("SELECT cloud_id, access_token_enc, refresh_token_enc, expires_at, scope FROM user_oauth WHERE email=:e", {"e":email})
    if not rows: return None
    r = list(rows)
    if not r: return None
    cloud_id, at_enc, rt_enc, exp, scope = r[0]
    f = get_master_fernet()
    if not f: return None
    try:
        at = f.decrypt(at_enc.encode()).decode()
        rt = f.decrypt(rt_enc.encode()).decode()
    except Exception:
        return None
    return {"cloud_id":cloud_id,"access_token":at,"refresh_token":rt,"expires_at":exp,"scope":scope}

def oauth_ensure(email: str) -> Optional[dict]:
    rec = oauth_load(email)
    if not rec: return None
    if rec["expires_at"] - int(time.time()) > 60:
        return rec
    new = oauth_refresh(rec["refresh_token"])
    access_token = new["access_token"]; refresh_token = new.get("refresh_token", rec["refresh_token"])
    expires_in = int(new.get("expires_in", 3600)); scope = new.get("scope","")
    oauth_store(email, rec["cloud_id"], access_token, refresh_token, expires_in, scope)
    rec = oauth_load(email)
    return rec

# ============================== Jira Clients ==============================
class JiraError(Exception): pass

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
    def list_status_names(self):
        d=self._req("GET","/rest/api/3/status") or []
        return {s.get("name") for s in d if s.get("name")}
    def list_status_names_for_projects(self, project_keys: List[str]):
        names=set()
        for k in project_keys:
            try:
                d=self._req("GET", f"/rest/api/3/project/{k}/statuses") or []
                for stnode in d:
                    for s in stnode.get("statuses", []):
                        n=s.get("name"); 
                        if n: names.add(n)
            except Exception:
                pass
        return names
    def search_issues(self, jql, fields, batch_size=100):
        start_at=0; out=[]
        while True:
            d=self._req("POST","/rest/api/3/search", data=json.dumps({"jql":jql,"startAt":start_at,"maxResults":batch_size,"fields":fields}))
            out.extend(d.get("issues",[]))
            if start_at+batch_size>=d.get("total",0): break
            start_at+=batch_size
        return out
    def update_issue_labels(self, issue_key, new_labels):
        self._req("PUT", f"/rest/api/3/issue/{issue_key}", data=json.dumps({"fields":{"labels":new_labels}}))
    def bulk_edit_labels(self, issue_keys, add_labels=None, remove_labels=None, notify=False, progress_cb=None):
        import time as _t
        add_labels=list(add_labels or []); remove_labels=list(remove_labels or [])
        if not issue_keys: return []
        def _labels_block(option, labels):
            return {"fieldId":"labels","bulkEditMultiSelectFieldOption":option,"labels":[{"name":n} for n in labels]}
        CHUNK=1000; total=len(issue_keys); done=0; results=[]
        for i in range(0,total,CHUNK):
            chunk=issue_keys[i:i+CHUNK]
            edited={"labelsFields":[]}
            if add_labels: edited["labelsFields"].append(_labels_block("ADD", add_labels))
            if remove_labels: edited["labelsFields"].append(_labels_block("REMOVE", remove_labels))
            payload={"editedFieldsInput":edited,"selectedIssueIdsOrKeys":chunk,"sendBulkNotification":bool(notify)}
            d=self._req("POST","/rest/api/3/bulk/issues/fields", data=json.dumps(payload)) or {}
            tid=d.get("taskId")
            if tid:
                for _ in range(180):
                    q=self._req("GET", f"/rest/api/3/bulk/queue/{tid}") or {}
                    status=q.get("status"); percent=q.get("progress",{}).get("percentage") or q.get("percentage") or 0
                    if progress_cb and total:
                        base=done/total; frac=min(1.0, base + (len(chunk)/total)*(percent/100.0)); 
                        try: progress_cb(frac)
                        except Exception: pass
                    if status in ("COMPLETE","FAILED","CANCELLED"): results.append(q); break
                    _t.sleep(1.0)
            done+=len(chunk)
            if progress_cb and total:
                try: progress_cb(done/total)
                except Exception: pass
        return results

class JiraClientOAuth:
    def __init__(self, cloud_id: str, access_token: str, timeout=30):
        self.cloud_id=cloud_id; self.timeout=timeout
        self.base=f"https://api.atlassian.com/ex/jira/{cloud_id}"
        self.s=requests.Session()
        self.s.headers.update({"Accept":"application/json","Content-Type":"application/json","Authorization":f"Bearer {access_token}"})
    def _req(self, method, path, params=None, data=None, retries=3):
        url=f"{self.base}{path}"
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
    def list_status_names(self):
        d=self._req("GET","/rest/api/3/status") or []
        return {s.get("name") for s in d if s.get("name")}
    def list_status_names_for_projects(self, project_keys: List[str]):
        names=set()
        for k in project_keys:
            try:
                d=self._req("GET", f"/rest/api/3/project/{k}/statuses") or []
                for stnode in d:
                    for s in stnode.get("statuses", []):
                        n=s.get("name"); 
                        if n: names.add(n)
            except Exception:
                pass
        return names
    def search_issues(self, jql, fields, batch_size=100):
        start_at=0; out=[]
        while True:
            d=self._req("POST","/rest/api/3/search", data=json.dumps({"jql":jql,"startAt":start_at,"maxResults":batch_size,"fields":fields}))
            out.extend(d.get("issues",[]))
            if start_at+batch_size>=d.get("total",0): break
            start_at+=batch_size
        return out
    def update_issue_labels(self, issue_key, new_labels):
        self._req("PUT", f"/rest/api/3/issue/{issue_key}", data=json.dumps({"fields":{"labels":new_labels}}))
    def bulk_edit_labels(self, issue_keys, add_labels=None, remove_labels=None, notify=False, progress_cb=None):
        # reuse logic from basic class
        return JiraClientBasic.bulk_edit_labels(self, issue_keys, add_labels, remove_labels, notify, progress_cb)

# ============================== UI State ==============================
st.title("Jira Stichwort-Zuordnung — PRO v7.1")
st.caption("P‑Labels • Worklogs • Reports • Timesheet • Health‑Check+  |  DB‑Speicherung & SSO optional")

for k in ["jira","jira_mode","me","site_url","projects_cache","only_lead_prev","pl_preview_map","pl_preview_p","oauth_state","oauth_verifier","oauth_email"]:
    st.session_state.setdefault(k, None)

db_init()

# ============================== Sidebar: Login & Storage ==============================
with st.sidebar:
    st.header("Anmeldung")
    tab_pin, tab_sso, tab_store = st.tabs(["🔐 PIN‑Login","🪪 Jira SSO","💾 Token speichern/ändern"])

    with tab_pin:
        site_url = st.text_input("Jira‑URL", value=st.session_state.get("site_url") or _sec("JIRA_BASE_URL",""))
        email = st.text_input("E‑Mail", value="")
        pin = st.text_input("PIN", type="password", value="")
        if st.button("Schnell‑Login"):
            try:
                rows = db_exec("SELECT token_cipher, salt FROM user_pin WHERE email=:e", {"e":email})
                rec = list(rows)[0] if rows else None
                if not rec: st.error("Kein gespeicherter Token zu dieser E‑Mail. Bitte unter 'Token speichern/ändern' hinterlegen."); st.stop()
                token_cipher, salt = rec
                api_token = decrypt_token_with_pin(pin, token_cipher, salt)
                jira = JiraClientBasic(site_url, email, api_token)
                me = jira.get_myself()
                st.session_state.update({"jira":jira,"jira_mode":"basic","me":me,"site_url":site_url})
                st.success(f"Angemeldet als {me.get('displayName','?')}")
            except Exception as e:
                st.error(f"Login fehlgeschlagen: {e}")

    with tab_sso:
        st.caption("Optional: OAuth 2.0 (Atlassian). Erfordert FERNET_KEY & Client‑Credentials in Secrets.")
        sso_email = st.text_input("E‑Mail (für Speicherung)", value=st.session_state.get("oauth_email") or "")
        c1,c2 = st.columns([1,1])
        if c1.button("Mit Jira anmelden"):
            if not (ATL_CLIENT_ID and ATL_CLIENT_SECRET and ATL_REDIRECT_URI):
                st.error("SSO nicht konfiguriert (Client‑ID/Secret/Redirect fehlt).")
            else:
                verifier = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip("=")
                digest = hashlib.sha256(verifier.encode()).digest()
                challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
                state = base64.urlsafe_b64encode(os.urandom(24)).decode()
                st.session_state.oauth_verifier = verifier
                st.session_state.oauth_state = state
                st.session_state.oauth_email = sso_email
                url = oauth_authorize_url(state, challenge)
                st.markdown(f"[Weiter zur Jira‑Anmeldung]({url})")
                st.info("Nach dem Login wirst du zur App zurückgeleitet.")
        # Callback
        qp = dict(st.query_params)
        code = qp.get("code",[None])[0] if isinstance(qp.get("code"), list) else qp.get("code")
        state = qp.get("state",[None])[0] if isinstance(qp.get("state"), list) else qp.get("state")
        if code and state and state == st.session_state.get("oauth_state"):
            try:
                tok = oauth_token_exchange(code, st.session_state.get("oauth_verifier",""))
                access_token = tok["access_token"]; refresh_token = tok.get("refresh_token",""); scope = tok.get("scope",""); expires_in = int(tok.get("expires_in",3600))
                res = oauth_resources(access_token)
                if not res: raise Exception("Keine Jira‑Ressourcen gefunden.")
                cloud_id = res[0]["id"]
                oauth_store(sso_email, cloud_id, access_token, refresh_token, expires_in, scope)
                rec = oauth_load(sso_email)
                jira = JiraClientOAuth(rec["cloud_id"], rec["access_token"])
                me = jira.get_myself()
                st.session_state.update({"jira":jira,"jira_mode":"oauth","me":me,"site_url":None})
                st.success(f"SSO aktiv. Angemeldet als {me.get('displayName','?')}")
            except Exception as e:
                st.error(f"SSO fehlgeschlagen: {e}")

    with tab_store:
        st.caption("Token sicher speichern (PIN‑verschlüsselt)")
        s_site = st.text_input("Jira‑URL (z. B. https://tenant.atlassian.net)", value=st.session_state.get("site_url") or _sec("JIRA_BASE_URL",""), key="store_site")
        s_email = st.text_input("E‑Mail", key="store_email")
        s_token = st.text_input("API‑Token", type="password", key="store_token")
        s_pin = st.text_input("PIN (nur zum Entschlüsseln, wird nicht gespeichert)", type="password", key="store_pin")
        if st.button("Speichern/Ändern"):
            try:
                ct, salt = encrypt_token_with_pin(s_pin, s_token)
                db_exec("""INSERT INTO user_pin(email, site_url, token_cipher, salt) VALUES(:e,:u,:c,:s)
                           ON CONFLICT(email) DO UPDATE SET site_url=excluded.site_url, token_cipher=excluded.token_cipher, salt=excluded.salt""",
                        {"e":s_email,"u":s_site,"c":ct,"s":salt})
                st.success("Token gespeichert. Du kannst nun per PIN‑Login verbinden.")
            except Exception as e:
                st.error(f"Speichern fehlgeschlagen: {e}")

# Must be logged in
if not st.session_state.jira:
    st.info("Bitte melde dich an (PIN‑Login oder SSO).")
    st.stop()

jira = st.session_state.jira
me = st.session_state.me or {}
site_url = st.session_state.site_url  # bei SSO None (wir zeigen dann evtl. leere Link-Spalte)

# ============================== Projects ==============================
def _invalidate_projects(): st.session_state.projects_cache=None
only_lead = st.toggle("Nur Projekte, bei denen ich Lead bin", value=bool(st.session_state.get("only_lead_prev") or False), on_change=_invalidate_projects)
if st.session_state.only_lead_prev is None or st.session_state.only_lead_prev != only_lead:
    st.session_state.projects_cache=None
st.session_state.only_lead_prev = only_lead

with st.spinner("Lade Projekte…"):
    if not st.session_state.get("projects_cache"):
        projs = jira.list_projects(me.get("accountId") if only_lead else None)
        if only_lead and not projs:
            st.info("Keine Projekte mit dir als Lead gefunden – zeige alle Projekte.")
            projs = jira.list_projects(None)
        st.session_state.projects_cache = sorted(projs, key=lambda p: p.get("key",""))

projects = st.session_state.projects_cache or []
proj_labels=[f"{p.get('key')} — {p.get('name')}" for p in projects]
proj_key_by_label={f"{p.get('key')} — {p.get('name')}": p.get("key") for p in projects}

st.toggle("Multi-Projekt-Modus", value=False, key="multi_proj")
if st.session_state.multi_proj and projects:
    selected_labels = st.multiselect("Projekte auswählen", proj_labels, default=proj_labels[:1], key="proj_multi")
    selected_keys = [proj_key_by_label[l] for l in selected_labels]
else:
    selected_label = st.selectbox("Projekt auswählen", proj_labels, index=0 if proj_labels else None, key="proj_single")
    selected_keys = [proj_key_by_label[selected_label]] if proj_labels else []

# ============================== Data Fetch with Cache ==============================
@st.cache_data(ttl=120, show_spinner=False)
def fetch_issues_df(_jira_client, project_keys: List[str], site_url: Optional[str]) -> pd.DataFrame:
    if isinstance(project_keys, str): project_keys=[project_keys]
    if not project_keys:
        return pd.DataFrame(columns=["Project","Key","Ticket","Summary","Status","P_Label_Aktuell","Alle_Labels"])
    quoted = ",".join([f'"{k}"' for k in project_keys])
    try:
        names = _jira_client.list_status_names_for_projects(project_keys) or _jira_client.list_status_names()
    except Exception:
        names = set()
    excludes = [s for s in STATUS_EXCLUDES_BASE if s in names]
    base_clause = f'project in ({quoted})'
    if excludes:
        not_in = ",".join([f'"{s}"' for s in excludes])
        jql = f'{base_clause} AND status not in ({not_in}) ORDER BY created DESC'
    else:
        jql = f'{base_clause} ORDER BY created DESC'
    fields = ["summary","status","labels","project"]
    issues = _jira_client.search_issues(jql, fields)
    rows=[]
    for it in issues:
        f = it.get("fields", {}) or {}
        k = it.get("key","")
        proj = (f.get("project") or {}).get("key","")
        summary = f.get("summary","")
        status = (f.get("status") or {}).get("name","")
        labels = f.get("labels") or []
        if status in set(STATUS_EXCLUDES_BASE): 
            continue
        link = f"{site_url}/browse/{k}" if site_url else ""
        rows.append({"Project":proj,"Key":k,"Ticket":link,"Summary":summary,"Status":status,
                     "P_Label_Aktuell": extract_p_label(labels) or "", "Alle_Labels": ", ".join(labels) if labels else ""})
    return pd.DataFrame(rows)

def refresh_after_update():
    fetch_issues_df.clear()
    st.rerun()

df = fetch_issues_df(jira, selected_keys, site_url)

# ============================== Tabs ==============================
tab_overview, tab_plabel, tab_worklog, tab_csv, tab_reports, tab_timesheet, tab_health = st.tabs(
    ["📋 Übersicht","🏷️ P-Labels","⏱️ Worklog (einzeln)","📥 CSV-Import","📊 Reports","🗓️ Timesheet","🩺 Health-Check+"]
)

# ------------------------------ Übersicht ------------------------------
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

    st.dataframe(df_view, use_container_width=True, hide_index=True, column_config={
        "Ticket": st.column_config.LinkColumn("Ticket öffnen", display_text="Open"),
        "Project": st.column_config.TextColumn("Projekt"),
        "Key": st.column_config.TextColumn("Key"),
        "Summary": st.column_config.TextColumn("Summary"),
        "Status": st.column_config.TextColumn("Status"),
        "P_Label_Aktuell": st.column_config.TextColumn("P-Label"),
        "Alle_Labels": st.column_config.TextColumn("Alle Labels"),
    })

# ------------------------------ P-Labels ------------------------------
with tab_plabel:
    st.subheader("P‑Labels zuweisen (Vorschau → Bestätigen → Bulk‑Update)")
    df_scope = df if st.session_state.multi_proj else (df[df["Project"]==selected_keys[0]] if selected_keys else df)
    table = df_scope[["Project","Key","Summary","Status","P_Label_Aktuell","Alle_Labels"]].copy()
    table.insert(0, "Auswählen", False)

    colsel1, colsel2 = st.columns([1,1])
    if colsel1.button("Alle ohne P‑Label auswählen"): table.loc[table["P_Label_Aktuell"]=="","Auswählen"]=True
    if colsel2.button("Auswahl leeren"): table["Auswählen"]=False

    with st.form("pl_form"):
        edited = st.data_editor(
            table,
            use_container_width=True,
            hide_index=True,
            num_rows="fixed",
            column_config={
                "Auswählen": st.column_config.CheckboxColumn(help="Ticket in Aktion einschließen"),
                "P_Label_Aktuell": st.column_config.TextColumn("P‑Label"),
            },
            key="pl_editor",
        )
        colp1, colp2 = st.columns([2,1])
        p_number = colp1.text_input("Projektnummer (PXXXXXX)", value=st.session_state.get("pl_preview_p") or "", key="pl_p_number")
        mode_all = colp2.toggle("Alle in aktueller Ansicht verwenden", value=False, key="pl_all_mode")
        preview_btn = st.form_submit_button("Änderungen prüfen")

    if preview_btn:
        target = df_scope["Key"].tolist() if mode_all else edited.loc[edited["Auswählen"]==True,"Key"].tolist()
        if not target:
            st.warning("Keine Tickets ausgewählt.")
        elif not (p_number and is_p_label(p_number)):
            st.error("Ungültige Projektnummer. Format: PXXXXXX (6 Ziffern).")
        else:
            prev_map = {}
            for k in target:
                row = df_scope.loc[df_scope["Key"]==k].iloc[0]
                labels = [l.strip() for l in (row["Alle_Labels"].split(",") if row["Alle_Labels"] else []) if l.strip()]
                old_p = next((l for l in labels if is_p_label(l)), "")
                prev_map[k] = old_p
            st.session_state.pl_preview_map = prev_map
            st.session_state.pl_preview_p = p_number
            st.success(f"Vorschau bereit. {len(target)} Tickets werden auf `{p_number}` gesetzt.")

    if st.session_state.pl_preview_map:
        st.markdown("#### Vorschau")
        rows=[{"Key":k,"Alt": (old or "(kein P)"), "Neu": st.session_state.pl_preview_p} for k,old in sorted(st.session_state.pl_preview_map.items())]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        cp1, cp2 = st.columns([1,1])
        if cp1.button("✅ Bestätigen & Anwenden", key="pl_apply"):
            upd = st.session_state.pl_preview_map or {}
            keys = sorted(list(upd.keys()))
            p_val = st.session_state.get("pl_preview_p") or ""
            remove_set = sorted({v for v in upd.values() if v and v != p_val})

            st.info(f"{len(keys)} Tickets werden aktualisiert. Neues P‑Label: `{p_val}`")
            prog = st.progress(0, text="Bulk‑Update läuft …")
            def _cb(frac):
                try: prog.progress(min(1.0, frac), text=f"Fortschritt: {int(100*min(1.0, frac))}%")
                except Exception: pass
            try:
                jira.bulk_edit_labels(keys, add_labels=[p_val], remove_labels=remove_set, notify=False, progress_cb=_cb)
                prog.progress(1.0, text="Fertig")
                st.success(f"P‑Label `{p_val}` angewandt. {len(keys)} Tickets aktualisiert.")
                st.session_state.pl_preview_map=None; st.session_state.pl_preview_p=None
                refresh_after_update()
            except Exception as e:
                st.error(f"Fehler beim Bulk‑Update: {e}")
        if cp2.button("Abbrechen", key="pl_cancel"):
            st.session_state.pl_preview_map=None; st.session_state.pl_preview_p=None
            st.info("Vorschau verworfen.")

# ------------------------------ Worklog (einzeln) ------------------------------
with tab_worklog:
    st.subheader("Zeiterfassung (einzeln)")
    t_key = st.text_input("Ticket‑Key (z. B. PROJ-123)")
    colw1,colw2,colw3 = st.columns([1,1,2])
    w_date = colw1.date_input("Datum", value=date.today())
    w_time = colw2.time_input("Startzeit", value=dtime(9,0))
    dur_quarters = colw3.slider("Dauer (15‑Min‑Schritte)", min_value=1, max_value=32, value=4, step=1, help="1=15min … 32=8h")
    comment = st.text_input("Beschreibung (optional)")

    if st.button("Worklog anlegen"):
        if not t_key: st.warning("Bitte Ticket‑Key angeben."); st.stop()
        started = datetime.combine(w_date, w_time).astimezone().strftime("%Y-%m-%dT%H:%M:%S.000%z")
        secs = int(dur_quarters)*15*60
        try:
            d = jira._req("POST", f"/rest/api/3/issue/{t_key}/worklog", data=json.dumps({"started":started,"timeSpentSeconds":secs,"comment":comment or ""}))
            st.session_state["last_worklog"] = {"issue":t_key, "id": d.get("id")}
            st.success(f"Erfasst: {t_key} — {secs//60} Minuten")
        except Exception as e:
            st.error(f"Fehler: {e}")

    if st.session_state.get("last_worklog"):
        lw = st.session_state["last_worklog"]
        if st.button(f"Letzten Eintrag rückgängig machen ({lw['issue']} / #{lw['id']})"):
            try:
                jira._req("DELETE", f"/rest/api/3/issue/{lw['issue']}/worklog/{lw['id']}")
                st.session_state["last_worklog"]=None
                st.success("Letzter Worklog gelöscht.")
            except Exception as e:
                st.error(f"Fehler beim Löschen: {e}")

# ------------------------------ CSV Import (Worklogs) ------------------------------
with tab_csv:
    st.subheader("CSV‑Import (Vorschau → Bestätigen)")
    st.caption("Spalten: Ticketnummer;Datum;benötigte Zeit in h (z. B. 1,5 oder 0,25); optional: Uhrzeit;Beschreibung")
    example = "Ticketnummer;Datum;benötigte Zeit in h;Uhrzeit;Beschreibung\nPROJ-101;21.08.2025;0,25;12:30;Daily Standup\nPROJ-202;21.08.2025;1.5;09:00;Konzept & Abstimmung\n"
    st.download_button("Beispiel‑CSV herunterladen", data=example.encode("utf-8"), file_name="beispiel_worklogs.csv", mime="text/csv")

    up = st.file_uploader("CSV hochladen", type=["csv"])
    if up:
        raw = up.read().decode("utf-8")
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        hdr = lines[0].split(";")
        rows = [l.split(";") for l in lines[1:]]
        parsed=[]; errors=[]
        for i, r in enumerate(rows, start=2):
            try:
                key=r[0].strip()
                dstr=r[1].strip()
                hrs=r[2].strip().replace(",",".")
                tm=r[3].strip() if len(r)>3 and r[3].strip() else "09:00"
                cmt=r[4].strip() if len(r)>4 else ""
                dt = datetime.strptime(dstr, "%d.%m.%Y").date()
                hh,mm = map(int, tm.split(":"))
                started = datetime.combine(dt, dtime(hh,mm)).astimezone().strftime("%Y-%m-%dT%H:%M:%S.000%z")
                secs = int(float(hrs)*3600)
                secs = (secs // (15*60)) * (15*60)
                if secs<=0: raise ValueError("Dauer <= 0")
                parsed.append({"issueKey":key, "started":started, "timeSpentSeconds":secs, "comment":cmt})
            except Exception as e:
                errors.append(f"Zeile {i}: {e}")

        st.markdown("#### Vorschau")
        if errors:
            st.error("Fehler in CSV:\n- " + "\n- ".join(errors))
        if parsed:
            df_prev=pd.DataFrame([{"Ticket":p["issueKey"],"Start":p["started"],"Minuten":p["timeSpentSeconds"]//60,"Kommentar":p["comment"]} for p in parsed])
            st.dataframe(df_prev, use_container_width=True, hide_index=True)
            if st.button("✅ Import bestätigen"):
                prog = st.progress(0.0, text="Import…")
                created=[]
                for i,p in enumerate(parsed, start=1):
                    try:
                        d=jira._req("POST", f"/rest/api/3/issue/{p['issueKey']}/worklog", data=json.dumps({"started":p["started"],"timeSpentSeconds":p["timeSpentSeconds"],"comment":p["comment"]}))
                        created.append({"issue":p["issueKey"],"id":d.get("id")})
                    except Exception as e:
                        st.error(f"{p['issueKey']}: {e}")
                    prog.progress(i/max(len(parsed),1), text=f"Import… ({i}/{len(parsed)})")
                st.session_state["last_batch_worklogs"]=created
                st.success(f"Import fertig. {len(created)} Einträge angelegt.")
                prog.empty()

# ------------------------------ Reports ------------------------------
with tab_reports:
    st.subheader("Eigene Zeiterfassungen (global)")
    today=datetime.now().date()
    colg0,colg1=st.columns([1.5,1])
    g_start=colg0.date_input("Von", value=today - timedelta(days=30))
    g_end  =colg1.date_input("Bis (inkl.)", value=today)

    if st.button("Alle eigenen Worklogs laden"):
        jql=f'worklogAuthor = currentUser() AND worklogDate >= "{g_start.strftime("%Y/%m/%d")}" AND worklogDate <= "{g_end.strftime("%Y/%m/%d")}" ORDER BY updated DESC'
        fields=["summary","labels","project","status"]
        issues = jira.search_issues(jql, fields, batch_size=100)
        logs=[]; prog=st.progress(0.0, text="Lade eigene Worklogs…")
        for i,it in enumerate(issues, start=1):
            k=it.get("key"); f=it.get("fields",{})
            labels=f.get("labels") or []; p_val=extract_p_label(labels) or "(kein P)"
            try:
                wl=jira._req("GET", f"/rest/api/3/issue/{k}/worklog") or {}
                for w in wl.get("worklogs", []):
                    try: started=pd.to_datetime(w.get("started"))
                    except Exception: continue
                    if started.tzinfo is None: started=started.tz_localize("UTC").astimezone()
                    d0=started.date()
                    if g_start <= d0 <= g_end and (w.get("author") or {}).get("accountId","")==me.get("accountId",""):
                        mins=int(w.get("timeSpentSeconds",0))//60
                        logs.append({"P":p_val,"Ticket":k,"Date":d0,"Minutes":mins})
            except Exception as e:
                pass
            prog.progress(i/max(len(issues),1), text=f"Lade eigene Worklogs… ({i}/{len(issues)})")
        prog.empty()
        if logs:
            df_rep=pd.DataFrame(logs)
            agg=df_rep.groupby("P", as_index=False)["Minutes"].sum().sort_values("Minutes", ascending=False)
            st.dataframe(agg.rename(columns={"Minutes":"Minuten gesamt"}), use_container_width=True, hide_index=True)
            fig, ax = plt.subplots()
            ax.pie(agg["Minutes"], labels=agg["P"], autopct=lambda p: f"{p:.1f}%")
            ax.set_title("Verteilung Aufwände (Minuten) nach P‑Label — Eigene global")
            st.pyplot(fig, use_container_width=True)
            st.download_button("CSV (eigene Worklogs, global)", data=df_rep.to_csv(index=False).encode("utf-8"), file_name=f"worklogs_eigene_{g_start.isoformat()}_{g_end.isoformat()}.csv", mime="text/csv")
        else:
            st.info("Keine eigenen Worklogs im Zeitraum gefunden.")

# ------------------------------ Timesheet ------------------------------
with tab_timesheet:
    st.subheader("Wochenansicht / Timesheet")
    base_day = st.date_input("Woche von (Montag)", value=date.today() - timedelta(days=(date.today().weekday())))
    week_days = [base_day + timedelta(days=i) for i in range(7)]
    jql=f'worklogAuthor = currentUser() AND worklogDate >= "{week_days[0].strftime("%Y/%m/%d")}" AND worklogDate <= "{week_days[-1].strftime("%Y/%m/%d")}" ORDER BY updated DESC'
    issues = jira.search_issues(jql, ["summary","labels","project","status"], batch_size=100)
    data=[]
    for it in issues:
        k=it.get("key"); f=it.get("fields",{})
        try:
            wl=jira._req("GET", f"/rest/api/3/issue/{k}/worklog") or {}
            for w in wl.get("worklogs", []):
                try: started=pd.to_datetime(w.get("started"))
                except Exception: continue
                if started.tzinfo is None: started=started.tz_localize("UTC").astimezone()
                d0=started.date()
                if week_days[0] <= d0 <= week_days[-1] and (w.get("author") or {}).get("accountId","") == me.get("accountId",""):
                    mins=int(w.get("timeSpentSeconds",0))//60
                    data.append({"Ticket":k,"Date":d0,"Minutes":mins})
        except Exception: pass
    if data:
        df_ts=pd.DataFrame(data)
        pivot=df_ts.pivot_table(index="Date", values="Minutes", aggfunc="sum").reindex(week_days, fill_value=0)
        total=int(df_ts["Minutes"].sum())
        st.metric("Gesamt (Woche)", f"{total//60} h {total%60} min")
        st.dataframe(pivot.rename(columns={"Minutes":"Minuten"}), use_container_width=True)
        st.download_button("CSV (Woche, eigene Worklogs)", data=df_ts.to_csv(index=False).encode("utf-8"), file_name=f"timesheet_{week_days[0].isoformat()}_{week_days[-1].isoformat()}.csv", mime="text/csv")
    else:
        st.info("Keine eigenen Worklogs in dieser Woche.")

# ------------------------------ Health-Check+ ------------------------------
with tab_health:
    st.subheader("Health‑Check+")
    try:
        me2=jira.get_myself()
        st.success(f"Jira erreichbar: {me2.get('displayName','?')}")
    except Exception as e:
        st.error(f"Jira‑Fehler: {e}")
    try:
        db_exec("SELECT 1")
        st.success("DB‑Verbindung OK")
    except Exception as e:
        st.error(f"DB‑Fehler: {e}")
    try:
        pr = jira._req("GET","/rest/api/3/mypermissions", params={"projectKey":""}) or {}
        st.info(f"Berechtigungen Keycount: {len((pr.get('permissions') or {}).keys())}")
    except Exception:
        pass
    if st.session_state.jira_mode=="oauth":
        rec = oauth_load(st.session_state.get("oauth_email","") or me.get("emailAddress",""))
        if rec:
            left = rec["expires_at"] - int(time.time())
            st.write(f"SSO‑Token Restlaufzeit: ~{max(0,left)}s")
    st.caption("Hinweis: Bulk‑APIs erfordern ggf. zusätzliche Rechte (Global bulk change).")
