# app.py — Jira Stichwort-Zuordnung PRO v3 (Cloud-ready, patched)
# Fixes:
# - Lead-Only Toggle invalidates project cache
# - No sticky "no secrets" info (silent before login)
# - timezone-aware UTC (no datetime.utcnow deprecation)

import os, re, io, time, json
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, date, time as dtime, timedelta, timezone

import requests
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Jira Stichwort-Zuordnung PRO v3 — Cloud", layout="wide")

def _sec(name: str, default: str = "") -> str:
    try:
        return st.secrets.get(name, default)  # type: ignore[attr-defined]
    except Exception:
        return os.getenv(name, default)

DEFAULTS = {
    "JIRA_BASE_URL":      _sec("JIRA_BASE_URL", ""),
    "JIRA_EMAIL":         _sec("JIRA_EMAIL", ""),
    "JIRA_API_TOKEN":     _sec("JIRA_API_TOKEN", ""),
}

P_PATTERN = re.compile(r"^P\d{6}$")
def is_p_label(label: str) -> bool: return bool(P_PATTERN.match(label or ""))
def extract_p_label(labels: List[str]) -> Optional[str]:
    for l in labels or []:
        if is_p_label(l): return l
    return None
def hide_sidebar_css():
    st.markdown("""<style>[data-testid="stSidebar"]{display:none!important}.block-container{padding-top:1rem}</style>""", unsafe_allow_html=True)
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

class JiraError(Exception): pass
def normalize_base_url(url: str) -> str: url=(url or "").strip(); return url[:-1] if url.endswith("/") else url

class JiraClientBasic:
    def __init__(self, base_url, email, api_token, timeout=30):
        self.base_url=normalize_base_url(base_url); self.timeout=timeout
        self.s=requests.Session(); self.s.auth=(email, api_token)
        self.s.headers.update({"Accept":"application/json","Content-Type":"application/json"})
    def _req(self, method, path, params=None, data=None, retries=3, return_headers=False):
        url=f"{self.base_url}{path}"
        for attempt in range(retries):
            r=self.s.request(method,url,params=params,data=data,timeout=self.timeout)
            if return_headers: return r
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
    def probe_headers(self):
        r=self._req("GET","/rest/api/3/myself", return_headers=True)
        return dict(r.headers), r.status_code

st.title("Jira Stichwort-Zuordnung — PRO v3 (Cloud)")
st.caption("Timesheet • Wochensumme • Health-Check+ • Multi-Tab • Multi-Projekt • Cloud Secrets")

for k in ["jira","myself","site_url","sidebar_collapsed","timesheet","undo","projects_cache","own_only_prev","proj_cache_filter"]: 
    st.session_state.setdefault(k, None)

# Login (silent if not connected)
st.sidebar.header("API Token Einstellungen")
base_url = st.sidebar.text_input("Jira Base-URL", value=DEFAULTS["JIRA_BASE_URL"])
email    = st.sidebar.text_input("E-Mail", value=DEFAULTS["JIRA_EMAIL"])
api_token= st.sidebar.text_input("API Token", type="password", value=DEFAULTS["JIRA_API_TOKEN"])
c1,c2 = st.sidebar.columns(2)
connect = c1.button("Verbinden"); logout = c2.button("Logout")
if logout:
    for k in ["jira","myself","site_url","projects_cache","own_only_prev","proj_cache_filter"]: st.session_state[k]=None

# Auto-connect via secrets (only if all present)
if (DEFAULTS["JIRA_BASE_URL"] and DEFAULTS["JIRA_EMAIL"] and DEFAULTS["JIRA_API_TOKEN"] and not st.session_state.get("jira") and not connect):
    try:
        jira = JiraClientBasic(DEFAULTS["JIRA_BASE_URL"], DEFAULTS["JIRA_EMAIL"], DEFAULTS["JIRA_API_TOKEN"])
        me = jira.get_myself()
        st.session_state.jira=jira; st.session_state.myself=me; st.session_state.site_url=DEFAULTS["JIRA_BASE_URL"]
        st.session_state.sidebar_collapsed=True
    except Exception as e:
        # Zeige nur in Sidebar kompakt, kein permanentes Error-Panel
        st.sidebar.error(f"Login fehlgeschlagen: {e}")

if connect:
    try:
        jira = JiraClientBasic(base_url, email, api_token); me = jira.get_myself()
        st.session_state.jira=jira; st.session_state.myself=me; st.session_state.site_url=base_url
        st.session_state.sidebar_collapsed=True
    except Exception as e:
        st.sidebar.error(f"Verbindungsfehler: {e}")

if not st.session_state.get("jira"):
    # Keine laute Info – nur UI für Login sichtbar
    st.stop()

# Sidebar collapse
if st.session_state.get("sidebar_collapsed", False):
    hide_sidebar_css()
    if st.button("⚙️ Einstellungen anzeigen"): st.session_state.sidebar_collapsed=False; st.rerun()
else:
    st.sidebar.button("↩︎ Sidebar einklappen", on_click=lambda: (st.session_state.update({"sidebar_collapsed": True}), st.rerun()))

jira=st.session_state.jira; me=st.session_state.myself; site_url=st.session_state.site_url

# Lead-only toggle with cache invalidation
def _invalidate_projects():
    st.session_state.projects_cache=None
    st.session_state.proj_cache_filter = st.session_state.get("own_only_toggle", False)

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
def fetch_issues_df(_jira_client, project_keys: List[str], site_url: str) -> pd.DataFrame:
    if isinstance(project_keys, str): project_keys=[project_keys]
    if not project_keys: 
        return pd.DataFrame(columns=["Project","Key","Ticket","Summary","Status","P_Label_Aktuell","Alle_Labels"])
    quoted = ",".join([f'"{k}"' for k in project_keys])
    jql = f'project in ({quoted}) AND statusCategory != Done ORDER BY created DESC'
    fields = ["summary","status","labels","project"]
    issues = _jira_client.search_issues(jql, fields)
    rows=[]
    for it in issues:
        k=it.get("key"); f=it.get("fields",{})
        proj=(f.get("project") or {}).get("key","")
        summary=f.get("summary",""); status=(f.get("status") or {}).get("name",""); labels=f.get("labels") or []
        p_label=extract_p_label(labels); link=f"{site_url}/browse/{k}" if site_url else ""
        rows.append({"Project":proj,"Key":k,"Ticket":link,"Summary":summary,"Status":status,"P_Label_Aktuell":p_label or "", "Alle_Labels":", ".join(labels) if labels else ""})
    return pd.DataFrame(rows)

def refresh_after_update():
    fetch_issues_df.clear(); st.experimental_set_query_params(_=str(time.time())); st.rerun()

df = fetch_issues_df(jira, selected_keys, site_url)

tab_overview, tab_plabel, tab_worklog, tab_csv, tab_reports, tab_timesheet, tab_health = st.tabs(
    ["📋 Übersicht","🏷️ P-Labels","⏱️ Worklog (Einzeln)","📥 CSV-Import","📊 Reports & Export","🗓️ Timesheet","🩺 Health-Check+"]
)

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
    st.dataframe(df_view, use_container_width=True, hide_index=True, column_config={
        "Ticket": st.column_config.LinkColumn("Ticket öffnen", display_text="Open"),
        "Project": st.column_config.TextColumn("Projekt"),
        "Key": st.column_config.TextColumn("Key"),
        "Summary": st.column_config.TextColumn("Summary"),
        "Status": st.column_config.TextColumn("Status"),
        "P_Label_Aktuell": st.column_config.TextColumn("P-Label"),
        "Alle_Labels": st.column_config.TextColumn("Alle Labels"),
    })

with tab_plabel:
    st.subheader("P-Label Zuweisung (Dry-Run möglich)")
    df_scope=df if st.session_state.multi_proj else (df[df["Project"]==selected_keys[0]] if selected_keys else df)
    keys_all=df_scope["Key"].tolist(); keys_without=df_scope.loc[df_scope["P_Label_Aktuell"]=="","Key"].tolist()
    dry_run_labels=st.checkbox("Nur validieren (Dry-Run)", value=True, key="labels_dryrun")
    p_number=st.text_input("Projektnummer (PXXXXXX)", value="", key="pl_p_number")
    keys_select=st.multiselect("Auswahl Tickets", keys_all, default=keys_without, key="pl_keys_select")
    def build_label_preview(target_keys,new_p):
        rows=[]
        for k in target_keys:
            r=df_scope.loc[df_scope["Key"]==k].iloc[0]
            old=[l.strip() for l in (r["Alle_Labels"].split(",") if r["Alle_Labels"] else []) if l.strip()]
            base=[l for l in old if not is_p_label(l)]
            new=base+([new_p] if new_p else [])
            rows.append({"Key":k,"Alt":", ".join(old),"Neu":", ".join(new),"Ändert sich?":"Ja" if set(old)!=set(new) else "Nein"})
        return pd.DataFrame(rows)
    colbb1,colbb2=st.columns(2)
    if colbb1.button("Allen in Ansicht zuweisen", key="pl_all"):
        target=keys_all
        if not p_number or not P_PATTERN.match(p_number): st.error("Ungültige P-Nummer.")
        else:
            if dry_run_labels: st.dataframe(build_label_preview(target, p_number), use_container_width=True, hide_index=True)
            else:
                prev={}
                for k in target:
                    r=df_scope.loc[df_scope["Key"]==k].iloc[0]
                    prev[k]=[l.strip() for l in (r["Alle_Labels"].split(",") if r["Alle_Labels"] else []) if l.strip()]
                    new=[l for l in prev[k] if not is_p_label(l)]+[p_number]
                    try: jira.update_issue_labels(k,new)
                    except Exception as e: st.error(f"{k}: {e}")
                st.session_state.undo={"type":"labels","data":prev}; st.success(f"P {p_number} auf {len(target)} Ticket(s) angewandt."); refresh_after_update()
    if colbb2.button("Nur AUSWAHL zuweisen", key="pl_sel"):
        target=keys_select
        if not target: st.info("Keine Auswahl.")
        elif not p_number or not P_PATTERN.match(p_number): st.error("Ungültige P-Nummer.")
        else:
            if dry_run_labels: st.dataframe(build_label_preview(target, p_number), use_container_width=True, hide_index=True)
            else:
                prev={}
                for k in target:
                    r=df_scope.loc[df_scope["Key"]==k].iloc[0]
                    prev[k]=[l.strip() for l in (r["Alle_Labels"].split(",") if r["Alle_Labels"] else []) if l.strip()]
                    new=[l for l in prev[k] if not is_p_label(l)]+[p_number]
                    try: jira.update_issue_labels(k,new)
                    except Exception as e: st.error(f"{k}: {e}")
                st.session_state.undo={"type":"labels","data":prev}; st.success(f"P {p_number} auf {len(target)} Ticket(s) angewandt."); refresh_after_update()

with tab_worklog:
    st.subheader("Worklog (Einzel)")
    csel1,csel2=st.columns([2,1])
    issue_choice=csel1.selectbox("Ticket (aus Liste)", df["Key"].tolist() if not df.empty else [], key="wl_key_select")
    issue_direct=csel2.text_input("Oder Key direkt", value="", key="wl_key_direct")
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
        if not ensure_15min(seconds): st.error("Dauer muss Vielfaches von 15min sein und >0.")
        elif not use_key: st.error("Ticket-Key angeben.")
        else:
            try:
                wid=jira.add_worklog(use_key, to_started_iso(work_date, start_time), seconds, desc)
                st.session_state.undo={"type":"worklogs","data":[(use_key,wid)]}; st.success(f"Worklog für {use_key} erfasst.")
            except Exception as e: st.error(f"Fehler: {e}")

with tab_csv:
    st.subheader("CSV-Import Zeiterfassung")
    st.caption("Spalten: Ticketnummer;Datum;benötigte Zeit in h  | optional: Uhrzeit, Beschreibung")
    sample="Ticketnummer;Datum;benötigte Zeit in h;Uhrzeit;Beschreibung\nPROJ-101;21.08.2025;0,25;12:30;Daily Standup\nPROJ-202;21.08.2025;1.5;09:00;Konzept & Abstimmung\n"
    st.download_button("Beispiel-CSV herunterladen", data=sample.encode("utf-8"), file_name="worklog_beispiel.csv", mime="text/csv", key="csv_sample")
    default_desc=st.text_input("Standardbeschreibung (optional)", key="csv_default_desc")
    dry_run=st.checkbox("Nur validieren (Dry-Run)", value=True, key="csv_dryrun")
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
        col_hours=find_col("benötigte zeit in h","hours")
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
                if seconds%900!=0: errors.append(f"{key}: {h_float}h ist kein Vielfaches von 15 min"); continue
                if col_time and pd.notna(r[col_time]):
                    try: parsed_time=pd.to_datetime(str(r[col_time])).time()
                    except Exception: parsed_time=dtime(12,0)
                else: parsed_time=dtime(12,0)
                desc_val=""
                if col_desc and pd.notna(r[col_desc]): desc_val=str(r[col_desc]).strip()
                elif default_desc: desc_val=default_desc
                preview_rows.append({"Ticket":key,"Datum":d.isoformat(),"Startzeit":parsed_time.strftime("%H:%M"),"Dauer (min)":seconds//60,"Beschreibung":desc_val or "(leer)"})
            st.write("**Vorschau**"); df_prev=pd.DataFrame(preview_rows); st.dataframe(df_prev, use_container_width=True, hide_index=True)
            if errors:
                with st.expander("Fehler in CSV"):
                    for e in errors: st.write("• " + e)
            if preview_rows and st.button("Import starten", key="csv_import_btn"):
                if dry_run: st.info("Dry-Run aktiv – keine Daten geschrieben.")
                else:
                    ok=0; errs=[]; created=[]; prog=st.progress(0.0, text="Übertrage…")
                    for i,row in enumerate(preview_rows, start=1):
                        try:
                            started_iso=to_started_iso(pd.to_datetime(row["Datum"]).date(), datetime.strptime(row["Startzeit"], "%H:%M").time())
                            wid=jira.add_worklog(row["Ticket"], started_iso, int(row["Dauer (min)"])*60, None if row["Beschreibung"]=="(leer)" else row["Beschreibung"])
                            created.append((row["Ticket"],wid)); ok+=1
                        except Exception as e: errs.append(f"{row['Ticket']}: {e}")
                        prog.progress(i/len(preview_rows), text=f"Übertrage… ({i}/{len(preview_rows)})")
                    prog.empty(); st.success(f"Import: {ok}/{len(preview_rows)} Worklogs erstellt.")
                    if errs:
                        with st.expander("Fehlerdetails"):
                            for e in errs: st.write(e)
                    if created: st.session_state.undo={"type":"worklogs","data":created}

with tab_reports:
    st.subheader("Reports & Export")
    colr1,colr2=st.columns(2)
    with colr1:
        st.markdown("**Tickets ohne P-Label (aktuelle Auswahl)**")
        st.dataframe(df[df["P_Label_Aktuell"]==""][["Project","Key","Summary","Status"]], use_container_width=True, hide_index=True)
    with colr2:
        st.markdown("**Export Übersicht**")
        st.download_button("CSV herunterladen", data=df.to_csv(index=False).encode("utf-8"), file_name="tickets_uebersicht.csv", mime="text/csv", key="rep_csv")

with tab_timesheet:
    st.subheader("Wochenansicht / Timesheet")
    today=datetime.now().date()
    colts1,colts2,colts3,colts4=st.columns([2,1,1,2])
    wk_date=colts1.date_input("Woche auswählen (beliebiges Datum der Woche)", value=today, key="ts_date")
    if colts2.button("‹ Vorwoche", key="ts_prev"): st.session_state.ts_date=wk_date - timedelta(days=7); st.rerun()
    if colts3.button("Nächste Woche ›", key="ts_next"): st.session_state.ts_date=wk_date + timedelta(days=7); st.rerun()
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
        if df_ts.empty:
            df_ts = totals_df
        else:
            df_ts = pd.concat([df_ts, totals_df], ignore_index=True)
        cts1,cts2=st.columns([1,3]); cts1.metric("Wochensumme (h)", totals["Summe (h)"]); cts2.caption("Letzte Zeile: Tagessummen & Wochensumme")
        st.dataframe(df_ts, use_container_width=True, hide_index=True)
        st.download_button("Timesheet (CSV) herunterladen", data=df_ts.to_csv(index=False).encode("utf-8"), file_name=f"timesheet_{week_start.isoformat()}.csv", mime="text/csv", key="ts_export_csv")

with tab_health:
    st.subheader("Health-Check+")
    ok_msgs=[]; warn_msgs=[]
    def timed(fn,*a,**kw):
        t0=time.time()
        try: res=fn(*a,**kw); return time.time()-t0, res, None
        except Exception as e: return time.time()-t0, None, e
    # simple checks
    t_myself,_,e1=timed(jira.get_myself); ok_msgs.append(f"/myself ok ({t_myself*1000:.0f} ms)" if not e1 else f"/myself Fehler: {e1}")
    t_proj,_,e2=timed(jira.list_projects,None); ok_msgs.append(f"/project/search ok ({t_proj*1000:.0f} ms)" if not e2 else f"/project/search Fehler: {e2}")
    # headers + skew (timezone-aware)
    try:
        headers,status=jira.probe_headers(); rl=headers.get("X-RateLimit-Remaining") or headers.get("x-ratelimit-remaining") or "n/a"
        stime=headers.get("Date")
        skew="n/a"
        if stime:
            server_dt=pd.to_datetime(stime, utc=True).to_pydatetime()
            local_dt=datetime.now(timezone.utc)
            skew=f"{abs((server_dt-local_dt).total_seconds()):.0f}s"
        ok_msgs.append(f"Headers ok (Status {status}). RateLimit-Remaining: {rl}, Clock Skew ~ {skew}")
    except Exception as e: warn_msgs.append(f"Header-Check nicht möglich: {e}")
    st.success("✔ " + "\n\n✔ ".join(ok_msgs))
    if warn_msgs: st.warning("⚠ " + "\n\n⚠ ".join(warn_msgs))

st.markdown("---")
def refresh_after_update():
    fetch_issues_df.clear(); st.experimental_set_query_params(_=str(time.time())); st.rerun()
if st.session_state.get("undo"):
    u=st.session_state["undo"]
    if u["type"]=="labels":
        if st.button("↩️ Letzte Label-Änderung rückgängig machen", key="undo_labels"):
            prev=u["data"]; errs=[]
            for k,old in prev.items():
                try: jira.update_issue_labels(k, old)
                except Exception as e: errs.append(f"{k}: {e}")
            st.session_state.undo=None; st.success("Label-Änderung rückgängig gemacht."); refresh_after_update()
    elif u["type"]=="worklogs":
        if st.button("↩️ Letzte Worklogs rückgängig machen", key="undo_wl"):
            errs=[]
            for (k,wid) in u["data"]:
                try: jira.delete_worklog(k, wid)
                except Exception as e: errs.append(f"{k}/{wid}: {e}")
            st.session_state.undo=None
            if errs: st.error("Einige Worklogs konnten nicht gelöscht werden.")
            else: st.success("Worklogs gelöscht.")
