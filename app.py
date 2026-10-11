"""Enterprise DLP lab API: auth, RBAC, CSRF, audit trail, case management, analytics, configurable policies."""
import os, io, re, csv, pathlib, json, time, secrets, sqlite3, datetime as dt
import logging
from functools import wraps
from flask import Flask, request, jsonify, session, Response, g
from werkzeug.security import generate_password_hash, check_password_hash
import db as D
from dlp_engine import SCENARIOS, safe, scan_text, CATS, DEFAULT_POLICIES, SAMPLE, to_csv, daily_report
SEV=("Critical","High","Medium","Low"); STATUSES=("Open","Investigating","Escalated","Resolved","False Positive")
PRIO=("Low","Medium","High","Urgent"); ACTIONS=("alert","escalate","quarantine_sim"); ROLES=("admin","analyst","auditor")
PMAP={"Critical":"Urgent","High":"High","Medium":"Medium","Low":"Low"}
EXT={".txt",".log",".csv",".json",".md",".tsv",".xml"}; DATE=re.compile(r"\d{4}-\d{2}-\d{2}")
now=lambda: dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
s=lambda v,n=2000: str(v if v is not None else "").strip()[:n]
err=lambda m,c=400:(jsonify(error=m),c)
EDIT_TEXT=("root_cause","impact","remediation_taken","resolution","closure_reason")
PROD_DB="/var/data/dlp.db"; TRIO=(("admin","admin"),("analyst","analyst"),("auditor","auditor"))
def load_env():   # optional .env (never committed - see .gitignore); real environment variables win
    try:
        for ln in open(os.path.join(os.path.dirname(os.path.abspath(__file__)),".env"),encoding="utf-8"):
            ln=ln.strip()
            if ln and not ln.startswith("#") and "=" in ln: k,v=ln.split("=",1); os.environ.setdefault(k.strip(),v.strip().strip('"').strip("'"))
    except FileNotFoundError: pass
class _Redact(logging.Filter):   # request logs must never carry query strings (search text could contain sensitive values)
    def filter(self,rec):
        f=lambda v: re.sub(r"\?\S*","?<redacted>",v) if isinstance(v,str) else v
        rec.msg=f(rec.msg); rec.args=tuple(f(a) for a in rec.args) if isinstance(rec.args,tuple) else rec.args; return True

def create_app(db_path=None,demo_password=None):
    app=Flask(__name__,static_folder="static",static_url_path="")
    load_env(); prod=os.environ.get("DLP_ENV")=="production"
    path=db_path or os.environ.get("DB_PATH") or (PROD_DB if prod else "dlp.db")
    if prod:   # production database must live on the persistent disk
        if os.path.abspath(path)!=os.path.abspath(PROD_DB): raise RuntimeError(f"Production database path must be {PROD_DB} (got {path})")
        if not os.path.isdir(os.path.dirname(PROD_DB)) or not os.access(os.path.dirname(PROD_DB),os.W_OK): raise RuntimeError(f"{os.path.dirname(PROD_DB)} does not exist or is not writable - mount the persistent disk there")
    lg=logging.getLogger("werkzeug")
    if not any(isinstance(x,_Redact) for x in lg.filters): lg.addFilter(_Redact())
    D.migrate(path)
    kf=path+".secret"
    if not os.path.exists(kf):
        with open(kf,"w") as f: f.write(secrets.token_hex(32))
    app.config.update(SECRET_KEY=os.environ.get("SECRET_KEY") or pathlib.Path(kf).read_text().strip(),SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=prod or os.environ.get("DLP_HTTPS")=="1",PERMANENT_SESSION_LIFETIME=1800,MAX_CONTENT_LENGTH=25*1024*1024)
    DUMMY=generate_password_hash("not-a-real-password"); FAILS={}
    def db():
        if "db" not in g: g.db=D.connect(path)
        return g.db
    @app.teardown_appcontext
    def close(_):
        c=g.pop("db",None)
        if c: c.close()
    # ---- first-run bootstrap (users + default policies)
    c=D.connect(path)
    with c:
        if not c.execute("SELECT 1 FROM users").fetchone():
            env_pw=os.environ.get("DLP_INITIAL_ADMIN_PASSWORD","")
            if demo_password: seed,must=[(u,r,demo_password) for u,r in TRIO],0   # automated tests only
            elif env_pw:   # production path: only an admin, password from a secret env var, never printed or logged
                if len(env_pw)<10 or not re.search(r"[A-Za-z]",env_pw) or not re.search(r"\d",env_pw): raise RuntimeError("DLP_INITIAL_ADMIN_PASSWORD must be 10+ characters with letters and digits")
                seed,must=[("admin","admin",env_pw)],1
            elif prod: raise RuntimeError("Set DLP_INITIAL_ADMIN_PASSWORD (as a secret environment variable) to create the first admin account")
            else: seed,must=[(u,r,secrets.token_urlsafe(12)) for u,r in TRIO],1
            for u,r,pw in seed: c.execute("INSERT INTO users(username,pw_hash,role,active,created_at,must_change) VALUES(?,?,?,1,?,?)",(u,generate_password_hash(pw),r,now(),must))
            if not demo_password and not env_pw: print("\nDEVELOPMENT first run - temporary credentials (you must change them at first sign-in; never printed in production):\n"+"\n".join(f"  {u:8} ({r}): {pw}" for u,r,pw in seed)+"\n")
        if not c.execute("SELECT 1 FROM policies").fetchone():
            for p in DEFAULT_POLICIES: c.execute("INSERT INTO policies(name,description,category,severity,action,remediation,threshold,allowlist,enabled,updated_at) VALUES(?,?,?,?,?,?,?,?,1,?)",(p["name"],p["description"],p["category"],p["severity"],p["action"],p["remediation"],1,"[]",now()))
    c.close()
    # ---- request guards
    @app.before_request
    def guard():
        g.user=None
        if session.get("uid"):
            r=db().execute("SELECT id,username,role,must_change FROM users WHERE id=? AND active=1",(session["uid"],)).fetchone()
            g.user=dict(r) if r else None
        if g.user and g.user["must_change"] and request.path.startswith("/api/") and request.path not in("/api/me","/api/login","/api/logout","/api/me/password"):
            return jsonify(error="You must change your temporary password before continuing",must_change=True),403
        if request.path.startswith("/api/") and request.method in("POST","PUT","PATCH","DELETE") and request.path!="/api/login":
            tok=session.get("csrf") or ""
            if not g.user or not tok or not secrets.compare_digest(request.headers.get("X-CSRF-Token","")[:64],tok): return err("CSRF validation failed",403)
    @app.after_request
    def hdr(r):
        r.headers.update({"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Content-Security-Policy":"default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"})
        if request.path.startswith("/api/"): r.headers["Cache-Control"]="no-store"
        return r
    def need(*roles):
        def deco(f):
            @wraps(f)
            def w(*a,**k):
                if not g.user: return err("Authentication required",401)
                if g.user["role"] not in roles:
                    with db(): audit("ACCESS_DENIED",request.path,{"role":g.user["role"],"method":request.method})
                    return err("Insufficient permissions",403)
                return f(*a,**k)
            return w
        return deco
    def audit(action,target="",detail=None,actor=None):   # never receives raw sensitive values or passwords
        db().execute("INSERT INTO audit(ts,actor,action,target,detail) VALUES(?,?,?,?,?)",(now(),actor or (g.user["username"] if g.user else "anonymous"),action,str(target)[:120],json.dumps(detail or {},default=str)[:2000]))
    @app.errorhandler(404)
    def e404(e): return err("Not found",404) if request.path.startswith("/api/") else app.send_static_file("index.html")
    @app.errorhandler(405)
    def e405(e): return err("Method not allowed",405)
    @app.errorhandler(413)
    def e413(e): return err("Upload too large",413)
    @app.errorhandler(Exception)
    def e500(e):
        if hasattr(e,"code") and e.code: return err(getattr(e,"description","Error"),e.code)
        app.logger.exception("unhandled"); return err("Internal error",500)
    # ---- auth
    @app.post("/api/login")
    def login():
        d=request.get_json(silent=True) or {}; u=s(d.get("username"),64); p=str(d.get("password") or "")[:200]; key=(u.lower(),request.remote_addr); f=FAILS.get(key,(0,0))
        if f[0]>=5 and time.time()<f[1]:
            with db(): audit("LOGIN_BLOCKED","rate-limit",actor="unknown-user")
            return err("Too many failed attempts. Try again in a minute.",429)
        r=db().execute("SELECT * FROM users WHERE username=? AND active=1",(u,)).fetchone()
        ok=bool(r) and check_password_hash(r["pw_hash"],p)
        if not r: check_password_hash(DUMMY,p)
        who=u if r else "unknown-user"   # never log text typed into the username box for unknown users (could be a password)
        with db(): audit("LOGIN_SUCCESS" if ok else "LOGIN_FAILED",who,actor=who)
        if not ok: FAILS[key]=(f[0]+1,time.time()+60); return err("Invalid credentials",401)
        FAILS.pop(key,None); session.clear(); session.permanent=True; session["uid"]=r["id"]; session["csrf"]=secrets.token_hex(16)
        return jsonify(user=dict(username=r["username"],role=r["role"]),csrf=session["csrf"],must_change=bool(r["must_change"]))
    @app.post("/api/logout")
    def logout():
        if g.user:
            with db(): audit("LOGOUT",g.user["username"])
        session.clear(); return jsonify(ok=True)
    @app.get("/api/me")
    def me():
        if not g.user: return err("Not signed in",401)
        return jsonify(user={k:g.user[k] for k in("id","username","role")},csrf=session["csrf"],must_change=bool(g.user["must_change"]))
    @app.post("/api/me/password")
    def change_password():
        if not g.user: return err("Authentication required",401)
        d=request.get_json(silent=True) or {}; cur=str(d.get("current") or "")[:200]; new=str(d.get("new") or "")[:200]
        row=db().execute("SELECT pw_hash FROM users WHERE id=?",(g.user["id"],)).fetchone()
        if not check_password_hash(row["pw_hash"],cur):
            with db(): audit("PASSWORD_CHANGE_FAILED",g.user["username"])
            return err("Current password is incorrect")
        if not strong(new): return err("New password must be 10+ characters with letters and digits")
        if new==cur: return err("New password must be different from the current one")
        with db() as c: c.execute("UPDATE users SET pw_hash=?,must_change=0 WHERE id=?",(generate_password_hash(new),g.user["id"])); audit("PASSWORD_CHANGE",g.user["username"])
        return jsonify(ok=True)
    @app.get("/")
    def home(): return app.send_static_file("index.html")
    # ---- helpers
    def policies(only_enabled=True):
        rows=db().execute("SELECT * FROM policies"+(" WHERE enabled=1" if only_enabled else "")+" ORDER BY id").fetchall()
        return [dict(r,allowlist=json.loads(r["allowlist"] or "[]"),enabled=bool(r["enabled"])) for r in rows]
    def inc_out(r): d=dict(r); d["ref"]=f"INC-{d['id']:05d}"; d["case_id"]=f"CASE-{d['id']:05d}"; d.pop("vh",None); return d
    def flt(a):
        cl,pr=["1=1"],[]
        for k,col in (("status","i.status"),("severity","i.sev"),("category","i.type")):
            if a.get(k): cl.append(col+"=?"); pr.append(a[k])
        for k,op in (("from",">="),("to","<=")):
            if a.get(k) and DATE.fullmatch(a[k]): cl.append(f"substr(i.detected_at,1,10){op}?"); pr.append(a[k])
        if a.get("q"):
            cl.append("(i.type LIKE ? OR i.src LIKE ? OR COALESCE(i.policy_name,'') LIKE ? OR i.val LIKE ? OR ('INC-'||printf('%05d',i.id)) LIKE ?)"); pr+=[f"%{a['q'][:50]}%"]*5
        return " AND ".join(cl),pr
    def store(c,sid,incs,ts,channel=None,simu=None):
        for i in incs:
            st="Escalated" if i.get("action") in("escalate","quarantine_sim") else "Open"
            cur=c.execute("INSERT INTO incidents(scan_id,sev,type,val,src,line,rem,detected_at,status,priority,policy_id,policy_name,vh,created_at,updated_at,channel,sim_user) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(sid,i["sev"],i["type"],i["val"],i["src"],i["line"],i["rem"],ts,st,PMAP[i["sev"]],i["policy_id"],i["policy_name"],i["vh"],ts,ts,channel,simu))
            c.execute("INSERT INTO history(incident_id,ts,actor,from_status,to_status,note) VALUES(?,?,?,?,?,?)",(cur.lastrowid,ts,g.user["username"],None,st,"Created by policy: "+i["policy_name"]+(f" (response: {i['action']})" if st=="Escalated" else "")))
            i["id"]=cur.lastrowid
    # ---- scanning
    @app.get("/api/sample")
    @need("admin","analyst","auditor")
    def sample(): return jsonify(text=SAMPLE)
    @app.post("/api/scan")
    @need("admin","analyst")
    def scan():
        items=[]; t=request.form.get("text","")
        if len(t)>1_000_000: return err("Pasted text too large (max 1 MB)")
        if t.strip(): items.append(("pasted-text",t))
        files=request.files.getlist("files")
        if len(files)>20: return err("Maximum 20 files per scan")
        for f in files:
            name=os.path.basename(f.filename or "")[:120]
            if os.path.splitext(name)[1].lower() not in EXT: return err(f"Unsupported file type: {name or '(unnamed)'}")
            raw=f.read()
            if len(raw)>5*1024*1024: return err(f"{name}: file larger than 5 MB")
            try: txt=raw.decode("utf-8")
            except UnicodeDecodeError: return err(f"{name}: not valid UTF-8 text")
            if "\x00" in txt: return err(f"{name}: binary content rejected")
            items.append((name,txt))
        if not items: return err("Provide text or at least one file")
        pol=policies(); salt=app.config["SECRET_KEY"]; incs=[i for n,x in items for i in scan_text(x,n,pol,salt)]; ts=now()
        with db() as c:
            sid=c.execute("INSERT INTO scans(ts,total) VALUES(?,?)",(ts,len(incs))).lastrowid; store(c,sid,incs,ts)
            audit("SCAN_RUN",f"scan:{sid}",{"sources":len(items),"incidents":len(incs)})
        return jsonify(scan_id=sid,incidents=[{k:v for k,v in i.items() if k!="vh"} for i in incs])
    # ---- incidents / cases
    @app.get("/api/incidents")
    @need("admin","analyst","auditor")
    def incidents():
        w,pr=flt(request.args)
        rows=db().execute(f"SELECT i.*,u.username AS assignee FROM incidents i LEFT JOIN users u ON u.id=i.assignee_id WHERE {w} ORDER BY i.id DESC LIMIT 500",pr).fetchall()
        return jsonify([inc_out(r) for r in rows])
    @app.get("/api/incidents/<int:iid>")
    @need("admin","analyst","auditor")
    def incident(iid):
        c=db(); r=c.execute("SELECT i.*,u.username AS assignee FROM incidents i LEFT JOIN users u ON u.id=i.assignee_id WHERE i.id=?",(iid,)).fetchone()
        if not r: return err("Incident not found",404)
        return jsonify(incident=inc_out(r),notes=[dict(x) for x in c.execute("SELECT ts,actor,text FROM notes WHERE incident_id=? ORDER BY id DESC",(iid,))],history=[dict(x) for x in c.execute("SELECT ts,actor,from_status,to_status,note FROM history WHERE incident_id=? ORDER BY id DESC",(iid,))])
    @app.patch("/api/incidents/<int:iid>")
    @need("admin","analyst")
    def incident_update(iid):
        d=request.get_json(silent=True) or {}; c=db(); r=c.execute("SELECT * FROM incidents WHERE id=?",(iid,)).fetchone()
        if not r: return err("Incident not found",404)
        sets,pr,chg={},[],{}
        if "priority" in d:
            if d["priority"] not in PRIO: return err("Invalid priority")
            sets["priority"]=d["priority"]
        if "assignee_id" in d:
            a=d["assignee_id"] or None
            if a is not None and not c.execute("SELECT 1 FROM users WHERE id=? AND active=1 AND role IN('admin','analyst')",(a,)).fetchone(): return err("Invalid assignee")
            sets["assignee_id"]=a
        for k in EDIT_TEXT:
            if k in d: sets[k]=s(d[k])
        for k,v in sets.items():
            if (r[k] or None)!=(v or None): chg[k]=[r[k],v] if k in("priority","assignee_id") else "changed"
        if not chg: return jsonify(ok=True,changed=[])
        with c:
            c.execute("UPDATE incidents SET "+",".join(f"{k}=?" for k in sets)+",updated_at=? WHERE id=?",[*sets.values(),now(),iid])
            audit("INCIDENT_ASSIGN" if list(chg)==["assignee_id"] else "INCIDENT_UPDATE",f"INC-{iid:05d}",chg)
        return jsonify(ok=True,changed=list(chg))
    @app.post("/api/incidents/<int:iid>/status")
    @need("admin","analyst")
    def incident_status(iid):
        d=request.get_json(silent=True) or {}; st=s(d.get("status"),30); reason=s(d.get("reason")); c=db()
        r=c.execute("SELECT * FROM incidents WHERE id=?",(iid,)).fetchone()
        if not r: return err("Incident not found",404)
        if st not in STATUSES: return err("Invalid status")
        if st==r["status"]: return err("Incident already has this status")
        if r["status"] in("Resolved","False Positive") and st!="Open": return err("Closed incidents must be reopened first")
        closed=st in("Resolved","False Positive"); ts=now(); who=g.user["username"]; note=reason
        if st=="False Positive" and len(reason)<5: return err("A reason of at least 5 characters is required to mark a false positive")
        if st=="Open" and r["status"] in("Resolved","False Positive") and len(reason)<5: return err("A reason of at least 5 characters is required to reopen an incident")
        if st=="Resolved":   # a resolved incident must carry its real investigation record; the recorded reason is never blank
            res=reason if len(reason)>=5 else (r["resolution"] or "").strip()
            missing=[l for l,v in (("root-cause analysis",r["root_cause"]),("remediation action taken",r["remediation_taken"]),("resolution summary",res)) if len((v or "").strip())<5]
            if missing: return err("Before resolving, record: "+", ".join(missing)+" (save them in the investigation fields)")
            note=res
        with c:
            c.execute("UPDATE incidents SET status=?,updated_at=?,resolved_at=?,fp_reason=CASE WHEN ?='False Positive' THEN ? ELSE fp_reason END,resolution=CASE WHEN ?='Resolved' AND length(trim(COALESCE(resolution,'')))<5 THEN ? ELSE resolution END WHERE id=?",(st,ts,ts if closed else None,st,reason,st,note,iid))
            c.execute("INSERT INTO history(incident_id,ts,actor,from_status,to_status,note) VALUES(?,?,?,?,?,?)",(iid,ts,who,r["status"],st,note))
            audit("INCIDENT_REOPEN" if st=="Open" and closed is False and r["status"] in("Resolved","False Positive") else "INCIDENT_STATUS",f"INC-{iid:05d}",dict({"from":r["status"],"to":st},**({"reason":note[:200]} if note else {})))
        return jsonify(ok=True)
    @app.post("/api/incidents/<int:iid>/notes")
    @need("admin","analyst")
    def incident_note(iid):
        t=s((request.get_json(silent=True) or {}).get("text"))
        if not t: return err("Note text is required")
        if not db().execute("SELECT 1 FROM incidents WHERE id=?",(iid,)).fetchone(): return err("Incident not found",404)
        with db() as c:
            c.execute("INSERT INTO notes(incident_id,ts,actor,text) VALUES(?,?,?,?)",(iid,now(),g.user["username"],t)); audit("INCIDENT_NOTE",f"INC-{iid:05d}",{"length":len(t)})
        return jsonify(ok=True)
    @app.get("/api/staff")
    @need("admin","analyst","auditor")
    def staff(): return jsonify(staff=[dict(r) for r in db().execute("SELECT id,username,role FROM users WHERE active=1 AND role IN('admin','analyst') ORDER BY username")])
    # ---- analytics (all values computed from DB records)
    @app.get("/api/analytics")
    @need("admin","analyst","auditor")
    def analytics():
        w,pr=flt(request.args); c=db()
        grp=lambda e,t="":[dict(k=r[0],n=r[1]) for r in c.execute(f"SELECT {e} k,COUNT(*) n FROM incidents i WHERE {w} GROUP BY k {t}",pr)]
        status=grp("i.status"); cnt=lambda k:next((x["n"] for x in status if x["k"]==k),0); fp,res=cnt("False Positive"),cnt("Resolved")
        mttr=c.execute(f"SELECT AVG((julianday(i.resolved_at)-julianday(i.detected_at))*24) FROM incidents i WHERE {w} AND i.status='Resolved' AND i.resolved_at IS NOT NULL",pr).fetchone()[0]
        sw,sp=["1=1"],[]
        for k,op in (("from",">="),("to","<=")):
            if request.args.get(k) and DATE.fullmatch(request.args[k]): sw.append(f"substr(ts,1,10){op}?"); sp.append(request.args[k])
        return jsonify(total=sum(x["n"] for x in status),status=status,open=cnt("Open"),investigating=cnt("Investigating"),escalated=cnt("Escalated"),resolved=res,false_positive=fp,
            fp_rate=round(100*fp/(fp+res),1) if fp+res else None,mttr_hours=round(mttr,2) if mttr is not None else None,
            scans=c.execute(f"SELECT COUNT(*) FROM scans WHERE {' AND '.join(sw)}",sp).fetchone()[0],
            severity=grp("i.sev"),category=grp("i.type"),daily=grp("substr(i.detected_at,1,10)","ORDER BY k")[-60:],monthly=grp("substr(i.detected_at,1,7)","ORDER BY k")[-12:],
            policies=grp("COALESCE(i.policy_name,'(legacy rules)')","ORDER BY n DESC LIMIT 8"),sources=grp("i.src","ORDER BY n DESC LIMIT 8"),
            repeated=[dict(type=r[0],val=r[1],n=r[2]) for r in c.execute(f"SELECT i.type,MIN(i.val),COUNT(*) n FROM incidents i WHERE {w} AND i.vh IS NOT NULL GROUP BY i.vh HAVING n>1 ORDER BY n DESC LIMIT 8",pr)],
            definitions=dict(fp_rate="False Positive / (False Positive + Resolved), closed incidents only",mttr_hours="Average (resolved_at - detected_at) for Resolved incidents only; false positives excluded",scans="Number of scan runs, counted separately from incidents",repeated="Same salted value-hash seen in 2+ incidents (raw values are never stored)"))
    @app.get("/api/trend")   # v1 route kept: monthly total of incidents per scan month
    @need("admin","analyst","auditor")
    def trend():
        r=db().execute("SELECT substr(ts,1,7) m,SUM(total) t FROM scans GROUP BY m ORDER BY m DESC LIMIT 8").fetchall(); return jsonify([dict(month=x["m"],total=x["t"]) for x in reversed(r)])
    def latest():
        c=db(); sc=c.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        return [dict(r) for r in c.execute("SELECT id,sev,type,val,src,line,status,root_cause,impact,remediation_taken,resolution FROM incidents WHERE scan_id=?",(sc["id"],))] if sc else []
    @app.get("/api/export/incidents.csv")   # v1 route kept
    @need("admin","analyst","auditor")
    def exp():
        with db(): audit("REPORT_EXPORT","incidents.csv")
        return Response(to_csv(latest(),saved=True),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=dlp_incidents.csv"})
    @app.get("/api/export/all.csv")
    @need("admin","analyst","auditor")
    def exp_all():   # all incidents matching the same filters as the Incidents page; masked values only
        w,pr=flt(request.args)
        rows=db().execute(f"SELECT i.id,i.sev,i.status,i.priority,i.type,i.val,i.src,i.line,i.policy_name,u.username a,i.detected_at,i.resolved_at,i.root_cause,i.impact,i.remediation_taken,i.resolution FROM incidents i LEFT JOIN users u ON u.id=i.assignee_id WHERE {w} ORDER BY i.id",pr).fetchall()
        b=io.StringIO(); wr=csv.writer(b); wr.writerow(["Incident","Severity","Status","Priority","Category","Masked value","Source","Line","Policy","Assignee","Detected","Resolved","Root cause","Business impact","Remediation taken","Resolution"])
        for r in rows:
            v=list(r)[1:]; v[-4:]=[(x or "").strip() or "Not recorded" for x in v[-4:]]; wr.writerow([f"INC-{r['id']:05d}"]+[safe(x if x is not None else "") for x in v])
        with db(): audit("REPORT_EXPORT","all.csv",{"rows":len(rows)})
        return Response(b.getvalue(),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=dlp_all_incidents.csv"})
    @app.get("/api/report/daily.txt")   # v1 route kept
    @need("admin","analyst","auditor")
    def rep():
        with db(): audit("REPORT_EXPORT","daily.txt")
        return Response(daily_report(latest(),saved=True),mimetype="text/plain",headers={"Content-Disposition":"attachment; filename=dlp_daily_report.txt"})
    # ---- policies
    def pol_in(d):
        c=dict(name=s(d.get("name"),80),description=s(d.get("description"),300),category=s(d.get("category")),severity=s(d.get("severity")),action=s(d.get("action")),remediation=s(d.get("remediation"),500))
        if not c["name"]: return None,"Policy name is required"
        if c["category"] not in CATS: return None,"Unknown category"
        if c["severity"] not in SEV: return None,"Invalid severity"
        if c["action"] not in ACTIONS: return None,"Invalid response action"
        try: c["threshold"]=int(d.get("threshold",1)); assert 1<=c["threshold"]<=100
        except Exception: return None,"Threshold must be 1-100"
        al=d.get("allowlist") or []
        al=[s(a,100) for a in (al.splitlines() if isinstance(al,str) else al) if s(a,100)][:50]
        for a in al:
            if a.startswith("re:"):
                try: re.compile(a[3:])
                except re.error: return None,f"Invalid regex in allowlist: {a[:30]}"
        c["allowlist"]=json.dumps(al); c["enabled"]=1 if d.get("enabled",True) else 0; return c,None
    @app.get("/api/policies")
    @need("admin","analyst","auditor")
    def pol_list(): return jsonify(policies(False))
    @app.post("/api/policies")
    @need("admin")
    def pol_new():
        c,e=pol_in(request.get_json(silent=True) or {})
        if e: return err(e)
        try:
            with db() as x:
                pid=x.execute("INSERT INTO policies(name,description,category,severity,action,remediation,threshold,allowlist,enabled,updated_at) VALUES(:name,:description,:category,:severity,:action,:remediation,:threshold,:allowlist,:enabled,:ts)",dict(c,ts=now())).lastrowid
                audit("POLICY_CREATE",f"policy:{pid}",{"name":c["name"],"category":c["category"],"severity":c["severity"],"action":c["action"]})
        except sqlite3.IntegrityError: return err("A policy with this name already exists")
        return jsonify(id=pid)
    @app.put("/api/policies/<int:pid>")
    @need("admin")
    def pol_edit(pid):
        old=db().execute("SELECT * FROM policies WHERE id=?",(pid,)).fetchone()
        if not old: return err("Policy not found",404)
        c,e=pol_in(request.get_json(silent=True) or {})
        if e: return err(e)
        chg={k:[old[k],v] for k,v in c.items() if k!="allowlist" and old[k]!=v}
        if json.loads(old["allowlist"])!=json.loads(c["allowlist"]): chg["allowlist"]="changed"
        try:
            with db() as x:
                x.execute("UPDATE policies SET name=:name,description=:description,category=:category,severity=:severity,action=:action,remediation=:remediation,threshold=:threshold,allowlist=:allowlist,enabled=:enabled,updated_at=:ts WHERE id=:id",dict(c,ts=now(),id=pid))
                audit("POLICY_TOGGLE" if list(chg)==["enabled"] else "POLICY_UPDATE",f"policy:{pid}",chg)
        except sqlite3.IntegrityError: return err("A policy with this name already exists")
        return jsonify(ok=True)
    # ---- users
    @app.get("/api/users")
    @need("admin")
    def users(): return jsonify([dict(r) for r in db().execute("SELECT id,username,role,active,created_at FROM users ORDER BY id")])
    def strong(p): return len(p)>=10 and re.search(r"[A-Za-z]",p) and re.search(r"\d",p)
    @app.post("/api/users")
    @need("admin")
    def user_new():
        d=request.get_json(silent=True) or {}; u=s(d.get("username"),32); p=str(d.get("password") or ""); r=s(d.get("role"))
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}",u): return err("Username: 3-32 letters, digits, . _ -")
        if r not in ROLES: return err("Invalid role")
        if not strong(p): return err("Password must be 10+ characters with letters and digits")
        try:
            with db() as c: c.execute("INSERT INTO users(username,pw_hash,role,active,created_at,must_change) VALUES(?,?,?,1,?,1)",(u,generate_password_hash(p),r,now())); audit("USER_CREATE",u,{"role":r})
        except sqlite3.IntegrityError: return err("Username already exists")
        return jsonify(ok=True)
    @app.patch("/api/users/<int:uid>")
    @need("admin")
    def user_edit(uid):
        d=request.get_json(silent=True) or {}; c=db(); u=c.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
        if not u: return err("User not found",404)
        role=d.get("role",u["role"]); act=1 if d.get("active",bool(u["active"])) else 0
        if role not in ROLES: return err("Invalid role")
        if u["role"]=="admin" and u["active"] and (role!="admin" or not act) and c.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1 AND id!=?",(uid,)).fetchone()[0]==0: return err("Cannot remove the last active administrator")
        pw=d.get("password"); 
        if pw and not strong(str(pw)): return err("Password must be 10+ characters with letters and digits")
        with c:
            c.execute("UPDATE users SET role=?,active=?"+(",pw_hash=?,must_change=1" if pw else "")+" WHERE id=?",[role,act,*( [generate_password_hash(str(pw))] if pw else []),uid])
            if role!=u["role"] or act!=u["active"]: audit("USER_UPDATE",u["username"],{"role":[u["role"],role],"active":[u["active"],act]})
            if pw: audit("PASSWORD_RESET",u["username"])
        return jsonify(ok=True)
    # ---- audit trail (read-only: there is deliberately no write/delete route)
    @app.get("/api/audit")
    @need("admin","auditor")
    def audit_list():
        q=f"%{s(request.args.get('q'),50)}%"
        return jsonify([dict(r) for r in db().execute("SELECT ts,actor,action,target,detail FROM audit WHERE actor LIKE ? OR action LIKE ? OR target LIKE ? ORDER BY id DESC LIMIT 300",(q,q,q))])
    # ---- data-leakage simulator (synthetic events only; "quarantine" is a recorded simulation)
    CHANNELS=("email","file_upload","shared_document","app_log","usb_copy"); RANK={"alert":1,"escalate":2,"quarantine_sim":3}
    @app.get("/api/sim/scenarios")
    @need("admin","analyst","auditor")
    def sim_scn(): return jsonify(SCENARIOS)
    @app.get("/api/sim/events")
    @need("admin","analyst","auditor")
    def sim_events(): return jsonify([dict(r) for r in db().execute("SELECT * FROM sim_events ORDER BY id DESC LIMIT 100")])
    @app.post("/api/simulate")
    @need("admin","analyst")
    def simulate():
        d=request.get_json(silent=True) or {}; ch=s(d.get("channel"),30); name=s(d.get("name"),120); su=s(d.get("user"),64); txt=str(d.get("content") or "")
        if ch not in CHANNELS: return err("Invalid channel")
        if not name or not su: return err("Simulated user and event name are required")
        if not txt.strip() or len(txt)>200000: return err("Event content is required (max 200 KB)")
        incs=scan_text(txt,f"{ch}:{name}",policies(),app.config["SECRET_KEY"]); ts=now()
        act=max((i["action"] for i in incs),key=lambda a:RANK[a],default="none"); sev=min((i["sev"] for i in incs),key=SEV.index,default="")
        with db() as c:
            store(c,None,incs,ts,ch,su)
            eid=c.execute("INSERT INTO sim_events(ts,sim_user,channel,name,categories,policies,severity,action,quarantined,incident_ids,actor) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(ts,su,ch,name,", ".join(sorted({i["type"] for i in incs})),", ".join(sorted({i["policy_name"] for i in incs})),sev,act,1 if act=="quarantine_sim" else 0,",".join(str(i["id"]) for i in incs),g.user["username"])).lastrowid
            audit("SIM_EVENT",f"sim:{eid}",{"channel":ch,"user":su,"incidents":len(incs),"action":act})
        return jsonify(id=eid,action=act,severity=sev,quarantined=act=="quarantine_sim",incidents=[dict(id=i["id"],ref=f"INC-{i['id']:05d}",type=i["type"],sev=i["sev"],val=i["val"],policy=i["policy_name"]) for i in incs])
    # ---- security assessment & mitigation tracker (manual OWASP Top 10 tracker - NOT a scanner)
    OWASP=("A01 Broken Access Control","A02 Cryptographic Failures","A03 Injection","A04 Insecure Design","A05 Security Misconfiguration","A06 Vulnerable and Outdated Components","A07 Identification and Authentication Failures","A08 Software and Data Integrity Failures","A09 Security Logging and Monitoring Failures","A10 Server-Side Request Forgery")
    FST=("Open","In Progress","Mitigated","Accepted Risk"); RETEST=("Not retested","Passed","Failed")
    def fin_in(d):
        c=dict(title=s(d.get("title"),150),description=s(d.get("description")),component=s(d.get("component"),100),owasp=s(d.get("owasp")),risk=s(d.get("risk")),rationale=s(d.get("rationale")),mitigation=s(d.get("mitigation")),owner=s(d.get("owner"),64),due=s(d.get("due"),10),status=s(d.get("status") or "Open"),retest=s(d.get("retest") or "Not retested"),evidence=s(d.get("evidence"),500))
        if not c["title"]: return None,"Title is required"
        if c["owasp"] not in OWASP: return None,"Choose an OWASP Top 10 category"
        if c["risk"] not in SEV: return None,"Invalid risk rating"
        if c["status"] not in FST: return None,"Invalid status"
        if c["retest"] not in RETEST: return None,"Invalid retest outcome"
        if c["due"] and not DATE.fullmatch(c["due"]): return None,"Due date must be YYYY-MM-DD"
        return c,None
    @app.get("/api/findings")
    @need("admin","analyst","auditor")
    def fin_list(): return jsonify([dict(r) for r in db().execute("SELECT * FROM findings ORDER BY CASE risk WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,COALESCE(NULLIF(due,''),'9999'),id")])
    @app.post("/api/findings")
    @need("admin","analyst")
    def fin_new():
        c,e=fin_in(request.get_json(silent=True) or {})
        if e: return err(e)
        with db() as x:
            fid=x.execute("INSERT INTO findings(title,description,component,owasp,risk,rationale,mitigation,owner,due,status,retest,evidence,created_by,created_at,updated_at) VALUES(:title,:description,:component,:owasp,:risk,:rationale,:mitigation,:owner,:due,:status,:retest,:evidence,:by,:ts,:ts)",dict(c,by=g.user["username"],ts=now())).lastrowid
            audit("FINDING_CREATE",f"finding:{fid}",{"title":c["title"][:80],"owasp":c["owasp"],"risk":c["risk"]})
        return jsonify(id=fid)
    @app.put("/api/findings/<int:fid>")
    @need("admin","analyst")
    def fin_edit(fid):
        old=db().execute("SELECT * FROM findings WHERE id=?",(fid,)).fetchone()
        if not old: return err("Finding not found",404)
        c,e=fin_in(request.get_json(silent=True) or {})
        if e: return err(e)
        chg={k:([old[k],v] if k in("status","retest","risk","owner","due") else "changed") for k,v in c.items() if (old[k] or "")!=v}
        with db() as x:
            x.execute("UPDATE findings SET title=:title,description=:description,component=:component,owasp=:owasp,risk=:risk,rationale=:rationale,mitigation=:mitigation,owner=:owner,due=:due,status=:status,retest=:retest,evidence=:evidence,updated_at=:ts WHERE id=:id",dict(c,ts=now(),id=fid))
            if chg: audit("FINDING_UPDATE",f"finding:{fid}",chg)
        return jsonify(ok=True)
    # ---- investigation / policy / closure reports (masked values only; printable in the UI, CSV via format=csv)
    @app.get("/api/report")
    @need("admin","analyst","auditor")
    def report():
        a=request.args; ty=a.get("type","daily"); c=db(); today=dt.date.today().isoformat(); J="LEFT JOIN users u ON u.id=i.assignee_id"; nr=lambda col,al="":f"COALESCE(NULLIF(trim({al}{col}),''),'Not recorded')"
        if ty=="daily":
            d=a.get("date") or today
            if not DATE.fullmatch(d): return err("Invalid date (use YYYY-MM-DD)")
            title=f"Daily Incident Summary - {d}"; cols=["Incident","Detected","Severity","Category","Masked value","Source","Policy","Status","Assignee","Root cause","Business impact","Remediation taken","Resolution"]
            rows=c.execute(f"SELECT 'INC-'||printf('%05d',i.id),i.detected_at,i.sev,i.type,i.val,i.src,COALESCE(i.policy_name,'(legacy)'),i.status,COALESCE(u.username,''),{nr('root_cause','i.')},{nr('impact','i.')},{nr('remediation_taken','i.')},{nr('resolution','i.')} FROM incidents i {J} WHERE substr(i.detected_at,1,10)=? ORDER BY i.id",(d,)).fetchall()
        elif ty=="monthly":
            m=a.get("month") or today[:7]
            if not re.fullmatch(r"\d{4}-\d{2}",m): return err("Invalid month (use YYYY-MM)")
            title=f"Monthly Incident Trend - {m}"; cols=["Date","Total","Critical","High","Medium","Low","Resolved","False positives"]
            rows=c.execute("SELECT substr(detected_at,1,10),COUNT(*),SUM(sev='Critical'),SUM(sev='High'),SUM(sev='Medium'),SUM(sev='Low'),SUM(status='Resolved'),SUM(status='False Positive') FROM incidents WHERE substr(detected_at,1,7)=? GROUP BY 1 ORDER BY 1",(m,)).fetchall()
        elif ty=="policy":
            title="Policy Violation Summary"; cols=["Policy","Category","Incidents","Active","Resolved","False positives"]
            rows=c.execute("SELECT COALESCE(policy_name,'(legacy rules)'),type,COUNT(*),SUM(status IN('Open','Investigating','Escalated')),SUM(status='Resolved'),SUM(status='False Positive') FROM incidents GROUP BY 1,2 ORDER BY 3 DESC").fetchall()
        elif ty=="closure":
            title="Remediation & Closure Report"; cols=["Incident","Severity","Category","Status","Root cause","Business impact","Remediation taken","Resolution","Closure reason","False-positive reason","Detected","Closed"]
            rows=c.execute(f"SELECT 'INC-'||printf('%05d',id),sev,type,status,{nr('root_cause')},{nr('impact')},{nr('remediation_taken')},{nr('resolution')},{nr('closure_reason')},COALESCE(fp_reason,''),detected_at,COALESCE(resolved_at,'') FROM incidents WHERE status IN('Resolved','False Positive') ORDER BY id").fetchall()
        elif ty=="incident":
            try: iid=int(a.get("id"))
            except (TypeError,ValueError): return err("Invalid incident id")
            r=c.execute(f"SELECT i.*,u.username AS assignee FROM incidents i {J} WHERE i.id=?",(iid,)).fetchone()
            if not r: return err("Incident not found",404)
            title=f"Incident Investigation Report - INC-{iid:05d}"; cols=["Field","Value"]
            rows=[[k,r[v] if v else x] for k,v,x in [("Incident",None,f"INC-{iid:05d}"),("Case",None,f"CASE-{iid:05d}"),("Severity","sev",""),("Status","status",""),("Priority","priority",""),("Category","type",""),("Masked value","val",""),("Source","src",""),("Channel","channel",""),("Simulated user","sim_user",""),("Policy","policy_name",""),("Assignee","assignee",""),("Detected","detected_at",""),("Closed at","resolved_at",""),("Root cause","root_cause",""),("Business impact","impact",""),("Remediation taken","remediation_taken",""),("Resolution","resolution",""),("Closure reason","closure_reason",""),("False-positive reason","fp_reason","")]]
            rows+=[["History",f"{h['ts']} {h['actor']}: {h['from_status'] or '-'} -> {h['to_status']} {h['note'] or ''}"] for h in c.execute("SELECT * FROM history WHERE incident_id=? ORDER BY id",(iid,))]
            rows+=[["Note",f"{n['ts']} {n['actor']}: {n['text']}"] for n in c.execute("SELECT * FROM notes WHERE incident_id=? ORDER BY id",(iid,))]
        else: return err("Unknown report type")
        rows=[["" if v is None else v for v in r] for r in rows]
        if ty=="incident": rows=[[k,v if str(v).strip() else "Not recorded"] if k in("Root cause","Business impact","Remediation taken","Resolution","Closure reason") else [k,v] for k,v in rows]
        if a.get("format")=="csv":
            b=io.StringIO(); w=csv.writer(b); w.writerow(cols)
            for r in rows: w.writerow([safe(v) for v in r])
            with db(): audit("REPORT_EXPORT",ty,{"rows":len(rows)})
            return Response(b.getvalue(),mimetype="text/csv",headers={"Content-Disposition":f"attachment; filename=dlp_{ty}_report.csv"})
        with db(): audit("REPORT_VIEW",ty,{"rows":len(rows)})
        return jsonify(title=title,columns=cols,rows=rows)
    return app
if __name__=="__main__":
    create_app().run(host=os.environ.get("HOST","127.0.0.1"),port=int(os.environ.get("PORT",8000)))
