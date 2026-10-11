import unittest, tempfile, os, io, sqlite3, glob, datetime, logging, re
from unittest import mock
import db as D
import dlp_engine as E
from app import create_app
PW="Test-Passw0rd!xyz"
class Base(unittest.TestCase):
    def setUp(self):
        self.d=tempfile.TemporaryDirectory(ignore_cleanup_errors=True); self.path=os.path.join(self.d.name,"t.db")
        self.app=create_app(self.path,demo_password=PW); self.c=self.app.test_client(); self.csrf=None
    def tearDown(self): self.d.cleanup()
    def login(self,u="admin",pw=PW):
        r=self.c.post("/api/login",json=dict(username=u,password=pw))
        if r.status_code==200: self.csrf=r.json["csrf"]
        return r
    def post(self,url,**kw): return self.c.post(url,headers={"X-CSRF-Token":self.csrf or ""},**kw)
    def put(self,url,**kw): return self.c.put(url,headers={"X-CSRF-Token":self.csrf or ""},**kw)
    def patch(self,url,**kw): return self.c.patch(url,headers={"X-CSRF-Token":self.csrf or ""},**kw)
    def scan(self,t=E.SAMPLE): return self.post("/api/scan",data={"text":t})
    def audit(self): return self.c.get("/api/audit").json

class TestEngine(unittest.TestCase):
    def test_checksums(self): self.assertTrue(E.verhoeff(E._demo_aadhaar())); self.assertTrue(E.luhn("4111111111111111")); self.assertFalse(E.luhn("4111111111111112"))
    def test_categories(self): self.assertEqual({i["type"] for i in E.scan_text(E.SAMPLE)},{"Payment Card","Aadhaar","PAN","Phone (IN)","Email"})
    def test_invalid_checksum_and_plain_text(self):
        self.assertEqual(E.scan_text("card 4111 1111 1111 1112"),[]); self.assertEqual(E.scan_text("Meeting at 10am, order 42 shipped."),[])
    def test_severity(self):
        sev={i["type"]:i["sev"] for i in E.scan_text(E.SAMPLE)}
        self.assertEqual(sev,{"Payment Card":"Critical","Aadhaar":"Critical","PAN":"High","Phone (IN)":"Medium","Email":"Low"})
    def test_masking(self):
        out=str(E.scan_text(E.SAMPLE)); self.assertNotIn("4111 1111 1111 1111",out); self.assertNotIn("ABCPE1234F",out); self.assertNotIn(E._demo_aadhaar(),out)
        self.assertTrue(E.mask("4111 1111 1111 1111").endswith("1111"))
    def test_allowlist_and_threshold(self):
        p=[dict(E.DEFAULT_POLICIES[0],allowlist=["4111111111111111"]),dict(E.DEFAULT_POLICIES[4],threshold=3)]
        self.assertEqual(E.scan_text("4111 1111 1111 1111 a@example.com b@example.com",policies=p),[])
        self.assertEqual(len(E.scan_text("a@example.com b@example.com c@example.com",policies=p)),3)

class TestAuth(Base):
    def test_login_and_failures_audited(self):
        self.assertEqual(self.login(pw="wrong-password").status_code,401); self.assertEqual(self.login().status_code,200)
        acts=[a["action"] for a in self.audit()]; self.assertIn("LOGIN_FAILED",acts); self.assertIn("LOGIN_SUCCESS",acts)
    def test_requires_login_and_csrf(self):
        self.assertEqual(self.c.get("/api/incidents").status_code,401); self.login()
        self.assertEqual(self.c.post("/api/scan",data={"text":"x"}).status_code,403)   # no CSRF header
    def test_lockout(self):
        for _ in range(5): self.login(pw="bad-password-1")
        self.assertEqual(self.login().status_code,429)
    def test_rbac(self):
        self.login("auditor"); self.assertEqual(self.scan().status_code,403); self.assertEqual(self.c.get("/api/users").status_code,403)
        self.assertEqual(self.c.get("/api/audit").status_code,200); self.assertEqual(self.c.get("/api/incidents").status_code,200)
        self.login("analyst"); self.assertEqual(self.post("/api/policies",json={}).status_code,403); self.assertEqual(self.c.get("/api/audit").status_code,403)
        self.assertEqual(self.scan().status_code,200)
    def test_audit_is_read_only(self):
        self.login(); self.assertEqual(self.put("/api/audit",json={}).status_code,405); self.assertEqual(self.c.delete("/api/audit",headers={"X-CSRF-Token":self.csrf}).status_code,405)

class TestCases(Base):
    def setUp(self): super().setUp(); self.login("analyst"); self.scan(); self.iid=self.c.get("/api/incidents?category=PAN").json[0]["id"]
    def test_persistence_across_restart(self):
        self.patch(f"/api/incidents/{self.iid}",json=dict(root_cause="Shared drive",priority="Urgent")); self.post(f"/api/incidents/{self.iid}/notes",json=dict(text="Contacted owner"))
        c2=create_app(self.path,demo_password=PW).test_client(); r=c2.post("/api/login",json=dict(username="analyst",password=PW)); self.assertEqual(r.status_code,200)
        d=c2.get(f"/api/incidents/{self.iid}").json; self.assertEqual(d["incident"]["root_cause"],"Shared drive"); self.assertEqual(d["incident"]["priority"],"Urgent"); self.assertEqual(d["notes"][0]["text"],"Contacted owner")
    def test_ids_and_defaults(self):
        i=self.c.get(f"/api/incidents/{self.iid}").json["incident"]; self.assertTrue(i["ref"].startswith("INC-")); self.assertTrue(i["case_id"].startswith("CASE-")); self.assertIn(i["status"],("Open","Escalated"))
    def test_false_positive_flow(self):
        u=f"/api/incidents/{self.iid}/status"
        self.assertEqual(self.post(u,json=dict(status="False Positive")).status_code,400)   # reason required
        self.assertEqual(self.post(u,json=dict(status="False Positive",reason="Test data")).status_code,200)
        self.assertEqual(self.post(u,json=dict(status="Investigating")).status_code,400)   # must reopen first
        self.assertEqual(self.post(u,json=dict(status="Open",reason="Reviewed again")).status_code,200)
        d=self.c.get(f"/api/incidents/{self.iid}").json; self.assertEqual(d["incident"]["status"],"Open"); self.assertEqual(len(d["history"]),3)
        self.assertIn("INCIDENT_REOPEN",[a["action"] for a in (self.login() and self.audit())])
    def test_resolution_and_analytics(self):
        u=f"/api/incidents/{self.iid}/status"; self.assertEqual(self.post(u,json=dict(status="Resolved")).status_code,400)
        self.assertEqual(self.post(u,json=dict(status="Resolved",reason="PAN masked in source")).status_code,400)   # root cause / remediation not recorded yet
        self._document(); self.assertEqual(self.post(u,json=dict(status="Resolved")).status_code,200)
        a=self.c.get("/api/analytics").json; self.assertEqual(a["resolved"],1); self.assertIsNotNone(a["mttr_hours"]); self.assertEqual(a["scans"],1); self.assertEqual(a["total"],5)
        self.assertEqual(sum(x["n"] for x in a["severity"]),5); self.assertEqual(a["monthly"][0]["n"],5)
    def _document(self,**kw):
        f=dict(root_cause="PAN pasted into support ticket by agent",impact="Customer PAN visible to 40 staff for 2 days",remediation_taken="Redacted ticket and rotated access list",resolution="PAN removed and agents retrained"); f.update(kw)
        self.assertEqual(self.patch(f"/api/incidents/{self.iid}",json=f).status_code,200); return f
    def test_resolve_records_meaningful_reason(self):   # Issue A
        f=self._document(); u=f"/api/incidents/{self.iid}/status"
        self.assertEqual(self.post(u,json=dict(status="Resolved")).status_code,200)   # empty reason box falls back to the saved resolution summary
        self.assertEqual(self.c.get(f"/api/incidents/{self.iid}").json["history"][0]["note"],f["resolution"])
        self.login(); a=[x for x in self.audit() if x["action"]=="INCIDENT_STATUS" and x["target"]==f"INC-{self.iid:05d}"][0]; self.assertIn(f["resolution"],a["detail"]); self.assertNotIn('"reason": ""',a["detail"])
    def test_resolve_requires_investigation_details(self):
        u=f"/api/incidents/{self.iid}/status"; r=self.post(u,json=dict(status="Resolved",reason="done and dusted")); self.assertEqual(r.status_code,400); self.assertIn("root-cause",r.json["error"])
        self._document(impact=""); self.assertEqual(self.post(u,json=dict(status="Resolved")).status_code,200)   # business impact is optional; reports show "Not recorded"
    def test_blank_or_trivial_reasons_rejected(self):
        u=f"/api/incidents/{self.iid}/status"
        for bad in ("","   ","no"): self.assertEqual(self.post(u,json=dict(status="False Positive",reason=bad)).status_code,400)
    def test_reports_use_saved_details(self):   # Issue B
        f=self._document(); self.post(f"/api/incidents/{self.iid}/status",json=dict(status="Resolved"))
        flat=" ".join(map(str,self.c.get("/api/report?type=closure").json["rows"][0]))
        for k in("root_cause","impact","remediation_taken","resolution"): self.assertIn(f[k],flat)
        inc=dict((x[0],x[1]) for x in self.c.get(f"/api/report?type=incident&id={self.iid}").json["rows"] if x[0] not in("History","Note")); self.assertEqual(inc["Root cause"],f["root_cause"]); self.assertEqual(inc["Business impact"],f["impact"])
        d=self.c.get("/api/report?type=daily&date="+datetime.date.today().isoformat()).json; self.assertIn("Business impact",d["columns"]); self.assertIn(f["remediation_taken"],str(d["rows"]))
        txt=self.c.get("/api/report/daily.txt").get_data(as_text=True); self.assertIn(f["remediation_taken"],txt); self.assertIn("Not recorded",txt); self.assertNotIn("Mask PAN in documents",txt)
        cs=self.c.get("/api/export/incidents.csv").get_data(as_text=True); self.assertIn(f["root_cause"],cs); self.assertNotIn("Mask PAN in documents",cs)
        al=self.c.get("/api/export/all.csv").get_data(as_text=True); self.assertIn(f["impact"],al); self.assertIn("Not recorded",al)
    def test_audit_has_no_sensitive_values(self):
        self.login(); blob=str(self.audit()); self.assertNotIn("4111",blob); self.assertNotIn("ABCPE1234F",blob); self.assertNotIn(PW,blob)
        acts=[a["action"] for a in self.audit()]; self.assertIn("SCAN_RUN",acts)
    def test_invalid_input(self):
        self.assertEqual(self.patch(f"/api/incidents/{self.iid}",json=dict(priority="Nope")).status_code,400)
        self.assertEqual(self.patch("/api/incidents/99999",json=dict(priority="Low")).status_code,404)
        self.assertEqual(self.post(f"/api/incidents/{self.iid}/notes",json=dict(text="  ")).status_code,400)
    def test_exports_masked(self):
        r=self.c.get("/api/export/incidents.csv"); self.assertEqual(r.status_code,200); t=r.get_data(as_text=True); self.assertNotIn("4111 1111",t); self.assertIn("1111",t)
    def test_export_all_csv_filtered_masked_audited(self):
        r=self.c.get("/api/export/all.csv?category=PAN"); txt=r.get_data(as_text=True)
        self.assertEqual(r.status_code,200); self.assertEqual(len(txt.strip().splitlines()),2); self.assertIn("INC-",txt); self.assertNotIn("ABCPE1234F",txt)
        self.login(); self.assertIn("REPORT_EXPORT",[a["action"] for a in self.audit()])
    def test_upload_validation(self):
        self.assertEqual(self.post("/api/scan",data={"files":(io.BytesIO(b"MZ"),"x.exe")},content_type="multipart/form-data").status_code,400)
        self.assertEqual(self.post("/api/scan",data={"files":(io.BytesIO(b"\xff\xfe\x00"),"x.txt")},content_type="multipart/form-data").status_code,400)
        self.assertEqual(self.post("/api/scan",data={}).status_code,400)
        self.assertEqual(self.post("/api/scan",data={"files":(io.BytesIO(b"mail a@example.com"),"ok.log")},content_type="multipart/form-data").status_code,200)

class TestPolicies(Base):
    def test_disable_policy_stops_detection_and_is_audited(self):
        self.login(); pol=[p for p in self.c.get("/api/policies").json if p["category"]=="Email"][0]
        self.assertEqual(self.put(f"/api/policies/{pol['id']}",json=dict(pol,enabled=False)).status_code,200)
        self.assertNotIn("Email",{i["type"] for i in self.scan().json["incidents"]}); self.assertIn("POLICY_TOGGLE",[a["action"] for a in self.audit()])
    def test_policy_validation_and_create(self):
        self.login(); base=dict(name="Test",category="PAN",severity="Low",action="alert",threshold=1)
        self.assertEqual(self.post("/api/policies",json=dict(base,severity="Huge")).status_code,400); self.assertEqual(self.post("/api/policies",json=dict(base,allowlist=["re:(["])).status_code,400)
        self.assertEqual(self.post("/api/policies",json=base).status_code,200); self.assertEqual(self.post("/api/policies",json=base).status_code,400)  # duplicate name
    def test_policy_action_escalates(self):
        self.login(); r=self.scan("Aadhaar "+E._demo_aadhaar()); iid=r.json["incidents"][0]["id"]
        self.assertEqual(self.c.get(f"/api/incidents/{iid}").json["incident"]["status"],"Escalated")
    def test_policy_allowlist_via_api(self):
        self.login(); pol=[p for p in self.c.get("/api/policies").json if p["category"]=="PAN"][0]
        self.put(f"/api/policies/{pol['id']}",json=dict(pol,allowlist="ABCPE1234F")); self.assertEqual(self.scan("PAN ABCPE1234F").json["incidents"],[])

class TestUsersAndMigration(Base):
    def test_user_management(self):
        self.login(); self.assertEqual(self.post("/api/users",json=dict(username="x",password="short",role="analyst")).status_code,400)
        self.assertEqual(self.post("/api/users",json=dict(username="newbie",password="LongPassw0rd!!",role="analyst")).status_code,200)
        admin=[u for u in self.c.get("/api/users").json if u["username"]=="admin"][0]
        self.assertEqual(self.patch(f"/api/users/{admin['id']}",json=dict(role="analyst")).status_code,400)   # last admin protected
        self.assertIn("USER_CREATE",[a["action"] for a in self.audit()])
    def test_empty_analytics(self):
        self.login(); a=self.c.get("/api/analytics").json; self.assertEqual(a["total"],0); self.assertIsNone(a["mttr_hours"]); self.assertIsNone(a["fp_rate"])
    def test_v1_migration_preserves_data(self):
        p=os.path.join(self.d.name,"old.db"); c=sqlite3.connect(p)
        c.executescript("CREATE TABLE scans(id INTEGER PRIMARY KEY,ts TEXT,total INT);CREATE TABLE incidents(id INTEGER PRIMARY KEY,scan_id INT,sev TEXT,type TEXT,val TEXT,src TEXT,line INT,rem TEXT);")
        c.execute("INSERT INTO scans VALUES(1,'2026-09-05T10:00:00+00:00',1)"); c.execute("INSERT INTO incidents VALUES(1,1,'High','PAN','******234F','a.txt',2,'Mask it')"); c.commit(); c.close()
        cl=create_app(p,demo_password=PW).test_client(); cl.post("/api/login",json=dict(username="admin",password=PW))
        r=cl.get("/api/incidents").json; self.assertEqual(len(r),1); self.assertEqual(r[0]["status"],"Open"); self.assertEqual(r[0]["detected_at"][:10],"2026-09-05")
        self.assertTrue(glob.glob(p+".bak-*"))
class TestEnterprise(Base):
    def test_simulator(self):
        self.login("analyst"); sc=self.c.get("/api/sim/scenarios").json; self.assertGreaterEqual(len(sc),5); s=sc[0]
        r=self.post("/api/simulate",json=dict(user=s["user"],channel=s["channel"],name=s["event"],content=s["content"])); self.assertEqual(r.status_code,200)
        self.assertEqual(r.json["action"],"quarantine_sim"); self.assertTrue(r.json["quarantined"])
        i=self.c.get("/api/incidents").json[0]; self.assertEqual(i["status"],"Escalated"); self.assertEqual(i["channel"],"email"); self.assertEqual(i["sim_user"],s["user"])
        self.assertEqual(self.post("/api/simulate",json=dict(user="u",channel="app_log",name="clean",content="nothing sensitive")).json["action"],"none")
        self.assertEqual(self.post("/api/simulate",json=dict(user="u",channel="fax",name="x",content="y")).status_code,400)
        self.assertEqual(len(self.c.get("/api/sim/events").json),2)
        self.login("auditor"); self.assertEqual(self.c.get("/api/sim/events").status_code,200); self.assertEqual(self.post("/api/simulate",json=dict(user="u",channel="email",name="x",content="y")).status_code,403)
        self.login(); self.assertIn("SIM_EVENT",[a["action"] for a in self.audit()])
    def test_reports(self):
        self.login("analyst"); self.scan(); today=datetime.date.today().isoformat()
        d=self.c.get(f"/api/report?type=daily&date={today}").json; self.assertEqual(len(d["rows"]),5); self.assertIn("Daily",d["title"])
        self.assertEqual(self.c.get("/api/report?type=monthly&month="+today[:7]).json["rows"][0][1],5)
        self.assertEqual(len(self.c.get("/api/report?type=policy").json["rows"]),5); self.assertEqual(self.c.get("/api/report?type=closure").json["rows"],[])
        iid=self.c.get("/api/incidents").json[0]["id"]; self.assertTrue(any(x[0]=="History" for x in self.c.get(f"/api/report?type=incident&id={iid}").json["rows"]))
        r=self.c.get(f"/api/report?type=daily&date={today}&format=csv"); t=r.get_data(as_text=True); self.assertEqual(r.status_code,200); self.assertNotIn("4111 1111",t); self.assertNotIn("ABCPE1234F",t)
        self.assertEqual(self.c.get("/api/report?type=daily&date=bad").status_code,400); self.assertEqual(self.c.get("/api/report?type=nope").status_code,400)
        self.login(); acts=[a["action"] for a in self.audit()]; self.assertIn("REPORT_EXPORT",acts); self.assertIn("REPORT_VIEW",acts)
    def test_findings_tracker(self):
        self.login("analyst"); b=dict(title="No rate limit on login",owasp="A07 Identification and Authentication Failures",risk="High",component="Login API",mitigation="Add lockout",owner="analyst",due="2026-12-01")
        self.assertEqual(self.post("/api/findings",json=dict(b,owasp="Nope")).status_code,400); self.assertEqual(self.post("/api/findings",json=dict(b,due="soon")).status_code,400)
        fid=self.post("/api/findings",json=b).json["id"]; self.assertEqual(self.put(f"/api/findings/{fid}",json=dict(b,status="Mitigated",retest="Passed")).status_code,200)
        f=self.c.get("/api/findings").json[0]; self.assertEqual((f["status"],f["retest"]),("Mitigated","Passed"))
        self.login("auditor"); self.assertEqual(self.c.get("/api/findings").status_code,200); self.assertEqual(self.post("/api/findings",json=b).status_code,403)
        self.login(); self.assertIn("FINDING_UPDATE",[a["action"] for a in self.audit()])
ALL=("admin","analyst","auditor"); AA=("admin","analyst"); AD=("admin",); AU=("admin","auditor")
MATRIX={("GET","/api/sample"):ALL,("POST","/api/scan"):AA,("GET","/api/incidents"):ALL,("GET","/api/incidents/<int:iid>"):ALL,("PATCH","/api/incidents/<int:iid>"):AA,
 ("POST","/api/incidents/<int:iid>/status"):AA,("POST","/api/incidents/<int:iid>/notes"):AA,("GET","/api/staff"):ALL,("GET","/api/analytics"):ALL,("GET","/api/trend"):ALL,
 ("GET","/api/export/incidents.csv"):ALL,("GET","/api/export/all.csv"):ALL,("GET","/api/report/daily.txt"):ALL,("GET","/api/report"):ALL,("GET","/api/policies"):ALL,
 ("POST","/api/policies"):AD,("PUT","/api/policies/<int:pid>"):AD,("GET","/api/users"):AD,("POST","/api/users"):AD,("PATCH","/api/users/<int:uid>"):AD,("GET","/api/audit"):AU,
 ("GET","/api/sim/scenarios"):ALL,("GET","/api/sim/events"):ALL,("POST","/api/simulate"):AA,("GET","/api/findings"):ALL,("POST","/api/findings"):AA,("PUT","/api/findings/<int:fid>"):AA}
PUBLIC={("POST","/api/login"),("POST","/api/logout"),("GET","/api/me"),("POST","/api/me/password")}
class TestHardening(Base):
    def test_every_api_route_enforces_roles_on_the_backend(self):
        rules=[(m,r.rule) for r in self.app.url_map.iter_rules() if r.rule.startswith("/api/") for m in r.methods-{"HEAD","OPTIONS"}]
        for k in rules:
            if k not in PUBLIC: self.assertIn(k,MATRIX,f"{k} is missing from the permission matrix")
        for k in MATRIX: self.assertIn(k,rules,f"stale matrix entry {k}")
        def call(cl,csrf,m,rule):
            url=re.sub(r"<int:\w+>","1",rule); h={"X-CSRF-Token":csrf}
            return cl.open(url,method=m,headers=h) if m=="GET" else cl.open(url,method=m,headers=h,json={})
        anon=self.app.test_client()
        for (m,rule) in MATRIX: self.assertIn(call(anon,"",m,rule).status_code,(401,403),f"anonymous reached {m} {rule}")
        for role in ALL:
            cl=self.app.test_client(); csrf=cl.post("/api/login",json=dict(username=role,password=PW)).json["csrf"]
            for (m,rule),allowed in MATRIX.items():
                st=call(cl,csrf,m,rule).status_code
                if role in allowed: self.assertNotIn(st,(401,403),f"{role} should be allowed {m} {rule} (got {st})")
                else: self.assertEqual(st,403,f"{role} must be denied {m} {rule} (got {st})")
    def test_failed_login_never_logs_what_was_typed(self):
        self.c.post("/api/login",json=dict(username="Sup3rSecret!Pass9xyz",password="Another-Secret-77")); self.c.post("/api/login",json=dict(username="admin",password="Wrong-Passw0rd-1"))
        self.login(); blob=str(self.audit())
        for bad in("Sup3rSecret","Another-Secret","Wrong-Passw0rd",PW): self.assertNotIn(bad,blob)
    def test_request_log_query_strings_are_redacted(self):
        f=[x for x in logging.getLogger("werkzeug").filters if x.__class__.__name__=="_Redact"][0]
        rec=logging.LogRecord("werkzeug",20,"",0,'%s - - [%s] "%s" %s -',("127.0.0.1","t","GET /api/incidents?q=4111111111111111 HTTP/1.1",200),None); f.filter(rec)
        out=rec.getMessage(); self.assertNotIn("4111",out); self.assertIn("/api/incidents",out)
    def test_new_and_reset_accounts_must_change_password(self):
        self.login(); self.post("/api/users",json=dict(username="newbie",password="Temp-Passw0rd-1",role="analyst"))
        cl=self.app.test_client(); r=cl.post("/api/login",json=dict(username="newbie",password="Temp-Passw0rd-1")); self.assertTrue(r.json["must_change"]); h={"X-CSRF-Token":r.json["csrf"]}
        b=cl.get("/api/incidents"); self.assertEqual(b.status_code,403); self.assertTrue(b.json["must_change"])
        for body in(dict(current="wrong",new="Brand-New-Pass9"),dict(current="Temp-Passw0rd-1",new="short"),dict(current="Temp-Passw0rd-1",new="Temp-Passw0rd-1")): self.assertEqual(cl.post("/api/me/password",headers=h,json=body).status_code,400)
        self.assertEqual(cl.post("/api/me/password",headers=h,json=dict(current="Temp-Passw0rd-1",new="Brand-New-Pass9")).status_code,200); self.assertEqual(cl.get("/api/incidents").status_code,200)
        self.assertEqual(self.app.test_client().post("/api/login",json=dict(username="newbie",password="Temp-Passw0rd-1")).status_code,401)
        blob=str(self.audit()); self.assertIn("PASSWORD_CHANGE",blob)
        for p in("Temp-Passw0rd","Brand-New-Pass9"): self.assertNotIn(p,blob)
    def test_initial_admin_from_environment_is_not_printed_and_must_be_changed(self):
        with mock.patch.dict(os.environ,{"DLP_INITIAL_ADMIN_PASSWORD":"Init-Passw0rd-9"}): cl=create_app(os.path.join(self.d.name,"env.db")).test_client()
        r=cl.post("/api/login",json=dict(username="admin",password="Init-Passw0rd-9")); self.assertEqual(r.status_code,200); self.assertTrue(r.json["must_change"])
        self.assertEqual(cl.post("/api/login",json=dict(username="analyst",password="Init-Passw0rd-9")).status_code,401)   # only the admin exists
        with mock.patch.dict(os.environ,{"DLP_INITIAL_ADMIN_PASSWORD":"weak"}): self.assertRaises(RuntimeError,create_app,os.path.join(self.d.name,"w.db"))
    def test_production_database_path_and_secrets_policy(self):
        env={"DLP_ENV":"production","DLP_INITIAL_ADMIN_PASSWORD":"Init-Passw0rd-9"}
        with mock.patch.dict(os.environ,env):
            os.environ.pop("DB_PATH",None)
            with self.assertRaises(RuntimeError) as e: create_app(os.path.join(self.d.name,"p.db"))
            self.assertIn("/var/data/dlp.db",str(e.exception))
            if not os.path.isdir("/var/data"):
                with self.assertRaises(RuntimeError) as e2: create_app()
                self.assertIn("/var/data",str(e2.exception))
    def test_backup_is_consistent_and_rotates(self):
        self.login("analyst"); self.scan(); bk=os.path.join(self.d.name,"bk")
        files=[D.backup(self.path,bk,keep=2)[0] for _ in range(3)]
        left=glob.glob(os.path.join(bk,"dlp-*.db")); self.assertEqual(len(left),2); self.assertNotIn(files[0],left)
        c=sqlite3.connect(files[2]); self.assertEqual(c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],5); self.assertEqual(c.execute("PRAGMA integrity_check").fetchone()[0],"ok"); c.close()
if __name__=="__main__": unittest.main()
