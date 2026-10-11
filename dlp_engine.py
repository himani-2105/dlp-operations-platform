"""DLP detection engine, now policy-driven. scan_text(text, src) still works with built-in default policies.
Note: checksum/format validity does NOT prove a real identity or an active card - it only reduces false positives."""
import re, csv, io, sys, pathlib, hashlib, datetime as dt
D=[[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
P=[[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
def verhoeff(s):
    c=0
    for i,ch in enumerate(reversed(s)): c=D[c][P[i%8][int(ch)]]
    return c==0
def luhn(s):
    t,alt=0,False
    for ch in reversed(s):
        n=int(ch)
        if alt:
            n*=2
            if n>9: n-=9
        t+=n; alt=not alt
    return t%10==0
digits=lambda v: re.sub(r"\D","",v)
CATS={
 "Payment Card":(re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),lambda v:13<=len(digits(v))<=19 and luhn(digits(v))),
 "Aadhaar":(re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"),lambda v:verhoeff(digits(v))),
 "PAN":(re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),lambda v:v[3] in "ABCFGHJLPT"),
 "Phone (IN)":(re.compile(r"(?<!\d)(?:\+91[ -]?)?[6-9]\d{9}(?!\d)"),lambda v:True),
 "Email":(re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),lambda v:True)}
def _p(name,cat,sev,act,rem,desc): return dict(name=name,category=cat,severity=sev,action=act,remediation=rem,description=desc,threshold=1,allowlist=[],enabled=1)
DEFAULT_POLICIES=[
 _p("PCI Card Data Exposure","Payment Card","Critical","quarantine_sim","PCI-DSS violation: remove card data from plaintext, tokenise/encrypt, restrict access and purge from logs.","Checksum-valid payment card numbers in unprotected content."),
 _p("Aadhaar Number Exposure","Aadhaar","Critical","escalate","UIDAI/DPDP Act violation: remove or mask (last 4 only), restrict access, notify the data owner.","Verhoeff-valid Aadhaar numbers."),
 _p("PAN Exposure","PAN","High","alert","Mask PAN in documents and logs, restrict share permissions, encrypt at rest.","Permanent Account Number format with valid entity-type character."),
 _p("Personal Phone Exposure","Phone (IN)","Medium","alert","Limit exposure of personal contact data; share on a need-to-know basis.","Indian mobile numbers."),
 _p("Personal Email Exposure","Email","Low","alert","Confirm purpose of storage; avoid bulk exposure of personal email addresses.","Email addresses.")]
RULES=[(p["category"],p["severity"],CATS[p["category"]][0],CATS[p["category"]][1],p["remediation"]) for p in DEFAULT_POLICIES]  # v1 compatibility
def mask(v):
    d=re.sub(r"[\s-]","",v); return "****" if len(d)<=4 else "*"*max(len(d)-4,2)+d[-4:]
def _norm(raw): return digits(raw) if "@" not in raw and re.search(r"\d",raw) else raw.lower()
def fingerprint(raw,salt=""): return hashlib.sha256((salt+_norm(raw)).encode()).hexdigest()[:12]  # salted hash: lets us count repeats without storing raw values
def _allowed(p,raw):
    for a in p.get("allowlist") or []:
        a=str(a).strip()
        if a.startswith("re:"):
            try:
                if re.fullmatch(a[3:],raw): return True
            except re.error: pass
        elif a.lower() in (raw.lower(),_norm(raw)): return True
    return False
def scan_text(text,src="text",policies=None,salt=""):
    pol={p["category"]:p for p in (DEFAULT_POLICIES if policies is None else policies) if p.get("enabled",1)}
    found={c:[] for c in pol}
    for ln,line in enumerate(text.splitlines(),1):
        taken=[]
        for cat,(rx,ok) in CATS.items():
            for m in rx.finditer(line):
                s,e=m.span()
                if any(s<b and e>a for a,b in taken) or not ok(m.group()): continue
                taken.append((s,e)); p=pol.get(cat)
                if p is None or _allowed(p,m.group()): continue
                found[cat].append(dict(sev=p["severity"],type=cat,val=mask(m.group()),src=src,line=ln,rem=p.get("remediation") or "",policy_id=p.get("id"),policy_name=p["name"],action=p.get("action","alert"),vh=fingerprint(m.group(),salt)))
    out=[]
    for cat,items in found.items():
        if len(items)>=int(pol[cat].get("threshold",1)): out+=items
    return sorted(out,key=lambda i:i["line"])
ORDER={"Critical":0,"High":1,"Medium":2,"Low":3}
safe=lambda v: "'"+str(v) if str(v)[:1] in "=+-@" else v   # CSV formula-injection guard
NR="Not recorded"
sv=lambda i,k:(i.get(k) or "").strip() or NR   # saved investigation field, or an explicit "Not recorded"
def to_csv(inc,saved=False):   # saved=True: DB-backed incidents -> actual saved investigation fields (no generic guidance text)
    b=io.StringIO(); w=csv.writer(b)
    w.writerow(["Incident","Severity","Status","Type","Masked value","Source","Line","Root cause","Business impact","Remediation taken","Resolution"] if saved else ["Severity","Type","Masked value","Source","Line","Remediation"])
    for i in sorted(inc,key=lambda i:ORDER[i["sev"]]):
        w.writerow([f"INC-{i['id']:05d}",safe(i["sev"]),safe(i["status"]),safe(i["type"]),safe(i["val"]),safe(i["src"]),i["line"]]+[safe(sv(i,k)) for k in("root_cause","impact","remediation_taken","resolution")] if saved else [safe(i["sev"]),safe(i["type"]),safe(i["val"]),safe(i["src"]),i["line"],safe(i["rem"])])
    return b.getvalue()
def daily_report(inc,saved=False):
    d=dt.date.today().isoformat(); c={}
    for i in inc: c[i["type"]]=c.get(i["type"],0)+1
    L=[f"DLP DAILY INCIDENT REPORT - {d}","="*44,f"Total incidents: {len(inc)}","","By type:"]+[f"  - {k}: {v}" for k,v in c.items()]+["","Incidents:"]
    for n,i in enumerate(sorted(inc,key=lambda i:ORDER[i["sev"]]),1):
        if saved: L+=[f"{n}. INC-{i['id']:05d} [{i['sev']}] {i['type']} {i['val']} @ {i['src']}:{i['line']} - Status: {i['status']}",f"   Root cause: {sv(i,'root_cause')}",f"   Business impact: {sv(i,'impact')}",f"   Remediation taken: {sv(i,'remediation_taken')}",f"   Resolution: {sv(i,'resolution')}"]
        else: L+=[f"{n}. [{i['sev']}] {i['type']} {i['val']} @ {i['src']}:{i['line']}",f"   Remediation: {i['rem']}"]
    return "\n".join(L)+"\n"
def _demo_aadhaar():
    p="23456789012"; return next(p+str(k) for k in range(10) if verhoeff(p+str(k)))
SAMPLE=f"2026-10-10 INFO payment ok card=4111 1111 1111 1111 user=test.user@example.com\nKYC upload PAN: ABCPE1234F phone +91 9876543210\nAadhaar on file: {_demo_aadhaar()}\nOrder id 1234 5678 9012 (fails checksum, ignored)\n"
SCENARIOS=[  # all synthetic / test values
 dict(name="Email: refund with card + Aadhaar",user="a.rao",channel="email",event="Refund-request.eml",content=f"Hi team, please process the refund. Card 4111 1111 1111 1111, Aadhaar {_demo_aadhaar()}."),
 dict(name="Upload: KYC sheet with PAN",user="s.mehta",channel="file_upload",event="kyc_batch.csv",content="name,pan\nTest One,ABCPE1234F\nTest Two,AAAPL1234C"),
 dict(name="Shared doc: HR contact list",user="p.iyer",channel="shared_document",event="HR-contacts",content="a.one@example.com\nb.two@example.com\nc.three@example.com\nMobile: 9876543210"),
 dict(name="App log: card in debug output",user="svc-payments",channel="app_log",event="payments-debug.log",content="DEBUG charge request card=5555 5555 5555 4444 status=ok"),
 dict(name="USB copy: customer export",user="r.khan",channel="usb_copy",event="customers_export.xlsx",content=f"Aadhaar {_demo_aadhaar()} PAN ABCPE1234F phone 9123456780"),
 dict(name="Clean document (no violation)",user="m.dsouza",channel="shared_document",event="roadmap.docx",content="Quarterly roadmap: improve onboarding and reduce latency.")]
if __name__=="__main__":   # python dlp_engine.py <file-or-folder> ...
    res=[]
    for a in sys.argv[1:]:
        p=pathlib.Path(a)
        for f in ([q for q in p.rglob("*") if q.is_file()] if p.is_dir() else [p]): res+=scan_text(f.read_text("utf-8","ignore"),str(f))
    print(daily_report(res))
