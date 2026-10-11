"""SQLite schema + non-destructive migrations. Existing scans/incidents rows are preserved (a .bak copy is made first)."""
import os, glob, shutil, sqlite3, datetime as dt
VERSION=4
BASE="""
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY,ts TEXT,total INT);
CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY,scan_id INT,sev TEXT,type TEXT,val TEXT,src TEXT,line INT,rem TEXT);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,pw_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN('admin','analyst','auditor')),active INT NOT NULL DEFAULT 1,created_at TEXT);
CREATE TABLE IF NOT EXISTS policies(id INTEGER PRIMARY KEY,name TEXT UNIQUE NOT NULL,description TEXT,category TEXT NOT NULL,severity TEXT NOT NULL,action TEXT NOT NULL,remediation TEXT,threshold INT NOT NULL DEFAULT 1,allowlist TEXT NOT NULL DEFAULT '[]',enabled INT NOT NULL DEFAULT 1,updated_at TEXT);
CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY,incident_id INT NOT NULL REFERENCES incidents(id),ts TEXT,actor TEXT,text TEXT);
CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY,incident_id INT NOT NULL REFERENCES incidents(id),ts TEXT,actor TEXT,from_status TEXT,to_status TEXT,note TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,ts TEXT,actor TEXT,action TEXT,target TEXT,detail TEXT);
CREATE TABLE IF NOT EXISTS sim_events(id INTEGER PRIMARY KEY,ts TEXT,sim_user TEXT,channel TEXT,name TEXT,categories TEXT,policies TEXT,severity TEXT,action TEXT,quarantined INT DEFAULT 0,incident_ids TEXT,actor TEXT);
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY,title TEXT NOT NULL,description TEXT,component TEXT,owasp TEXT,risk TEXT,rationale TEXT,mitigation TEXT,owner TEXT,due TEXT,status TEXT NOT NULL DEFAULT 'Open',retest TEXT NOT NULL DEFAULT 'Not retested',evidence TEXT,created_by TEXT,created_at TEXT,updated_at TEXT);
"""
NEW=[("detected_at","TEXT"),("status","TEXT NOT NULL DEFAULT 'Open'"),("priority","TEXT NOT NULL DEFAULT 'Medium'"),("assignee_id","INTEGER"),("policy_id","INTEGER"),("policy_name","TEXT"),("vh","TEXT"),("root_cause","TEXT"),("impact","TEXT"),("remediation_taken","TEXT"),("resolution","TEXT"),("closure_reason","TEXT"),("fp_reason","TEXT"),("created_at","TEXT"),("updated_at","TEXT"),("resolved_at","TEXT"),("channel","TEXT"),("sim_user","TEXT")]
IDX=["incidents(status)","incidents(sev)","incidents(type)","incidents(detected_at)","incidents(vh)","history(incident_id)","notes(incident_id)","audit(ts)"]
def connect(path):
    c=sqlite3.connect(path,timeout=10); c.row_factory=sqlite3.Row; c.execute("PRAGMA foreign_keys=ON"); return c
def migrate(path):
    existed=os.path.exists(path); c=connect(path)
    if existed and c.execute("PRAGMA user_version").fetchone()[0]<VERSION:
        c.close(); shutil.copy2(path,f"{path}.bak-{dt.datetime.now():%Y%m%d%H%M%S}"); c=connect(path)
    c.executescript(BASE)
    have={r[1] for r in c.execute("PRAGMA table_info(incidents)")}
    with c:
        for n,ddl in NEW:
            if n not in have: c.execute(f"ALTER TABLE incidents ADD COLUMN {n} {ddl}")
        if "must_change" not in {r[1] for r in c.execute("PRAGMA table_info(users)")}: c.execute("ALTER TABLE users ADD COLUMN must_change INTEGER NOT NULL DEFAULT 0")
        c.execute("UPDATE incidents SET detected_at=COALESCE((SELECT ts FROM scans WHERE scans.id=incidents.scan_id),datetime('now')) WHERE detected_at IS NULL")
        c.execute("UPDATE incidents SET created_at=detected_at,updated_at=detected_at WHERE created_at IS NULL")
        c.execute("INSERT INTO history(incident_id,ts,actor,from_status,to_status,note) SELECT id,detected_at,'system',NULL,status,'Migrated from v1' FROM incidents WHERE id NOT IN(SELECT incident_id FROM history)")
        for i in IDX: c.execute(f"CREATE INDEX IF NOT EXISTS ix_{i.replace('(','_').replace(')','')} ON {i}")
    c.execute(f"PRAGMA user_version={VERSION}"); c.close()

def backup(path,dest_dir=None,keep=14):
    """Consistent online backup (SQLite backup API) + integrity check + rotation. Returns (file, incident_count)."""
    dest_dir=dest_dir or os.path.join(os.path.dirname(os.path.abspath(path)),"backups"); os.makedirs(dest_dir,exist_ok=True)
    dest=os.path.join(dest_dir,f"dlp-{dt.datetime.now():%Y%m%d-%H%M%S-%f}.db"); src=sqlite3.connect(path); dst=sqlite3.connect(dest)
    try: src.backup(dst)
    finally: dst.close(); src.close()
    chk=sqlite3.connect(dest)
    try: ok=chk.execute("PRAGMA integrity_check").fetchone()[0]=="ok"; n=chk.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    finally: chk.close()
    if not ok: os.remove(dest); raise RuntimeError("Backup failed its integrity check and was discarded")
    for old in sorted(glob.glob(os.path.join(dest_dir,"dlp-*.db")))[:-keep]: os.remove(old)
    return dest,n
