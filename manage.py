"""python manage.py migrate | backup | reset-password <user>
Database path: DB_PATH, or /var/data/dlp.db when DLP_ENV=production, else ./dlp.db"""
import sys, os, getpass, db as D
from werkzeug.security import generate_password_hash
path=os.environ.get("DB_PATH") or ("/var/data/dlp.db" if os.environ.get("DLP_ENV")=="production" else "dlp.db")
cmd=sys.argv[1] if len(sys.argv)>1 else ""
if cmd=="migrate": D.migrate(path); print("Database migrated:",path)
elif cmd=="backup":
    f,n=D.backup(path,os.environ.get("BACKUP_DIR"),int(os.environ.get("BACKUP_KEEP","14"))); print(f"Backup OK (integrity verified, {n} incidents): {f}")
elif cmd=="reset-password" and len(sys.argv)>2:
    D.migrate(path); pw=getpass.getpass("New password (10+ chars): ")
    if len(pw)<10: sys.exit("Too short")
    c=D.connect(path)
    with c: n=c.execute("UPDATE users SET pw_hash=?,must_change=0 WHERE username=?",(generate_password_hash(pw),sys.argv[2])).rowcount
    print("Updated" if n else "No such user")
else: print(__doc__)
