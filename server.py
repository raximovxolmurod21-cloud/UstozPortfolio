#!/usr/bin/env python3
import os, json, sqlite3, secrets, hashlib, hmac, csv, io
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from datetime import datetime, timezone

BASE = Path(__file__).resolve().parent
APP = BASE
DB_PATH = Path(os.environ.get('USTOZ_DB', str(BASE / 'ustozportfolio.db')))
HOST = os.environ.get('USTOZ_HOST', '0.0.0.0')
PORT = int(os.environ.get('USTOZ_PORT', '8000'))
ADMIN_USER = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASS = os.environ.get('ADMIN_PASSWORD', 'Admin@12345')
DEFAULT_INSTITUTIONS = [
    'Qarshi davlat universiteti',
    'O‘zbekiston milliy pedagogika universiteti',
    'Farg‘ona davlat universiteti',
    'Samarqand davlat universiteti'
]

conn = sqlite3.connect(DB_PATH, check_same_thread=False)
conn.row_factory = sqlite3.Row
conn.execute('PRAGMA journal_mode=WAL')
conn.execute('PRAGMA foreign_keys=ON')
conn.executescript('''
CREATE TABLE IF NOT EXISTS institutions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  participant_code TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL,
  institution TEXT NOT NULL,
  group_code TEXT,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'respondent',
  consent INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  last_login TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS states (
  user_id INTEGER PRIMARY KEY,
  data TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS diagnostics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  phase TEXT NOT NULL,
  result TEXT NOT NULL,
  submitted_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  detail TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);
''')

def now(): return datetime.now(timezone.utc).isoformat()

# Seed the original four institutions, while allowing the administrator to add any number of additional OTMlar.
for _name in DEFAULT_INSTITUTIONS:
    conn.execute('INSERT OR IGNORE INTO institutions(name,active,created_at) VALUES(?,?,?)', (_name,1,now() if 'now' in globals() else datetime.now(timezone.utc).isoformat()))
conn.commit()

def institutions_list():
    return [dict(r) for r in conn.execute('SELECT id,name,active,created_at FROM institutions WHERE active=1 ORDER BY name').fetchall()]

def institution_names():
    return [r['name'] for r in conn.execute('SELECT name FROM institutions WHERE active=1 ORDER BY name').fetchall()]


def json_bytes(obj): return json.dumps(obj, ensure_ascii=False).encode('utf-8')
def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return 'scrypt$%s$%s' % (salt.hex(), dk.hex())
def verify_password(password, stored):
    try:
        _, sh, dh = stored.split('$')
        salt = bytes.fromhex(sh); expected = bytes.fromhex(dh)
        got = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(got, expected)
    except Exception: return False

def clean_code(v): return ''.join((v or '').strip().split()).upper()
def user_row(user_id): return conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
def get_user_by_code(code): return conn.execute('SELECT * FROM users WHERE participant_code=?', (clean_code(code),)).fetchone()
def session_user(handler):
    cookie = handler.headers.get('Cookie','')
    token = next((p.split('=',1)[1] for p in cookie.split(';') if p.strip().startswith('ustoz_session=')), None)
    if not token: return None
    row = conn.execute('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>?', (token, now())).fetchone()
    return row

def audit(uid, action, detail=''):
    conn.execute('INSERT INTO audit_log(user_id,action,detail,created_at) VALUES(?,?,?,?)', (uid,action,detail,now())); conn.commit()

def state_for(uid):
    r = conn.execute('SELECT data FROM states WHERE user_id=?', (uid,)).fetchone()
    return json.loads(r['data']) if r else {}

def public_user(u):
    return {'id':u['id'],'participantCode':u['participant_code'],'fullName':u['full_name'],'institution':u['institution'],'group':u['group_code'],'role':u['role'],'consent':bool(u['consent'])}

def make_cookie(token): return f'ustoz_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200'

class Handler(BaseHTTPRequestHandler):
    server_version='UstozPortfolio/12.0'
    def log_message(self, fmt, *args):
        print('[%s] %s' % (datetime.now().strftime('%H:%M:%S'), fmt % args))
    def send_json(self, code, obj, headers=None):
        data=json_bytes(obj); self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(data))); self.send_header('Cache-Control','no-store')
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(data)
    def send_text(self, code, text, content_type='text/plain; charset=utf-8'):
        data=text.encode('utf-8'); self.send_response(code); self.send_header('Content-Type',content_type); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    def body(self):
        n=int(self.headers.get('Content-Length','0')); raw=self.rfile.read(n) if n else b'{}'; return json.loads(raw or b'{}')
    def require_user(self, admin=False):
        u=session_user(self)
        if not u: self.send_json(401, {'ok':False,'error':'Avtorizatsiya talab qilinadi.'}); return None
        if admin and u['role']!='admin': self.send_json(403, {'ok':False,'error':'Admin huquqi talab qilinadi.'}); return None
        return u
    def do_GET(self):
        p=urlparse(self.path).path
        if p=='/api/institutions':
            self.send_json(200, {'ok':True,'institutions':institutions_list()}); return
        if p=='/api/me':
            u=session_user(self); self.send_json(200, {'ok':True,'authenticated':bool(u),'user':public_user(u) if u else None}); return
        if p=='/api/state':
            u=self.require_user();
            if u: self.send_json(200, {'ok':True,'user':public_user(u),'state':state_for(u['id'])})
            return
        if p=='/api/admin/institutions':
            u=self.require_user(True)
            if not u:return
            self.send_json(200, {'ok':True,'institutions':institutions_list()}); return
        if p=='/api/admin/stats':
            u=self.require_user(True)
            if not u:return
            self.send_json(200, admin_stats()); return
        if p=='/api/admin/respondents':
            u=self.require_user(True)
            if not u:return
            self.send_json(200, {'ok':True,'respondents':admin_respondents()}); return
        if p=='/api/admin/export.csv':
            u=self.require_user(True)
            if not u:return
            self.export_csv(); return
        if p=='/api/admin/respondent':
            u=self.require_user(True)
            if not u:return
            q=parse_qs(urlparse(self.path).query); code=clean_code((q.get('code') or [''])[0]); r=get_user_by_code(code)
            if not r: self.send_json(404, {'ok':False,'error':'Respondent topilmadi.'}); return
            di=conn.execute('SELECT * FROM diagnostics WHERE user_id=? ORDER BY id', (r['id'],)).fetchall()
            self.send_json(200, {'ok':True,'user':public_user(r),'state':state_for(r['id']),'diagnostics':[dict(x) for x in di]}); return
        if p=='/admin': self.serve_file(APP/'admin.html'); return
        if p=='/' or p=='/index.html': self.serve_file(APP/'index.html'); return
        rel=p.lstrip('/')
        target=(APP/rel).resolve()
        if str(target).startswith(str(APP.resolve())) and target.is_file(): self.serve_file(target); return
        self.send_text(404,'Not found')
    def do_POST(self):
        p=urlparse(self.path).path
        try: data=self.body()
        except Exception: self.send_json(400, {'ok':False,'error':'JSON noto‘g‘ri.'}); return
        if p=='/api/register': self.register(data); return
        if p=='/api/login': self.login(data); return
        if p=='/api/logout': self.logout(); return
        if p=='/api/state': self.save_state(data); return
        if p=='/api/diagnostic': self.save_diagnostic(data); return
        if p=='/api/admin/assign-group': self.assign_group(data); return
        if p=='/api/admin/institutions/add': self.add_institution(data); return
        if p=='/api/admin/institutions/delete': self.delete_institution(data); return
        if p=='/api/admin/reset-password': self.reset_password(data); return
        self.send_json(404, {'ok':False,'error':'API topilmadi.'})
    def register(self,d):
        code=clean_code(d.get('participantCode')); name=(d.get('fullName') or '').strip(); inst=(d.get('institution') or '').strip(); pw=d.get('password') or ''; consent=bool(d.get('consent'))
        if not code or len(code)<3 or not name or inst not in institution_names() or len(pw)<8 or not consent:
            self.send_json(400, {'ok':False,'error':'Kod, F.I.Sh., OTM, kamida 8 belgili parol va rozilik talab qilinadi.'}); return
        if get_user_by_code(code): self.send_json(409, {'ok':False,'error':'Bu ishtirokchi kodi allaqachon ro‘yxatdan o‘tgan.'}); return
        cur=conn.execute('INSERT INTO users(participant_code,full_name,institution,password_hash,consent,created_at) VALUES(?,?,?,?,?,?)', (code,name,inst,hash_password(pw),1,now())); uid=cur.lastrowid
        conn.execute('INSERT INTO states(user_id,data,updated_at) VALUES(?,?,?)',(uid,json.dumps({'ustozportfolio_research':{'participantCode':code,'institution':inst,'group':'','consent':True},'ustozportfolio_profile':{'name':name,'position':'O‘qituvchi','direction':'Aralash ta’lim va raqamli pedagogika'}},ensure_ascii=False),now())); conn.commit(); audit(uid,'register',inst)
        token=secrets.token_urlsafe(32); conn.execute('INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,datetime(\'now\',\'+12 hours\'))',(token,uid)); conn.commit()
        self.send_json(200, {'ok':True,'user':public_user(user_row(uid))}, {'Set-Cookie':make_cookie(token)})
    def login(self,d):
        code=clean_code(d.get('participantCode')); pw=d.get('password') or ''; u=get_user_by_code(code)
        if not u or not verify_password(pw,u['password_hash']): self.send_json(401, {'ok':False,'error':'Ishtirokchi kodi yoki parol noto‘g‘ri.'}); return
        conn.execute('UPDATE users SET last_login=? WHERE id=?',(now(),u['id'])); token=secrets.token_urlsafe(32); conn.execute('INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,datetime(\'now\',\'+12 hours\'))',(token,u['id'])); conn.commit(); audit(u['id'],'login')
        self.send_json(200, {'ok':True,'user':public_user(user_row(u['id']))}, {'Set-Cookie':make_cookie(token)})
    def logout(self):
        cookie=self.headers.get('Cookie',''); token=next((p.split('=',1)[1] for p in cookie.split(';') if p.strip().startswith('ustoz_session=')),None)
        if token: conn.execute('DELETE FROM sessions WHERE token=?',(token,)); conn.commit()
        self.send_json(200, {'ok':True}, {'Set-Cookie':'ustoz_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'})
    def save_state(self,d):
        u=self.require_user();
        if not u:return
        state=d.get('state') or {}
        if not isinstance(state,dict): self.send_json(400,{'ok':False,'error':'state obyekt bo‘lishi kerak.'}); return
        rp=state.get('ustozportfolio_research') or {}
        rp['participantCode']=u['participant_code']; rp['institution']=u['institution']; rp['group']=u['group_code'] or ''; rp['consent']=bool(u['consent']); state['ustozportfolio_research']=rp
        conn.execute('INSERT INTO states(user_id,data,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at',(u['id'],json.dumps(state,ensure_ascii=False),now())); conn.commit(); self.send_json(200,{'ok':True})
    def save_diagnostic(self,d):
        u=self.require_user();
        if not u:return
        phase=d.get('phase') or 'pre'; result=d.get('result')
        if phase not in ('pre','post') or not isinstance(result,dict) or not u['group_code']:
            self.send_json(400,{'ok':False,'error':'Diagnostika uchun guruh admin tomonidan biriktirilgan bo‘lishi kerak.'}); return
        conn.execute('INSERT INTO diagnostics(user_id,phase,result,submitted_at) VALUES(?,?,?,?)',(u['id'],phase,json.dumps(result,ensure_ascii=False),now())); conn.commit(); audit(u['id'],'diagnostic',phase); self.send_json(200,{'ok':True})
    def assign_group(self,d):
        a=self.require_user(True)
        if not a:return
        code=clean_code(d.get('participantCode')); g=d.get('group')
        if g not in ('EG','NG'): self.send_json(400,{'ok':False,'error':'Guruh EG yoki NG bo‘lishi kerak.'}); return
        r=get_user_by_code(code)
        if not r:self.send_json(404,{'ok':False,'error':'Respondent topilmadi.'}); return
        conn.execute('UPDATE users SET group_code=? WHERE id=?',(g,r['id'])); st=state_for(r['id']); rp=st.get('ustozportfolio_research') or {}; rp['group']=g; rp['participantCode']=r['participant_code']; rp['institution']=r['institution']; st['ustozportfolio_research']=rp; conn.execute('UPDATE states SET data=?,updated_at=? WHERE user_id=?',(json.dumps(st,ensure_ascii=False),now(),r['id'])); conn.commit(); audit(a['id'],'assign_group',f'{code}:{g}'); self.send_json(200,{'ok':True,'user':public_user(user_row(r['id']))})
    def add_institution(self,d):
        a=self.require_user(True)
        if not a:return
        name=' '.join((d.get('name') or '').strip().split())
        if len(name)<3:
            self.send_json(400, {'ok':False,'error':'OTM nomini kiriting.'}); return
        try:
            conn.execute('INSERT INTO institutions(name,active,created_at) VALUES(?,?,?)',(name,1,now())); conn.commit()
        except sqlite3.IntegrityError:
            conn.execute('UPDATE institutions SET active=1 WHERE name=?',(name,)); conn.commit()
        audit(a['id'],'add_institution',name)
        self.send_json(200, {'ok':True,'institutions':institutions_list()})
    def delete_institution(self,d):
        a=self.require_user(True)
        if not a:return
        name=' '.join((d.get('name') or '').strip().split())
        r=conn.execute('SELECT id FROM institutions WHERE name=? AND active=1',(name,)).fetchone()
        if not r:
            self.send_json(404, {'ok':False,'error':'OTM topilmadi.'}); return
        n=conn.execute("SELECT COUNT(*) c FROM users WHERE institution=? AND role='respondent'",(name,)).fetchone()['c']
        if n:
            self.send_json(409, {'ok':False,'error':f'Bu OTMga {n} nafar respondent bog‘langan. O‘chirish o‘rniga faol holatini o‘zgartirish talab qilinadi.'}); return
        conn.execute('UPDATE institutions SET active=0 WHERE id=?',(r['id'],)); conn.commit(); audit(a['id'],'delete_institution',name)
        self.send_json(200, {'ok':True,'institutions':institutions_list()})
    def reset_password(self,d):
        a=self.require_user(True)
        if not a:return
        code=clean_code(d.get('participantCode')); pw=d.get('password') or ''
        if len(pw)<8:self.send_json(400,{'ok':False,'error':'Parol kamida 8 belgi bo‘lishi kerak.'}); return
        r=get_user_by_code(code)
        if not r:self.send_json(404,{'ok':False,'error':'Respondent topilmadi.'}); return
        conn.execute('UPDATE users SET password_hash=? WHERE id=?',(hash_password(pw),r['id'])); conn.commit(); audit(a['id'],'reset_password',code); self.send_json(200,{'ok':True})
    def export_csv(self):
        rows=admin_respondents(); out=io.StringIO(); w=csv.writer(out); w.writerow(['participantCode','fullName','institution','group','registeredAt','lastLogin','PRE overall','POST overall','PRE Kognitiv','POST Kognitiv','PRE Motivatsiyali-aksiologik','POST Motivatsiyali-aksiologik','PRE Praksiologik','POST Praksiologik'])
        for r in rows: w.writerow([r['participantCode'],r['fullName'],r['institution'],r['group'] or '',r['createdAt'],r['lastLogin'] or '',r['pre']['overall'],r['post']['overall'],r['pre']['Kognitiv'],r['post']['Kognitiv'],r['pre']['Motivatsiyali-aksiologik'],r['post']['Motivatsiyali-aksiologik'],r['pre']['Praksiologik'],r['post']['Praksiologik']])
        data=out.getvalue().encode('utf-8-sig'); self.send_response(200); self.send_header('Content-Type','text/csv; charset=utf-8'); self.send_header('Content-Disposition','attachment; filename="ustozportfolio_tadqiqot_bazasi.csv"'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    def serve_file(self,path):
        import mimetypes
        data=path.read_bytes(); ctype=mimetypes.guess_type(str(path))[0] or 'application/octet-stream'; self.send_response(200); self.send_header('Content-Type',ctype+'; charset=utf-8' if ctype.startswith('text/') or ctype in ('application/javascript','application/json') else ctype); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)

def diag_summary(uid):
    rows=conn.execute('SELECT phase,result FROM diagnostics WHERE user_id=? ORDER BY id',(uid,)).fetchall(); out={'pre':{},'post':{}}
    for phase in ('pre','post'):
        xs=[]
        for r in rows:
            if r['phase']==phase:
                try: xs.append(json.loads(r['result']))
                except: pass
        if xs:
            x=xs[-1]; out[phase]={k:(x.get(k,{}).get('score') if isinstance(x.get(k),dict) else None) for k in ('Kognitiv','Motivatsiyali-aksiologik','Praksiologik','overall')}
        else: out[phase]={k:None for k in ('Kognitiv','Motivatsiyali-aksiologik','Praksiologik','overall')}
    return out

def admin_respondents():
    out=[]
    for u in conn.execute('SELECT * FROM users WHERE role=\'respondent\' ORDER BY institution,participant_code').fetchall():
        d=diag_summary(u['id']); st=state_for(u['id']); h=st.get('ustozportfolio_diagnostic_history') or []; tasks=st.get('ustozportfolio_task_records') or []; refs=st.get('ustozportfolio_reflections') or []
        out.append({'id':u['id'],'participantCode':u['participant_code'],'fullName':u['full_name'],'institution':u['institution'],'group':u['group_code'],'createdAt':u['created_at'],'lastLogin':u['last_login'],'pre':d['pre'],'post':d['post'],'historyCount':len(h),'taskCount':len(tasks),'reflectionCount':len(refs),'consent':bool(u['consent'])})
    return out

def admin_stats():
    rs=admin_respondents(); by={inst:{'registered':0,'EG':0,'NG':0,'pre':0,'post':0} for inst in institution_names()}
    for r in rs:
        b=by[r['institution']]; b['registered']+=1
        if r['group'] in ('EG','NG'): b[r['group']]+=1
        if r['pre']['overall'] is not None:b['pre']+=1
        if r['post']['overall'] is not None:b['post']+=1
    return {'ok':True,'total':len(rs),'assigned':sum(1 for r in rs if r['group']),'pre':sum(1 for r in rs if r['pre']['overall'] is not None),'post':sum(1 for r in rs if r['post']['overall'] is not None),'byInstitution':by}

def ensure_admin():
    r=conn.execute('SELECT id FROM users WHERE participant_code=?',(ADMIN_USER.upper(),)).fetchone()
    if not r:
        conn.execute('INSERT INTO users(participant_code,full_name,institution,password_hash,role,consent,created_at) VALUES(?,?,?,?,?,?,?)',(ADMIN_USER.upper(),'Tadqiqot administratori',institution_names()[0],hash_password(ADMIN_PASS),'admin',1,now())); conn.commit()

ensure_admin()
print('UstozPortfolio v12 server')
print(f'Admin login: {ADMIN_USER} / {ADMIN_PASS}')
print(f'URL: http://127.0.0.1:{PORT}')
ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
