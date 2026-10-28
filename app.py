import os, re, sqlite3, secrets, time, uuid
from flask import Flask, request, session, redirect, g, abort, render_template_string as R, send_file, flash
from werkzeug.security import generate_password_hash as gph, check_password_hash as cph
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

D = os.environ.get("DATA_DIR", "data"); os.makedirs(D + "/files", exist_ok=True)
MAX_FILE = 10 * 1024 * 1024; QUOTA = 50 * 1024 * 1024
ALLOWED = {"pdf", "png", "jpg", "jpeg", "gif", "txt", "csv", "zip", "docx", "mp3", "mp4"}
MAGIC = {"pdf": b"%PDF", "png": b"\x89PNG", "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff",
         "gif": b"GIF8", "zip": b"PK\x03\x04", "docx": b"PK\x03\x04"}
EMAIL = re.compile(r"[a-z0-9._%+-]+@rvce\.edu\.in")
ADMINS = {x.strip().lower() for x in os.environ.get("ADMINS", "").split(",") if x.strip()}
EXP = {"1h": 3600, "24h": 86400, "7d": 604800}

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(MAX_CONTENT_LENGTH=MAX_FILE + 4096, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
kf = D + "/secret"
if not os.path.exists(kf): open(kf, "w").write(secrets.token_hex(32))
app.secret_key = os.environ.get("SECRET_KEY") or open(kf).read()

def db():
    if "db" not in g: g.db = sqlite3.connect(D + "/app.db"); g.db.row_factory = sqlite3.Row
    return g.db
@app.teardown_appcontext
def close(e):
    if "db" in g: g.db.close()
with sqlite3.connect(D + "/app.db") as c:
    c.executescript("""create table if not exists users(id integer primary key, name text unique, pw text);
    create table if not exists files(id integer primary key, owner int, name text, stored text, size int,
      token text unique, expires real, revoked int default 0, downloads int default 0, created real);""")

with sqlite3.connect(D + "/app.db") as c:
    for q in ("alter table files add column max_dl int default 0", "alter table users add column created real"):
        try: c.execute(q)
        except sqlite3.OperationalError: pass

@app.after_request
def hdr(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Content-Security-Policy"] = f"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{getattr(g,'nonce','')}'; form-action 'self'"
    return r

@app.before_request
def csrf():
    g.nonce = secrets.token_urlsafe(12)
    if request.method == "POST":
        if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")): abort(400, "Bad CSRF token")
@app.context_processor
def ctx():
    session.setdefault("csrf", secrets.token_hex(16)); return dict(csrf=session["csrf"], user=session.get("uid"), uname=session.get("name"), admin=is_admin(), nonce=g.nonce)

def login_req(f):
    from functools import wraps
    @wraps(f)
    def w(*a, **k):
        if "uid" not in session: return redirect("/login")
        return f(*a, **k)
    return w

def is_admin():
    return session.get("name") in ADMINS if ADMINS else session.get("uid") == 1

hits = {}
def limited(key, n=10, win=300):
    t = time.time(); h = [x for x in hits.get(key, []) if t - x < win]; h.append(t); hits[key] = h
    return len(h) > n

BASE = '''<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Vaultly · Secure File Sharing</title>
<style>
:root{--bg:#05050a;--card:rgba(255,255,255,.075);--bd:rgba(255,255,255,.2);--tx:#fff;--mut:#bdbbd6;--a:#8b6bff;--b:#38e1ff}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 -apple-system,"Segoe UI",Inter,system-ui,sans-serif;color:var(--tx);min-height:100vh;
background:radial-gradient(900px 520px at 8% -10%,rgba(124,92,255,.28),transparent),radial-gradient(800px 520px at 100% 0,rgba(34,211,238,.16),transparent),var(--bg)}
a{color:inherit;text-decoration:none}.mut{color:var(--mut);font-size:13px}
nav{position:sticky;top:0;z-index:5;backdrop-filter:blur(14px);background:rgba(7,7,13,.65);border-bottom:1px solid var(--bd)}
nav .in{max-width:1000px;margin:auto;padding:14px 20px;display:flex;align-items:center;justify-content:space-between}
.logo{font-weight:800;font-size:19px;letter-spacing:-.3px;display:flex;gap:10px;align-items:center}
.logo i{width:30px;height:30px;border-radius:9px;background:linear-gradient(135deg,var(--a),var(--b));display:grid;place-items:center;font-style:normal;font-size:16px}
.who{display:flex;gap:12px;align-items:center}.av{width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,var(--a),var(--b));display:grid;place-items:center;font-weight:700}
.wrap{max-width:1000px;margin:auto;padding:28px 20px 60px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:18px;padding:18px;backdrop-filter:blur(10px)}
h1{font-size:30px;margin:0 0 4px;letter-spacing:-.6px}h2{margin:0 0 6px;letter-spacing:-.3px}
.btn{border:0;cursor:pointer;color:#fff;font:600 14px inherit;font-family:inherit;padding:10px 18px;border-radius:11px;background:linear-gradient(135deg,var(--a),#5b8cff);box-shadow:0 6px 20px rgba(124,92,255,.35);transition:.15s}
.btn:hover{transform:translateY(-1px);filter:brightness(1.1)}.btn.sm{padding:7px 12px;font-size:13px;box-shadow:none}
.btn.ghost{background:rgba(255,255,255,.07);border:1px solid var(--bd);box-shadow:none}.btn.danger{background:rgba(255,80,100,.14);color:#ff8a98;border:1px solid rgba(255,80,100,.3);box-shadow:none}
input,select{font:inherit;color:var(--tx);background:rgba(255,255,255,.11);border:1px solid var(--bd);border-radius:11px;padding:10px 12px;outline:0}
input:focus,select:focus{border-color:var(--a);box-shadow:0 0 0 3px rgba(124,92,255,.25)}select{padding:7px 8px;font-size:13px}select option{background:#14141f}
.toast{margin:0 0 16px;padding:12px 16px;border-radius:12px;background:rgba(124,92,255,.15);border:1px solid rgba(124,92,255,.4)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}
.stats .card{display:flex;flex-direction:column;gap:4px}.stats b{font-size:26px;letter-spacing:-.5px}.stats small{font-size:13px;color:var(--mut);font-weight:500}
.bar{height:6px;border-radius:9px;background:rgba(255,255,255,.1);overflow:hidden;margin-top:6px}.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--a),var(--b));border-radius:9px}
.drop{display:flex;gap:14px;align-items:center;flex-wrap:wrap;border:2px dashed rgba(124,92,255,.45);background:rgba(124,92,255,.06)}
.drop .t{flex:1;min-width:220px}.drop input[type=file]{flex:1;min-width:200px}
input[type=file]::file-selector-button{margin-right:12px;border:0;border-radius:8px;padding:6px 12px;background:rgba(255,255,255,.12);color:var(--tx);cursor:pointer}
.sec{display:flex;justify-content:space-between;align-items:end;margin:30px 0 12px}
.file{display:grid;grid-template-columns:52px 1fr auto;gap:14px;align-items:center;margin-bottom:12px;transition:.15s}.file:hover{border-color:rgba(124,92,255,.5)}
.ficon{width:52px;height:52px;border-radius:14px;background:rgba(255,255,255,.07);display:grid;place-items:center;font-size:24px}
.fname{font-weight:600;word-break:break-all}.link{width:100%;margin-top:8px;font-size:12px;color:var(--b)}
.acts{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end;align-items:center}.acts form{display:flex;gap:4px;margin:0}
.badge{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12px;font-weight:600;margin-left:8px;vertical-align:middle}
.b-active{background:rgba(52,211,153,.22);color:#6ee7a8}.b-expired{background:rgba(251,191,36,.15);color:#fbbf24}
.b-revoked{background:rgba(255,80,100,.15);color:#ff8a98}.b-notshared{background:rgba(255,255,255,.08);color:var(--mut)}
.center{min-height:calc(100vh - 140px);display:grid;place-items:center}.narrow{width:100%;max-width:420px}.tc{text-align:center}
.bigicon{font-size:46px;margin-bottom:10px}.form{display:flex;flex-direction:column;gap:12px;margin-top:16px}.form .btn{padding:12px}
.empty{text-align:center;padding:40px;color:var(--mut)}
.num{width:92px}.b-limitreached{background:rgba(251,146,60,.22);color:#fdba74}
details{margin-bottom:12px}summary{cursor:pointer;display:flex;gap:16px;flex-wrap:wrap;align-items:center;font-weight:600}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:14px}th,td{padding:8px;border-bottom:1px solid var(--bd);text-align:left}th{color:var(--mut);font-size:12px;text-transform:uppercase}
@media(max-width:760px){.stats{grid-template-columns:1fr 1fr}.file{grid-template-columns:44px 1fr}.acts{grid-column:1/-1;justify-content:flex-start}}
</style>
<nav><div class=in><a href=/ class=logo><i>🔒</i>Vaultly</a>
{% if user %}<form method=post action=/logout class=who><input type=hidden name=csrf value={{csrf}}>{% if admin %}<a href=/admin class=mut>Admin</a>{% endif %}<span class=mut>{{uname}}</span><span class=av>{{uname[0]|upper}}</span><button class="btn sm ghost">Logout</button></form>{% endif %}</div></nav>
<div class=wrap>{% for m in get_flashed_messages() %}<div class=toast>{{m}}</div>{% endfor %}
'''
BODY_END = '''</div><script nonce="{{nonce}}">
document.addEventListener('click',e=>{const b=e.target.closest('[data-copy]');if(b){navigator.clipboard.writeText(b.dataset.copy);b.textContent='Copied ✓';setTimeout(()=>b.textContent='Copy',1500)}});
document.addEventListener('submit',e=>{const m=e.target.dataset.confirm;if(m&&!confirm(m))e.preventDefault()});
</script>'''

def page(body, **k): return R(BASE + body + BODY_END, **k)

def err(m, code, icon="⛔"):
    return page("<div class=center><div class='card narrow tc'><div class=bigicon>{{i}}</div><h2>{{m}}</h2><p class=mut>Ask the owner to send you a new link.</p></div></div>", m=m, i=icon), code

@app.route("/register", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def auth():
    reg = request.path == "/register"
    if request.method == "POST":
        if limited(request.remote_addr): return "Too many attempts, try later.", 429
        n, p = request.form.get("name", "").strip().lower()[:80], request.form.get("pw", "")
        if reg:
            if not EMAIL.fullmatch(n) or len(p) < 8: flash("Use your @rvce.edu.in email and a password of 8+ characters.")
            else:
                try:
                    db().execute("insert into users(name,pw,created) values(?,?,?)", (n, gph(p), time.time())); db().commit()
                    flash("Registered. Please log in."); return redirect("/login")
                except sqlite3.IntegrityError: flash("Username taken.")
        else:
            u = db().execute("select * from users where name=?", (n,)).fetchone()
            if u and cph(u["pw"], p):
                session.clear(); session["uid"] = u["id"]; session["name"] = u["name"]; return redirect("/")
            flash("Invalid credentials.")
    return page("""<div class=center><div class="card narrow"><div class=tc><div class=bigicon>🔒</div><h2>{{'Create your account' if reg else 'Welcome back'}}</h2>
<p class=mut>{{'Only @rvce.edu.in email addresses can sign up.' if reg else 'Log in to manage your shared files.'}}</p></div>
<form method=post class=form><input type=hidden name=csrf value={{csrf}}><input name=name type=email placeholder="you@rvce.edu.in" required autocomplete=username>
<input name=pw type=password placeholder=Password required autocomplete={{'new-password' if reg else 'current-password'}}><button class=btn>{{'Sign up' if reg else 'Log in'}}</button></form>
<p class="mut tc">{{'Already have an account?' if reg else 'New here?'}} <a href={{'/login' if reg else '/register'}} style="color:var(--b)">{{'Log in' if reg else 'Create account'}}</a></p></div></div>""", reg=reg)

@app.post("/logout")
def logout(): session.clear(); return redirect("/login")

def status(f):
    if not f["token"]: return "not shared"
    if f["revoked"]: return "revoked"
    if f["expires"] < time.time(): return "expired"
    if f["max_dl"] and f["downloads"] >= f["max_dl"]: return "limit reached"
    return "active"

def kb(n): return f"{n/1048576:.1f} MB" if n >= 1048576 else f"{n/1024:.1f} KB"
def when(t): return time.strftime("%d %b %Y", time.localtime(t))
def left(f):
    d = int(f["expires"] - time.time())
    return f"{d//86400}d left" if d >= 86400 else f"{d//3600}h left" if d >= 3600 else f"{max(d//60,1)}m left"
def ic(n):
    e = n.rsplit(".", 1)[-1].lower()
    return "🖼️" if e in ("png","jpg","jpeg","gif") else "🎵" if e == "mp3" else "🎬" if e == "mp4" else "🗜️" if e == "zip" else "📕" if e == "pdf" else "📊" if e == "csv" else "📝"

@app.route("/")
@login_req
def dash():
    fs = db().execute("select * from files where owner=? order by id desc", (session["uid"],)).fetchall()
    used = sum(f["size"] for f in fs)
    return page("""
<h1>Your files</h1><p class=mut>Upload, share with expiring links, and stay in control.</p>
<div class=stats>
<div class=card><span class=mut>Files</span><b>{{fs|length}}</b></div>
<div class=card><span class=mut>Active links</span><b>{{act}}</b></div>
<div class=card><span class=mut>Total downloads</span><b>{{dls}}</b></div>
<div class=card><span class=mut>Storage</span><b>{{'%.1f'|format(used/1048576)}} <small>/ {{q}} MB</small></b><div class=bar><i style="width:{{pct}}%"></i></div></div></div>
<form method=post action=/upload enctype=multipart/form-data class="card drop"><input type=hidden name=csrf value={{csrf}}>
<div class=t><b>☁️ Upload a file</b><div class=mut>Max {{m}} MB · {{a}}</div></div><input type=file name=file required><button class=btn>Upload</button></form>
<div class=sec><h2>Library</h2></div>
{% for f in fs %}{% set s=st(f) %}
<div class="card file"><div class=ficon>{{ic(f.name)}}</div>
<div><div class=fname>{{f.name}}<span class="badge b-{{s|replace(' ','')}}">{{s|capitalize}}{% if s=='active' %} · {{left(f)}}{% endif %}</span></div>
<div class=mut>{{kb(f.size)}} · Uploaded {{when(f.created)}} · ⬇ {{f.downloads}}{% if f.max_dl %} / {{f.max_dl}}{% endif %} downloads</div>
{% if s=='active' %}<input class=link readonly value="{{host}}s/{{f.token}}">{% endif %}</div>
<div class=acts>
{% if s=='active' %}<button type=button class="btn sm" data-copy="{{host}}s/{{f.token}}">Copy</button>{% endif %}
<form method=post action=/share/{{f.id}}><input type=hidden name=csrf value={{csrf}}><input type=number name=max_dl min=0 max=100000 value="{{f.max_dl or ''}}" placeholder="∞ limit" title="Max downloads (empty or 0 = unlimited)" class=num><select name=exp>{% for k in exps %}<option>{{k}}{% endfor %}</select><button class="btn sm ghost">{{'Re-share' if f.token else 'Share'}}</button></form>
{% if s in ('active','limit reached') %}<form method=post action=/limit/{{f.id}}><input type=hidden name=csrf value={{csrf}}><input type=number name=max_dl min=0 max=100000 value="{{f.max_dl or ''}}" placeholder="∞" title="Max downloads (0 = unlimited)" class=num><button class="btn sm ghost">Set limit</button></form>{% endif %}
{% if s=='active' %}<form method=post action=/revoke/{{f.id}}><input type=hidden name=csrf value={{csrf}}><button class="btn sm ghost">Revoke</button></form>{% endif %}
<form method=post action=/delete/{{f.id}} data-confirm="Delete this file permanently?"><input type=hidden name=csrf value={{csrf}}><button class="btn sm danger">Delete</button></form></div></div>
{% else %}<div class="card empty"><div class=bigicon>📂</div>No files yet. Upload your first one above.</div>{% endfor %}""",
        fs=fs, used=used, q=QUOTA // 1048576, m=MAX_FILE // 1048576, pct=min(100, used * 100 // QUOTA),
        act=sum(status(f) == "active" for f in fs), dls=sum(f["downloads"] for f in fs),
        a=", ".join(sorted(ALLOWED)), st=status, exps=EXP, host=request.host_url, kb=kb, when=when, left=left, ic=ic)

@app.route("/admin")
@login_req
def admin():
    if not is_admin(): abort(404)
    us = db().execute("select u.id,u.name,u.created,count(f.id) n,coalesce(sum(f.size),0) used,coalesce(sum(f.downloads),0) dls from users u left join files f on f.owner=u.id group by u.id order by u.id").fetchall()
    files = {}
    for f in db().execute("select * from files order by id desc"): files.setdefault(f["owner"], []).append(f)
    return page("""<h1>Admin</h1><p class=mut>All users and their uploaded files (metadata only).</p>
<div class=stats><div class=card><span class=mut>Users</span><b>{{us|length}}</b></div><div class=card><span class=mut>Files</span><b>{{us|sum(attribute='n')}}</b></div>
<div class=card><span class=mut>Storage used</span><b>{{kb(us|sum(attribute='used'))}}</b></div><div class=card><span class=mut>Downloads</span><b>{{us|sum(attribute='dls')}}</b></div></div>
{% for u in us %}<details class=card><summary><span>👤 {{u.name}}</span><span class=mut>Joined {{when(u.created) if u.created else '—'}}</span><span class=mut>{{u.n}} files · {{kb(u.used)}} · ⬇ {{u.dls}}</span></summary>
{% if files.get(u.id) %}<table><tr><th>File<th>Size<th>Uploaded<th>Link<th>Downloads</tr>
{% for f in files[u.id] %}<tr><td>{{f.name}}<td>{{kb(f.size)}}<td>{{when(f.created)}}<td>{{st(f)}}<td>{{f.downloads}}{% if f.max_dl %} / {{f.max_dl}}{% endif %}</tr>{% endfor %}</table>
{% else %}<p class=mut>No files uploaded.</p>{% endif %}</details>{% endfor %}""", us=us, files=files, kb=kb, when=when, st=status)

@app.errorhandler(413)
def big(e): return err(f"File too large (max {MAX_FILE // 1048576} MB).", 413, "📦")

@app.post("/upload")
@login_req
def upload():
    f = request.files.get("file")
    name = secure_filename(f.filename or "") if f else ""
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if not name or ext not in ALLOWED: flash("File type not allowed."); return redirect("/")
    head = f.stream.read(8); f.stream.seek(0)
    if ext in MAGIC and not head.startswith(MAGIC[ext]): flash("File content doesn't match its type."); return redirect("/")
    used = db().execute("select coalesce(sum(size),0) from files where owner=?", (session["uid"],)).fetchone()[0]
    stored = uuid.uuid4().hex; path = f"{D}/files/{stored}"
    f.save(path); size = os.path.getsize(path)
    if size > MAX_FILE or used + size > QUOTA:
        os.remove(path); flash("Quota or size limit exceeded."); return redirect("/")
    db().execute("insert into files(owner,name,stored,size,created) values(?,?,?,?,?)", (session["uid"], name, stored, size, time.time()))
    db().commit(); flash("Uploaded."); return redirect("/")

def own(i):
    f = db().execute("select * from files where id=? and owner=?", (i, session["uid"])).fetchone()
    return f or abort(404)

@app.post("/share/<int:i>")
@login_req
def share(i):
    own(i); sec = EXP.get(request.form.get("exp"), 3600)
    db().execute("update files set token=?,expires=?,revoked=0,downloads=0,max_dl=? where id=?", (secrets.token_urlsafe(32), time.time() + sec, mx(), i))
    db().commit(); return redirect("/")

def mx():
    try: return max(0, min(int(request.form.get("max_dl") or 0), 100000))
    except ValueError: return 0

@app.post("/limit/<int:i>")
@login_req
def limit(i):
    own(i); db().execute("update files set max_dl=? where id=?", (mx(), i)); db().commit(); flash("Download limit updated."); return redirect("/")

@app.post("/revoke/<int:i>")
@login_req
def revoke(i): own(i); db().execute("update files set revoked=1 where id=?", (i,)); db().commit(); return redirect("/")

@app.post("/delete/<int:i>")
@login_req
def delete(i):
    f = own(i)
    try: os.remove(f"{D}/files/{f['stored']}")
    except OSError: pass
    db().execute("delete from files where id=?", (i,)); db().commit(); flash("Deleted."); return redirect("/")

def link(t):
    f = db().execute("select * from files where token=?", (t,)).fetchone()
    if not f: return None, ("This link is invalid or the file was deleted.", 404)
    s = status(f)
    if s == "revoked": return None, ("This link was revoked by the owner.", 410)
    if s == "expired": return None, ("This link has expired.", 410)
    if s == "limit reached": return None, ("This link has reached its download limit.", 410)
    return f, None

@app.route("/s/<t>")
def dl_page(t):
    if limited("dl" + request.remote_addr, 120): return "Too many requests", 429
    f, e = link(t)
    if e: return err(e[0], e[1], "⏳" if "expired" in e[0] else "🚫")
    return page("""<div class=center><div class="card narrow tc"><div class=bigicon>{{ic(f.name)}}</div><h2>{{f.name}}</h2>
<p class=mut>{{kb(f.size)}} · {{left(f)}}{% if f.max_dl %} · {{f.max_dl - f.downloads}} downloads left{% endif %}</p><form method=post action=/s/{{t}}/get class=form><input type=hidden name=csrf value={{csrf}}><button class=btn>⬇ Download file</button></form>
<p class=mut>Shared securely with Vaultly</p></div></div>""", f=f, t=t, kb=kb, left=left, ic=ic)

@app.post("/s/<t>/get")
def dl(t):
    f, e = link(t)
    if e: return err(e[0], e[1], "⏳" if "expired" in e[0] else "🚫")
    cur = db().execute("update files set downloads=downloads+1 where id=? and (max_dl=0 or downloads<max_dl)", (f["id"],)); db().commit()
    if not cur.rowcount: return err("This link has reached its download limit.", 410)
    return send_file(os.path.abspath(f"{D}/files/{f['stored']}"), as_attachment=True,
                     download_name=f["name"], mimetype="application/octet-stream")

if __name__ == "__main__": app.run(port=int(os.environ.get("PORT", 5000)))
