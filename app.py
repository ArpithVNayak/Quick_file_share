import os, sqlite3, secrets, time, uuid
from flask import Flask, request, session, redirect, g, abort, render_template_string as R, send_file, flash
from werkzeug.security import generate_password_hash as gph, check_password_hash as cph
from werkzeug.utils import secure_filename

D = os.environ.get("DATA_DIR", "data"); os.makedirs(D + "/files", exist_ok=True)
MAX_FILE = 10 * 1024 * 1024; QUOTA = 50 * 1024 * 1024
ALLOWED = {"pdf", "png", "jpg", "jpeg", "gif", "txt", "csv", "zip", "docx", "mp3", "mp4"}
MAGIC = {"pdf": b"%PDF", "png": b"\x89PNG", "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff",
         "gif": b"GIF8", "zip": b"PK\x03\x04", "docx": b"PK\x03\x04"}
EXP = {"1h": 3600, "24h": 86400, "7d": 604800}

app = Flask(__name__)
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

@app.after_request
def hdr(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"
    return r

@app.before_request
def csrf():
    if request.method == "POST":
        if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")): abort(400, "Bad CSRF token")
@app.context_processor
def ctx():
    session.setdefault("csrf", secrets.token_hex(16)); return dict(csrf=session["csrf"], user=session.get("uid"))

def login_req(f):
    from functools import wraps
    @wraps(f)
    def w(*a, **k):
        if "uid" not in session: return redirect("/login")
        return f(*a, **k)
    return w

hits = {}
def limited(key, n=10, win=300):
    t = time.time(); h = [x for x in hits.get(key, []) if t - x < win]; h.append(t); hits[key] = h
    return len(h) > n

BASE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>FileShare</title><style>body{font:16px system-ui;max-width:760px;margin:2rem auto;padding:0 1rem}
table{width:100%;border-collapse:collapse}td,th{padding:.4rem;border-bottom:1px solid #ddd;text-align:left}
.m{background:#eef;padding:.5rem;margin:.5rem 0}.bad{color:#b00}input,select,button{padding:.4rem;margin:.1rem}</style>
<h2>FileShare</h2>{% if user %}<form method=post action=/logout style=display:inline><input type=hidden name=csrf value={{csrf}}>
<a href=/>Dashboard</a> <button>Logout</button></form>{% endif %}
{% for m in get_flashed_messages() %}<div class=m>{{m}}</div>{% endfor %}"""

def page(body, **k): return R(BASE + body, **k)

@app.route("/register", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def auth():
    reg = request.path == "/register"
    if request.method == "POST":
        if limited(request.remote_addr): return "Too many attempts, try later.", 429
        n, p = request.form.get("name", "").strip()[:40], request.form.get("pw", "")
        if reg:
            if len(n) < 3 or len(p) < 8: flash("Username 3+ chars, password 8+ chars.")
            else:
                try:
                    db().execute("insert into users(name,pw) values(?,?)", (n, gph(p))); db().commit()
                    flash("Registered. Please log in."); return redirect("/login")
                except sqlite3.IntegrityError: flash("Username taken.")
        else:
            u = db().execute("select * from users where name=?", (n,)).fetchone()
            if u and cph(u["pw"], p):
                session.clear(); session["uid"] = u["id"]; return redirect("/")
            flash("Invalid credentials.")
    return page("<h3>{{t}}</h3><form method=post><input type=hidden name=csrf value={{csrf}}><input name=name placeholder=username required>"
                "<input name=pw type=password placeholder=password required><button>{{t}}</button></form>"
                "<p><a href={{'/login' if reg else '/register'}}>{{'Login' if reg else 'Register'}} instead</a></p>",
                t="Register" if reg else "Login")

@app.post("/logout")
def logout(): session.clear(); return redirect("/login")

def status(f):
    if not f["token"]: return "not shared"
    if f["revoked"]: return "revoked"
    if f["expires"] < time.time(): return "expired"
    return "active"

@app.route("/")
@login_req
def dash():
    fs = db().execute("select * from files where owner=? order by id desc", (session["uid"],)).fetchall()
    used = sum(f["size"] for f in fs)
    return page("""<p>Storage: {{(used/1048576)|round(2)}} / {{q}} MB &middot; Max file {{m}} MB &middot; Types: {{a}}</p>
<form method=post action=/upload enctype=multipart/form-data><input type=hidden name=csrf value={{csrf}}>
<input type=file name=file required><button>Upload</button></form>
<table><tr><th>File<th>Size<th>Link<th>Downloads<th></tr>
{% for f in fs %}<tr><td>{{f.name}}<td>{{(f.size/1024)|round(1)}} KB<td>{{st(f)}}
{% if f.token and st(f)=='active' %}<br><input readonly size=30 value="{{host}}s/{{f.token}}" onfocus=this.select()>{% endif %}
<td>{{f.downloads}}<td><form method=post action=/share/{{f.id}} style=display:inline><input type=hidden name=csrf value={{csrf}}>
<select name=exp>{% for k in exps %}<option>{{k}}{% endfor %}</select><button>Share</button></form>
<form method=post action=/revoke/{{f.id}} style=display:inline><input type=hidden name=csrf value={{csrf}}><button>Revoke</button></form>
<form method=post action=/delete/{{f.id}} style=display:inline onsubmit="return confirm('Delete?')"><input type=hidden name=csrf value={{csrf}}><button>Delete</button></form>
</tr>{% endfor %}</table>""", fs=fs, used=used, q=QUOTA // 1048576, m=MAX_FILE // 1048576,
                a=", ".join(sorted(ALLOWED)), st=status, exps=EXP, host=request.host_url)

@app.errorhandler(413)
def big(e): return page("<p class=bad>File too large (max {{m}} MB).</p><a href=/>Back</a>", m=MAX_FILE // 1048576), 413

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
    db().execute("update files set token=?,expires=?,revoked=0 where id=?", (secrets.token_urlsafe(32), time.time() + sec, i))
    db().commit(); return redirect("/")

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
    return f, None

@app.route("/s/<t>")
def dl_page(t):
    if limited("dl" + request.remote_addr, 120): return "Too many requests", 429
    f, err = link(t)
    if err: return page("<p class=bad>{{m}}</p>", m=err[0]), err[1]
    return page("<h3>{{f.name}}</h3><p>{{(f.size/1024)|round(1)}} KB</p><form method=post action=/s/{{t}}/get>"
                "<input type=hidden name=csrf value={{csrf}}><button>Download</button></form>", f=f, t=t)

@app.post("/s/<t>/get")
def dl(t):
    f, err = link(t)
    if err: return page("<p class=bad>{{m}}</p>", m=err[0]), err[1]
    db().execute("update files set downloads=downloads+1 where id=?", (f["id"],)); db().commit()
    return send_file(os.path.abspath(f"{D}/files/{f['stored']}"), as_attachment=True,
                     download_name=f["name"], mimetype="application/octet-stream")

if __name__ == "__main__": app.run(port=int(os.environ.get("PORT", 5000)))
