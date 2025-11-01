from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
import sqlite3, json, os, datetime, csv, io
from contextlib import closing
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

# --- Configurações principais ---
APP_SECRET = os.environ.get("APP_SECRET", "changeme")
ADMIN_USER  = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS_HASH = os.environ.get("ADMIN_PASS_HASH")
ADMIN_PASS      = os.environ.get("ADMIN_PASS")

app = Flask(__name__)
app.secret_key = APP_SECRET
DB_PATH = os.environ.get("DB_PATH", "inscricoes.db")
FALLBACK_DB = "inscricoes.db"

# --- Helpers de diretório ---
def _is_writable_dir(dirpath: str) -> bool:
    return os.path.isdir(dirpath) and os.access(dirpath, os.W_OK)

def _can_use_path(path: str) -> bool:
    dirpath = os.path.dirname(path)
    if not dirpath:
        return True
    if dirpath.startswith("/data"):
        return _is_writable_dir(dirpath)
    try:
        if not os.path.exists(dirpath):
            os.makedirs(dirpath, exist_ok=True)
    except Exception:
        return False
    return _is_writable_dir(dirpath)

def _choose_db_path(primary: str, fallback: str) -> str:
    if _can_use_path(primary):
        return primary
    if _can_use_path(fallback):
        return fallback
    return "inscricoes.db"

# --- Conexão e inicialização do banco ---
def get_db():
    path = _choose_db_path(DB_PATH, FALLBACK_DB)
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with closing(get_db()) as conn:
        cur = conn.cursor()
        cur.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS workshops(
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            capacity INTEGER NOT NULL,
            registered INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS attendees(
            id INTEGER PRIMARY KEY,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            selections TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)
        # --- (A) MIGRAÇÃO LEVE ---
        cur.execute("PRAGMA table_info(attendees)")
        cols = [r["name"] for r in cur.fetchall()]
        if "selections_map" not in cols:
            cur.execute("ALTER TABLE attendees ADD COLUMN selections_map TEXT")

        # Seed inicial
        cur.execute("SELECT COUNT(*) c FROM workshops")
        if cur.fetchone()["c"] == 0:
            names = [
                "TRANSFORMANDO COMPORTAMENTOS DESTRUTIVOS",
                "RAÍZES QUE PRECISAM SER ARRANCADAS",
                "VENCENDO AS MENTIRAS COM A VERDADE",
                "CUIDANDO DO CORPO ONDE O ESPÍRITO HABITA",
                "DOMINANDO AS EMOÇÕES PARA QUE O ESPÍRITO SANTO GOVERNE",
                "DA FRAQUEZA À VITÓRIA: TORNANDO-SE FORTE NA PALAVRA",
                "FORTALECENDO-SE NO PODER DO ESPÍRITO",
            ]
            for n in names:
                cur.execute(
                    "INSERT INTO workshops(name, capacity, registered) VALUES (?, ?, ?)",
                    (n, 40, 0)
                )
        conn.commit()

# --- Estrutura de horários ---
SLOTS = [
    {"id": 1, "hora": "14h00", "bloqueadas": ["FORTALECENDO-SE NO PODER DO ESPÍRITO"]},
    {"id": 2, "hora": "15h50", "bloqueadas": ["TRANSFORMANDO COMPORTAMENTOS DESTRUTIVOS", "VENCENDO AS MENTIRAS COM A VERDADE"]},
    {"id": 3, "hora": "19h00", "bloqueadas": ["CUIDANDO DO CORPO ONDE O ESPÍRITO HABITA", "DA FRAQUEZA À VITÓRIA: TORNANDO-SE FORTE NA PALAVRA"]},
    {"id": 4, "hora": "20h50", "bloqueadas": ["RAÍZES QUE PRECISAM SER ARRANCADAS", "DOMINANDO AS EMOÇÕES PARA QUE O ESPÍRITO SANTO GOVERNE"]},
]

# --- Bootstrap ---
app.config["BOOTSTRAPPED"] = False
@app.before_request
def _bootstrap_once():
    if not app.config["BOOTSTRAPPED"]:
        init_db()
        global ADMIN_PASS_HASH
        if not ADMIN_PASS_HASH and ADMIN_PASS:
            ADMIN_PASS_HASH = generate_password_hash(ADMIN_PASS)
        app.config["BOOTSTRAPPED"] = True

# --- Login helper ---
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_logged"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

# --- Rotas públicas ---
@app.route("/")
def index():
    with closing(get_db()) as conn:
        workshops = conn.execute("SELECT * FROM workshops ORDER BY id").fetchall()
    return render_template("index.html", workshops=workshops, slots=SLOTS)

@app.route("/inscrever", methods=["POST"])
def inscrever():
    full_name = (request.form.get("full_name") or "").strip()
    email     = (request.form.get("email") or "").strip().lower()
    consent   = request.form.get("consent") == "on"

    selected_per_slot = {}
    chosen_ids = []
    for slot in SLOTS:
        val = request.form.get(f"slot_{slot['id']}")
        if val:
            wid = int(val)
            selected_per_slot[slot["id"]] = wid
            chosen_ids.append(wid)

    if not consent:
        flash("Você precisa concordar com o tratamento dos dados.", "error")
        return redirect(url_for("index"))
    if not full_name or not email or "@" not in email:
        flash("Preencha nome e e-mail válidos.", "error")
        return redirect(url_for("index"))
    if len(chosen_ids) < 1:
        flash("Escolha pelo menos 1 oficina.", "error")
        return redirect(url_for("index"))
    if len(chosen_ids) > 4 or len(chosen_ids) != len(set(chosen_ids)):
        flash("Escolha no máximo 4 oficinas, sem repetir.", "error")
        return redirect(url_for("index"))

    with closing(get_db()) as conn:
        ws = conn.execute("SELECT id, name FROM workshops").fetchall()
        id_to_name = {r["id"]: r["name"] for r in ws}

    for slot in SLOTS:
        wid = selected_per_slot.get(slot["id"])
        if wid and id_to_name.get(wid) in slot["bloqueadas"]:
            flash(f"A oficina '{id_to_name[wid]}' não está disponível às {slot['hora']}.", "error")
            return redirect(url_for("index"))

    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM attendees WHERE email=?", (email,))
        if cur.fetchone():
            conn.execute("ROLLBACK")
            flash("E-mail já inscrito.", "error")
            return redirect(url_for("index"))
        for wid in chosen_ids:
            cur.execute("SELECT capacity, registered FROM workshops WHERE id=?", (wid,))
            row = cur.fetchone()
            if not row or row["registered"] >= row["capacity"]:
                conn.execute("ROLLBACK")
                flash("Uma das oficinas está lotada.", "error")
                return redirect(url_for("index"))
            cur.execute("UPDATE workshops SET registered = registered + 1 WHERE id=?", (wid,))
        now = datetime.datetime.utcnow().isoformat()
        cur.execute(
            "INSERT INTO attendees(full_name,email,selections,selections_map,created_at) VALUES(?,?,?,?,?)",
            (full_name, email, json.dumps(chosen_ids), json.dumps(selected_per_slot), now)
        )
        conn.execute("COMMIT")
        return redirect(url_for("sucesso"))
    except Exception:
        conn.execute("ROLLBACK")
        flash("Erro ao salvar. Tente novamente.", "error")
        return redirect(url_for("index"))
    finally:
        conn.close()

@app.route("/sucesso")
def sucesso():
    return render_template("success.html")

# --- Login / Admin ---
@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    if request.method == "POST":
        user = (request.form.get("username") or "").strip()
        pwd  = request.form.get("password") or ""
        if user != ADMIN_USER or not ADMIN_PASS_HASH or not check_password_hash(ADMIN_PASS_HASH, pwd):
            error = "Usuário ou senha inválidos."
        else:
            session["admin_logged"] = True
            return redirect(request.args.get("next") or url_for("admin"))
    return render_template("login.html", error=error)

@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Sessão encerrada.", "message")
    return redirect(url_for("login"))

@app.route("/admin")
@login_required
def admin():
    with closing(get_db()) as conn:
        ws = conn.execute("SELECT id,name,capacity,registered,(capacity-registered) AS remaining FROM workshops ORDER BY id").fetchall()
        attendees = conn.execute("SELECT full_name,email,selections,created_at FROM attendees ORDER BY created_at DESC").fetchall()
    parsed = []
    for a in attendees:
        try:
            sels = json.loads(a["selections"]) or []
        except Exception:
            sels = []
        parsed.append({"full_name": a["full_name"], "email": a["email"], "selections": sels, "created_at": a["created_at"]})
    return render_template("admin.html", workshops=ws, attendees=parsed)

@app.route("/export.csv")
@login_required
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    with closing(get_db()) as conn:
        ws = conn.execute("SELECT * FROM workshops ORDER BY id").fetchall()
        at = conn.execute("SELECT * FROM attendees ORDER BY created_at DESC").fetchall()
    writer.writerow(["WORKSHOPS"])
    writer.writerow(["id","name","capacity","registered"])
    for w in ws:
        writer.writerow([w["id"],w["name"],w["capacity"],w["registered"]])
    writer.writerow([])
    writer.writerow(["ATTENDEES"])
    writer.writerow(["full_name","email","selections","created_at"])
    for a in at:
        writer.writerow([a["full_name"],a["email"],a["selections"],a["created_at"]])
    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    resp = make_response(mem.read())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=inscricoes.csv"
    return resp

# --- Helpers de relatório ---
def _workshop_map(conn):
    rows = conn.execute("SELECT id, name FROM workshops").fetchall()
    return {r["id"]: r["name"] for r in rows}

def build_reports():
    with closing(get_db()) as conn:
        id2name = _workshop_map(conn)
        attendees = conn.execute("SELECT selections,selections_map FROM attendees").fetchall()

    by_workshop = {int(wid): {"name": name, "count": 0} for wid, name in id2name.items()}
    by_slot = {s["id"]: {"hora": s["hora"], "items": {int(wid): {"name": name, "count": 0} for wid, name in id2name.items()}} for s in SLOTS}

    for a in attendees:
        try:
            sel_list = json.loads(a["selections"]) if a["selections"] else []
            if isinstance(sel_list, list):
                for wid in sel_list:
                    wid_i = int(wid)
                    if wid_i in by_workshop:
                        by_workshop[wid_i]["count"] += 1
        except Exception:
            pass

        try:
            sel_map = json.loads(a["selections_map"]) if a["selections_map"] else {}
            if isinstance(sel_map, dict):
                for sid_raw, wid_raw in sel_map.items():
                    try:
                        sid_i = int(sid_raw)
                        wid_i = int(wid_raw)
                        if sid_i in by_slot and wid_i in by_slot[sid_i]["items"]:
                            by_slot[sid_i]["items"][wid_i]["count"] += 1
                    except Exception:
                        continue
        except Exception:
            pass

    return by_workshop, by_slot

# --- Rotas de relatórios ---
@app.route("/reports")
@login_required
def reports():
    by_workshop, by_slot = build_reports()
    ws_sorted = sorted(by_workshop.items(), key=lambda kv: kv[1]["name"])
    slots_view = []
    for s in SLOTS:
        sid = s["id"]
        items = by_slot[sid]["items"]
        rows = sorted(items.items(), key=lambda kv: kv[1]["name"])
        slots_view.append({"id": sid, "hora": s["hora"], "rows": rows})
    return render_template("reports.html", ws=ws_sorted, slots=slots_view)

@app.route("/export_by_workshop.csv")
@login_required
def export_by_workshop_csv():
    by_workshop, _ = build_reports()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["workshop_id","workshop_name","inscritos_total"])
    for wid, data in sorted(by_workshop.items(), key=lambda kv: kv[1]["name"]):
        writer.writerow([wid,data["name"],data["count"]])
    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    resp = make_response(mem.read())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=relatorio_por_oficina.csv"
    return resp

@app.route("/export_by_slot.csv")
@login_required
def export_by_slot_csv():
    _, by_slot = build_reports()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["slot_id","hora","workshop_id","workshop_name","inscritos_no_horario"])
    for s in SLOTS:
        sid, hora = s["id"], s["hora"]
        items = by_slot[sid]["items"]
        for wid, data in sorted(items.items(), key=lambda kv: kv[1]["name"]):
            writer.writerow([sid,hora,wid,data["name"],data["count"]])
    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    resp = make_response(mem.read())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=relatorio_por_horario.csv"
    return resp

# --- Execução local ---
if __name__ == "__main__":
    app.run(debug=True)
