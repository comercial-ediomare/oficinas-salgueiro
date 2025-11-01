from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
import sqlite3, json, os, datetime, csv, io, secrets
from contextlib import closing
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

# --- Configs principais ---
APP_SECRET = os.environ.get("APP_SECRET", "changeme")
ADMIN_USER  = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS_HASH = os.environ.get("ADMIN_PASS_HASH")
ADMIN_PASS      = os.environ.get("ADMIN_PASS")

app = Flask(__name__)
app.secret_key = APP_SECRET
DB_PATH = os.environ.get("DB_PATH", "inscricoes.db")
FALLBACK_DB = "inscricoes.db"

# --- Slots/Horários ---
SLOTS = [
    {"id": 1, "hora": "14h00", "bloqueadas": ["FORTALECENDO-SE NO PODER DO ESPÍRITO"]},
    {"id": 2, "hora": "15h50", "bloqueadas": ["TRANSFORMANDO COMPORTAMENTOS DESTRUTIVOS", "VENCENDO AS MENTIRAS COM A VERDADE"]},
    {"id": 3, "hora": "19h00", "bloqueadas": ["CUIDANDO DO CORPO ONDE O ESPÍRITO HABITA", "DA FRAQUEZA À VITÓRIA: TORNANDO-SE FORTE NA PALAVRA"]},
    {"id": 4, "hora": "20h50", "bloqueadas": ["RAÍZES QUE PRECISAM SER ARRANCADAS", "DOMINANDO AS EMOÇÕES PARA QUE O ESPÍRITO SANTO GOVERNE"]},
]

# --- Helpers de diretório/DB path ---
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
    if _can_use_path(primary):  return primary
    if _can_use_path(fallback): return fallback
    return "inscricoes.db"

def get_db():
    path = _choose_db_path(DB_PATH, FALLBACK_DB)
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn

# --- Init/Migrations ---
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
        # coluna selections_map (JSON {slot_id: workshop_id})
        cur.execute("PRAGMA table_info(attendees)")
        cols = [r["name"] for r in cur.fetchall()]
        if "selections_map" not in cols:
            cur.execute("ALTER TABLE attendees ADD COLUMN selections_map TEXT")

        # Tabela por horário/oficina
        cur.execute("""
        CREATE TABLE IF NOT EXISTS workshop_slots(
            workshop_id INTEGER NOT NULL,
            slot_id     INTEGER NOT NULL,
            capacity    INTEGER NOT NULL,
            registered  INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (workshop_id, slot_id)
        )
        """)

        # Seed workshops (se vazio)
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
                    (n, 30, 0)
                )
        # Garantir capacidade 30 (migração)
        cur.execute("UPDATE workshops SET capacity = 30 WHERE capacity <> 30")

        # Seed workshop_slots: 30 por (oficina, horário) válido (pula bloqueadas)
        # Mapeia id->name
        ws = cur.execute("SELECT id, name FROM workshops").fetchall()
        id_to_name = {w["id"]: w["name"] for w in ws}
        existing = set((r["workshop_id"], r["slot_id"]) for r in cur.execute("SELECT workshop_id, slot_id FROM workshop_slots"))
        for sid, slot in [(s["id"], s) for s in SLOTS]:
            bloqueadas = set(slot["bloqueadas"])
            for wid, wname in id_to_name.items():
                if wname in bloqueadas:
                    continue
                key = (wid, sid)
                if key not in existing:
                    cur.execute(
                        "INSERT INTO workshop_slots(workshop_id, slot_id, capacity, registered) VALUES (?, ?, ?, ?)",
                        (wid, sid, 30, 0)
                    )
        # Migração: garantir capacity=30 em todas as linhas
        cur.execute("UPDATE workshop_slots SET capacity = 30 WHERE capacity <> 30")

        conn.commit()

# --- Bootstrap + Auth/CSRF ---
app.config["BOOTSTRAPPED"] = False
@app.before_request
def _bootstrap_once():
    if not app.config["BOOTSTRAPPED"]:
        init_db()
        global ADMIN_PASS_HASH
        if not ADMIN_PASS_HASH and ADMIN_PASS:
            ADMIN_PASS_HASH = generate_password_hash(ADMIN_PASS)
        app.config["BOOTSTRAPPED"] = True

def _get_csrf_token():
    tok = session.get("_csrf_token")
    if not tok:
        tok = secrets.token_hex(16)
        session["_csrf_token"] = tok
    return tok

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

    # Coleta escolhas por horário
    selected_per_slot = {}
    chosen_ids = []
    for slot in SLOTS:
        val = request.form.get(f"slot_{slot['id']}")
        if val:
            wid = int(val)
            selected_per_slot[slot["id"]] = wid
            chosen_ids.append(wid)

    # Validações básicas
    if not consent:
        flash("Você precisa concordar com o tratamento dos dados.", "error")
        return redirect(url_for("index"))
    if not full_name or not email or "@" not in email:
        flash("Preencha nome e e-mail válidos.", "error")
        return redirect(url_for("index"))
    if len(chosen_ids) < 1:
        flash("Escolha pelo menos 1 oficina (em algum horário).", "error")
        return redirect(url_for("index"))
    if len(chosen_ids) > 4 or len(chosen_ids) != len(set(chosen_ids)):
        flash("Escolha no máximo 4 oficinas, sem repetir.", "error")
        return redirect(url_for("index"))

    # Verifica bloqueios por horário
    with closing(get_db()) as conn:
        ws = conn.execute("SELECT id, name FROM workshops").fetchall()
        id_to_name = {r["id"]: r["name"] for r in ws}
    for slot in SLOTS:
        wid = selected_per_slot.get(slot["id"])
        if wid and id_to_name.get(wid) in slot["bloqueadas"]:
            flash(f"A oficina '{id_to_name[wid]}' não está disponível às {slot['hora']}.", "error")
            return redirect(url_for("index"))

    # Reserva por (workshop_id, slot_id)
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.cursor()

        # E-mail único
        cur.execute("SELECT 1 FROM attendees WHERE email = ?", (email,))
        if cur.fetchone():
            conn.execute("ROLLBACK")
            flash("E-mail já inscrito.", "error")
            return redirect(url_for("index"))

        # Para cada (slot, wid) selecionado, verificar capacidade no workshop_slots
        for sid, wid in selected_per_slot.items():
            row = cur.execute(
                "SELECT capacity, registered FROM workshop_slots WHERE workshop_id=? AND slot_id=?",
                (wid, sid)
            ).fetchone()
            if not row:
                conn.execute("ROLLBACK")
                flash("Uma das escolhas não está disponível neste horário.", "error")
                return redirect(url_for("index"))
            if row["registered"] >= row["capacity"]:
                conn.execute("ROLLBACK")
                flash("Uma das oficinas atingiu o limite neste horário.", "error")
                return redirect(url_for("index"))
            # reserva 1 no slot específico
            cur.execute(
                "UPDATE workshop_slots SET registered = registered + 1 WHERE workshop_id=? AND slot_id=?",
                (wid, sid)
            )

        # (opcional) manter contador geral por oficina (soma dos slots)
        # incrementa uma unidade para cada oficina escolhida (independe do horário)
        for wid in chosen_ids:
            cur.execute("UPDATE workshops SET registered = registered + 1 WHERE id=?", (wid,))

        # grava attendee
        now = datetime.datetime.utcnow().isoformat()
        cur.execute(
            "INSERT INTO attendees(full_name,email,selections,selections_map,created_at) VALUES(?,?,?,?,?)",
            (full_name, email, json.dumps(chosen_ids), json.dumps(selected_per_slot), now)
        )

        conn.execute("COMMIT")
        return redirect(url_for("sucesso"))
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        flash("Erro ao salvar. Tente novamente.", "error")
        return redirect(url_for("index"))
    finally:
        conn.close()

@app.route("/sucesso")
def sucesso():
    return render_template("success.html")

# --- Login/Admin ---
@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    if request.method == "POST":
        user = (request.form.get("username") or "").strip()
        pwd  = (request.form.get("password") or "")
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
        ws = conn.execute("""
            SELECT id,name,capacity,registered,(capacity-registered) AS remaining
            FROM workshops ORDER BY id
        """).fetchall()
        attendees = conn.execute("""
            SELECT full_name,email,selections,created_at
            FROM attendees ORDER BY created_at DESC
        """).fetchall()
    parsed = []
    for a in attendees:
        try:
            sels = json.loads(a["selections"]) or []
        except Exception:
            sels = []
        parsed.append({"full_name": a["full_name"], "email": a["email"], "selections": sels, "created_at": a["created_at"]})
    return render_template("admin.html", workshops=ws, attendees=parsed, csrf_token=_get_csrf_token())

# --- Exports básicos ---
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
    mem = io.BytesIO(output.getvalue().encode("utf-8")); mem.seek(0)
    resp = make_response(mem.read())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=inscricoes.csv"
    return resp

# --- Relatórios ---
def _workshop_map(conn):
    rows = conn.execute("SELECT id, name FROM workshops").fetchall()
    return {r["id"]: r["name"] for r in rows}

def build_reports():
    # Mantemos por compatibilidade (conta via attendees), agora coerente com por-slot
    with closing(get_db()) as conn:
        id2name = _workshop_map(conn)
        attendees = conn.execute("SELECT selections,selections_map FROM attendees").fetchall()

    by_workshop = {int(wid): {"name": name, "count": 0} for wid, name in id2name.items()}
    by_slot = {s["id"]: {"hora": s["hora"], "items": {int(wid): {"name": name, "count": 0} for wid, name in id2name.items()}} for s in SLOTS}

    for a in attendees:
        # total por oficina
        try:
            sel_list = json.loads(a["selections"]) if a["selections"] else []
            if isinstance(sel_list, list):
                for wid in sel_list:
                    try:
                        wid_i = int(wid)
                        if wid_i in by_workshop:
                            by_workshop[wid_i]["count"] += 1
                    except Exception:
                        pass
        except Exception:
            pass

        # por horário
        try:
            sel_map = json.loads(a["selections_map"]) if a["selections_map"] else {}
            if isinstance(sel_map, dict):
                for sid_raw, wid_raw in sel_map.items():
                    try:
                        sid_i = int(sid_raw); wid_i = int(wid_raw)
                        if sid_i in by_slot and wid_i in by_slot[sid_i]["items"]:
                            by_slot[sid_i]["items"][wid_i]["count"] += 1
                    except Exception:
                        continue
        except Exception:
            pass

    return by_workshop, by_slot

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
    mem = io.BytesIO(output.getvalue().encode("utf-8")); mem.seek(0)
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
    mem = io.BytesIO(output.getvalue().encode("utf-8")); mem.seek(0)
    resp = make_response(mem.read())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=relatorio_por_horario.csv"
    return resp

# --- Exports de nomes (opcionais que você já pediu antes) ---
@app.route("/export_names_by_workshop.csv")
@login_required
def export_names_by_workshop_csv():
    with closing(get_db()) as conn:
        ws = conn.execute("SELECT id, name FROM workshops ORDER BY id").fetchall()
        attendees = conn.execute(
            "SELECT full_name, email, selections, selections_map FROM attendees ORDER BY full_name"
        ).fetchall()
    id2name = {int(r["id"]): r["name"] for r in ws}
    slot_hour = {s["id"]: s["hora"] for s in SLOTS}
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["workshop_id", "workshop_name", "full_name", "email", "slot_id", "hora"])
    for a in attendees:
        try:
            sel_list = json.loads(a["selections"]) if a["selections"] else []
        except Exception:
            sel_list = []
        try:
            sel_map = json.loads(a["selections_map"]) if a["selections_map"] else {}
        except Exception:
            sel_map = {}
        wid_to_slot = {}
        if isinstance(sel_map, dict):
            for sid_raw, wid_raw in sel_map.items():
                try:
                    sid_i = int(sid_raw); wid_i = int(wid_raw)
                    wid_to_slot[wid_i] = sid_i
                except Exception:
                    pass
        for wid_raw in sel_list or []:
            try:
                wid = int(wid_raw)
            except Exception:
                continue
            wname = id2name.get(wid, f"ID {wid}")
            sid = wid_to_slot.get(wid)
            hora = slot_hour.get(sid, "")
            writer.writerow([wid, wname, a["full_name"], a["email"], sid or "", hora])
    mem = io.BytesIO(output.getvalue().encode("utf-8")); mem.seek(0)
    resp = make_response(mem.read())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=nomes_por_oficina.csv"
    return resp

@app.route("/export_grouped_names_by_workshop_slot.csv")
@login_required
def export_grouped_names_by_workshop_slot_csv():
    with closing(get_db()) as conn:
        ws = conn.execute("SELECT id, name FROM workshops ORDER BY id").fetchall()
        attendees = conn.execute(
            "SELECT full_name, email, selections, selections_map FROM attendees ORDER BY full_name"
        ).fetchall()
    id2name = {int(r["id"]): r["name"] for r in ws}
    slot_hour = {s["id"]: s["hora"] for s in SLOTS}
    grouped = {}
    for a in attendees:
        try:
            sel_list = json.loads(a["selections"]) if a["selections"] else []
        except Exception:
            sel_list = []
        try:
            sel_map = json.loads(a["selections_map"]) if a["selections_map"] else {}
        except Exception:
            sel_map = {}
        wid_to_slot = {}
        if isinstance(sel_map, dict):
            for sid_raw, wid_raw in sel_map.items():
                try:
                    sid_i = int(sid_raw); wid_i = int(wid_raw)
                    wid_to_slot[wid_i] = sid_i
                except Exception:
                    pass
        for wid_raw in sel_list or []:
            try:
                wid = int(wid_raw)
            except Exception:
                continue
            sid = wid_to_slot.get(wid)
            key = (wid, sid)
            rec = grouped.setdefault(key, {"names": [], "emails": []})
            rec["names"].append(a["full_name"])
            rec["emails"].append(a["email"])
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["workshop_id", "workshop_name", "slot_id", "hora", "inscritos_count", "nomes", "emails"])
    def sort_key(item):
        (wid, sid), rec = item
        wname = id2name.get(wid, f"ID {wid}")
        hora = slot_hour.get(sid, "") if sid else ""
        return (wname.lower(), hora)
    for (wid, sid), rec in sorted(grouped.items(), key=sort_key):
        wname = id2name.get(wid, f"ID {wid}")
        hora = slot_hour.get(sid, "") if sid else ""
        writer.writerow([wid, wname, sid or "", hora, len(rec["names"]), "; ".join(rec["names"]), "; ".join(rec["emails"])])
    mem = io.BytesIO(output.getvalue().encode("utf-8")); mem.seek(0)
    resp = make_response(mem.read())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=nomes_agrupados_por_oficina_e_horario.csv"
    return resp

# --- Resetar Base (agora inclui workshop_slots) ---
@app.post("/admin/reset")
@login_required
def admin_reset():
    form_tok = request.form.get("_csrf_token") or ""
    if not form_tok or form_tok != session.get("_csrf_token"):
        flash("Falha de validação (CSRF). Recarregue a página e tente novamente.", "error")
        return redirect(url_for("admin"))
    with closing(get_db()) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM attendees")
        cur.execute("UPDATE workshops SET registered = 0")
        cur.execute("UPDATE workshop_slots SET registered = 0")
        conn.commit()
    flash("Base resetada com sucesso: inscrições removidas e contadores zerados (por horário e geral).", "message")
    return redirect(url_for("admin"))

# --- Execução local ---
if __name__ == "__main__":
    app.run(debug=True)
