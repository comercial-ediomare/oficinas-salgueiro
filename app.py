from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
import sqlite3, json, os, datetime, csv, io, secrets
from contextlib import closing
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from datetime import datetime as dt, timedelta

# =========================
# Configurações principais
# =========================
APP_SECRET      = os.environ.get("APP_SECRET", "changeme")
ADMIN_USER      = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS_HASH = os.environ.get("ADMIN_PASS_HASH")
ADMIN_PASS      = os.environ.get("ADMIN_PASS")
DB_PATH         = os.environ.get("DB_PATH", "inscricoes.db")
FALLBACK_DB     = "inscricoes.db"

PER_SLOT_CAPACITY = 40  # vagas por horário/oficina

app = Flask(__name__)
app.secret_key = APP_SECRET

# =========================
# Horários e bloqueios
# =========================
SLOTS = [
    {"id": 1, "hora": "14h00", "bloqueadas": ["FORTALECENDO-SE NO PODER DO ESPÍRITO"]},
    {"id": 2, "hora": "15h50", "bloqueadas": ["TRANSFORMANDO COMPORTAMENTOS DESTRUTIVOS", "VENCENDO AS MENTIRAS COM A VERDADE"]},
    {"id": 3, "hora": "19h00", "bloqueadas": ["CUIDANDO DO CORPO ONDE O ESPÍRITO HABITA", "DA FRAQUEZA À VITÓRIA: TORNANDO-SE FORTE NA PALAVRA"]},
    {"id": 4, "hora": "20h50", "bloqueadas": ["RAÍZES QUE PRECISAM SER ARRANCADAS", "DOMINANDO AS EMOÇÕES PARA QUE O ESPÍRITO SANTO GOVERNE"]},
]

# =========================
# Helpers de banco de dados
# =========================
def _choose_db_path(primary: str, fallback: str) -> str:
    dirpath = os.path.dirname(primary)
    try:
        if dirpath and not os.path.exists(dirpath):
            os.makedirs(dirpath, exist_ok=True)
        return primary
    except Exception:
        return fallback

def get_db():
    path = _choose_db_path(DB_PATH, FALLBACK_DB)
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn

# =========================
# Inicialização do BD
# =========================
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
            selections_map TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS workshop_slots(
            workshop_id INTEGER NOT NULL,
            slot_id     INTEGER NOT NULL,
            capacity    INTEGER NOT NULL,
            registered  INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (workshop_id, slot_id)
        );
        """)

        # Seed workshops
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
                    "INSERT INTO workshops(name, capacity, registered) VALUES (?, ?, 0)",
                    (n, PER_SLOT_CAPACITY)
                )

        # Seed workshop_slots com base nos bloqueios por horário
        ws = cur.execute("SELECT id, name FROM workshops").fetchall()
        id2name = {w["id"]: w["name"] for w in ws}
        existing = set((r["workshop_id"], r["slot_id"]) for r in cur.execute(
            "SELECT workshop_id, slot_id FROM workshop_slots"
        ))
        for slot in SLOTS:
            bloqueadas = set(slot["bloqueadas"])
            for wid, wname in id2name.items():
                if wname in bloqueadas:
                    continue
                if (wid, slot["id"]) not in existing:
                    cur.execute(
                        "INSERT INTO workshop_slots(workshop_id, slot_id, capacity, registered) VALUES (?, ?, ?, 0)",
                        (wid, slot["id"], PER_SLOT_CAPACITY)
                    )

        # Mantém a capacidade por slot consistente
        cur.execute("UPDATE workshop_slots SET capacity = ? WHERE capacity <> ?", (PER_SLOT_CAPACITY, PER_SLOT_CAPACITY))

        conn.commit()

# =========================
# Bootstrap + autenticação
# =========================
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

# =========================
# Página pública de inscrição
# =========================
@app.route("/")
def index():
    with closing(get_db()) as conn:
        workshops = conn.execute("SELECT * FROM workshops ORDER BY id").fetchall()
        slot_rows = conn.execute("SELECT workshop_id, slot_id, capacity, registered FROM workshop_slots").fetchall()

    # avail[slot_id][workshop_id] = {capacity, registered, remaining}
    avail = {}
    for r in slot_rows:
        sid, wid = int(r["slot_id"]), int(r["workshop_id"])
        cap, reg = int(r["capacity"]), int(r["registered"])
        avail.setdefault(sid, {})[wid] = {
            "capacity": cap,
            "registered": reg,
            "remaining": max(0, cap - reg),
        }

    return render_template("index.html", workshops=workshops, slots=SLOTS, avail=avail)

@app.route("/inscrever", methods=["POST"])
def inscrever():
    full_name = (request.form.get("full_name") or "").strip()
    email     = (request.form.get("email") or "").strip().lower()
    consent   = request.form.get("consent") == "on"

    # coleta escolhas por slot
    selected_per_slot = {}
    chosen_ids = []
    for slot in SLOTS:
        val = request.form.get(f"slot_{slot['id']}")
        if val:
            wid = int(val)
            selected_per_slot[slot["id"]] = wid
            chosen_ids.append(wid)

    # validações
    if not consent:
        flash("Você precisa autorizar o uso dos dados.", "error")
        return redirect(url_for("index"))
    if not full_name or not email or "@" not in email:
        flash("Preencha nome e e-mail válidos.", "error")
        return redirect(url_for("index"))
    if len(chosen_ids) < 1:
        flash("Escolha pelo menos uma oficina.", "error")
        return redirect(url_for("index"))
    if len(chosen_ids) > 4 or len(chosen_ids) != len(set(chosen_ids)):
        flash("Escolha no máximo 4 oficinas e sem repetir.", "error")
        return redirect(url_for("index"))

    # valida bloqueios por horário
    with closing(get_db()) as conn:
        ws = conn.execute("SELECT id, name FROM workshops").fetchall()
        id_to_name = {r["id"]: r["name"] for r in ws}
    for slot in SLOTS:
        wid = selected_per_slot.get(slot["id"])
        if wid and id_to_name.get(wid) in slot["bloqueadas"]:
            flash(f"A oficina '{id_to_name[wid]}' não está disponível às {slot['hora']}.", "error")
            return redirect(url_for("index"))

    # reserva
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.cursor()

        # e-mail único
        if cur.execute("SELECT 1 FROM attendees WHERE email=?", (email,)).fetchone():
            conn.execute("ROLLBACK")
            flash("E-mail já inscrito.", "error")
            return redirect(url_for("index"))

        # checa e reserva por (workshop_id, slot_id)
        for sid, wid in selected_per_slot.items():
            row = cur.execute(
                "SELECT capacity, registered FROM workshop_slots WHERE workshop_id=? AND slot_id=?",
                (wid, sid)
            ).fetchone()
            if not row or row["registered"] >= row["capacity"]:
                conn.execute("ROLLBACK")
                flash("Uma das oficinas atingiu o limite neste horário.", "error")
                return redirect(url_for("index"))
            cur.execute(
                "UPDATE workshop_slots SET registered = registered + 1 WHERE workshop_id=? AND slot_id=?",
                (wid, sid)
            )

        # mantém contador geral por oficina (não usado no admin para total, mas mantemos)
        for wid in chosen_ids:
            cur.execute("UPDATE workshops SET registered = registered + 1 WHERE id=?", (wid,))

        now_iso = datetime.datetime.utcnow().isoformat()
        cur.execute(
            "INSERT INTO attendees(full_name,email,selections,selections_map,created_at) VALUES(?,?,?,?,?)",
            (full_name, email, json.dumps(chosen_ids), json.dumps(selected_per_slot), now_iso)
        )

        conn.execute("COMMIT")
        return redirect(url_for("sucesso"))
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        flash("Erro ao salvar inscrição. Tente novamente.", "error")
        return redirect(url_for("index"))
    finally:
        conn.close()

@app.route("/sucesso")
def sucesso():
    return render_template("success.html")

# =========================
# Login / Admin
# =========================
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
    # capacidade total por oficina = soma dos slots; inscritos = recontados de attendees
    with closing(get_db()) as conn:
        cap_rows = conn.execute("""
            SELECT w.id AS wid, w.name AS name,
                   COALESCE(SUM(ws.capacity),0) AS cap_total
            FROM workshops w
            LEFT JOIN workshop_slots ws ON ws.workshop_id = w.id
            GROUP BY w.id, w.name
            ORDER BY w.id
        """).fetchall()
        at_rows = conn.execute("""
            SELECT id, full_name, email, selections, selections_map, created_at
            FROM attendees
            ORDER BY created_at DESC
        """).fetchall()

    cap_by_wid  = {int(r["wid"]): int(r["cap_total"]) for r in cap_rows}
    name_by_wid = {int(r["wid"]): r["name"] for r in cap_rows}

    reg_by_wid = {wid: 0 for wid in cap_by_wid.keys()}
    for a in at_rows:
        try:
            sel = json.loads(a["selections"]) if a["selections"] else []
            if isinstance(sel, list):
                for wid_raw in sel:
                    wid = int(wid_raw)
                    if wid in reg_by_wid:
                        reg_by_wid[wid] += 1
        except Exception:
            pass

    workshops_view = []
    for wid in sorted(cap_by_wid.keys()):
        cap_total = cap_by_wid[wid]
        reg_total = reg_by_wid.get(wid, 0)
        workshops_view.append({
            "id": wid,
            "name": name_by_wid.get(wid, f"ID {wid}"),
            "capacity_total": cap_total,
            "registered_total": reg_total,
            "remaining_total": max(0, cap_total - reg_total),
        })

    parsed_attendees = []
    for a in at_rows:
        try:
            utc_dt = dt.fromisoformat(a["created_at"])
            local_dt = utc_dt - timedelta(hours=3)  # GMT-3
            created_local = local_dt.strftime("%d/%m/%Y %H:%M")
        except Exception:
            created_local = a["created_at"]
        try:
            sels = json.loads(a["selections"]) or []
        except Exception:
            sels = []
        parsed_attendees.append({
            "id": a["id"],
            "full_name": a["full_name"],
            "email": a["email"],
            "selections": sels,
            "created_at_local": created_local,
        })

    return render_template("admin.html",
                           workshops=workshops_view,
                           attendees=parsed_attendees,
                           csrf_token=_get_csrf_token())

# =========================
# Excluir inscrição individual
# =========================
@app.post("/admin/attendee/<int:att_id>/delete")
@login_required
def delete_attendee(att_id):
    form_tok = request.form.get("_csrf_token") or ""
    if not form_tok or form_tok != session.get("_csrf_token"):
        flash("Falha de validação (CSRF). Recarregue a página e tente novamente.", "error")
        return redirect(url_for("admin"))

    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.cursor()

        row = cur.execute("""
            SELECT id, selections, selections_map
            FROM attendees
            WHERE id = ?
        """, (att_id,)).fetchone()

        if not row:
            conn.execute("ROLLBACK")
            flash("Inscrição não encontrada.", "error")
            return redirect(url_for("admin"))

        # devolve vagas por (workshop_id, slot_id)
        try:
            sel_list = json.loads(row["selections"]) if row["selections"] else []
        except Exception:
            sel_list = []
        try:
            sel_map = json.loads(row["selections_map"]) if row["selections_map"] else {}
        except Exception:
            sel_map = {}

        if isinstance(sel_map, dict):
            for sid_raw, wid_raw in sel_map.items():
                try:
                    sid = int(sid_raw); wid = int(wid_raw)
                except Exception:
                    continue
                cur.execute("""
                    UPDATE workshop_slots
                       SET registered = CASE WHEN registered > 0 THEN registered - 1 ELSE 0 END
                     WHERE workshop_id = ? AND slot_id = ?
                """, (wid, sid))

        if isinstance(sel_list, list):
            for wid_raw in set(sel_list):
                try:
                    wid = int(wid_raw)
                except Exception:
                    continue
                cur.execute("""
                    UPDATE workshops
                       SET registered = CASE WHEN registered > 0 THEN registered - 1 ELSE 0 END
                     WHERE id = ?
                """, (wid,))

        cur.execute("DELETE FROM attendees WHERE id = ?", (att_id,))
        conn.execute("COMMIT")
        flash("Inscrição excluída com sucesso.", "message")
    except Exception:
        try: conn.execute("ROLLBACK")
        except Exception: pass
        flash("Erro ao excluir a inscrição.", "error")
    finally:
        conn.close()

    return redirect(url_for("admin"))

# =========================
# Reset base
# =========================
@app.post("/admin/reset")
@login_required
def admin_reset():
    tok = request.form.get("_csrf_token") or ""
    if not tok or tok != session.get("_csrf_token"):
        flash("Falha de validação (CSRF). Recarregue a página.", "error")
        return redirect(url_for("admin"))
    with closing(get_db()) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM attendees")
        cur.execute("UPDATE workshops SET registered = 0")
        cur.execute("UPDATE workshop_slots SET registered = 0")
        conn.commit()
    flash("Base resetada com sucesso: inscrições removidas e contadores zerados.", "message")
    return redirect(url_for("admin"))

# =========================
# Relatórios (tela) – matriz por pessoa
# =========================
@app.route("/reports")
@login_required
def reports():
    # Matriz: 1 linha por pessoa; colunas por horário
    with closing(get_db()) as conn:
        attendees = conn.execute(
            "SELECT full_name, email, selections_map FROM attendees ORDER BY full_name"
        ).fetchall()
        wmap = {r["id"]: r["name"] for r in conn.execute("SELECT id, name FROM workshops")}
    people = []
    for a in attendees:
        try:
            sel_map = json.loads(a["selections_map"]) if a["selections_map"] else {}
        except Exception:
            sel_map = {}
        row = {"full_name": a["full_name"], "email": a["email"]}
        for s in SLOTS:
            sid = s["id"]
            wid = sel_map.get(str(sid))
            if wid is None:
                wid = sel_map.get(sid)  # caso salvo como int
            row[f"slot_{sid}"] = wmap.get(int(wid), "") if wid else ""
        people.append(row)
    return render_template("reports.html", slots=SLOTS, people=people)

# =========================
# Export CSV – Opção B (Oficina | Horário | Nome | E-mail)
# =========================
@app.route("/export_names_rows_by_workshop_slot.csv")
@login_required
def export_names_rows_by_workshop_slot_csv():
    # Cada linha: Oficina | Horário | Nome | E-mail
    with closing(get_db()) as conn:
        ws = conn.execute("SELECT id, name FROM workshops ORDER BY name").fetchall()
        attendees = conn.execute(
            "SELECT full_name, email, selections, selections_map FROM attendees ORDER BY full_name"
        ).fetchall()

    id2name = {int(r["id"]): r["name"] for r in ws}
    slot_hour = {s["id"]: s["hora"] for s in SLOTS}

    rows = []
    for a in attendees:
        try:
            sel_list = json.loads(a["selections"]) if a["selections"] else []
        except Exception:
            sel_list = []
        try:
            sel_map = json.loads(a["selections_map"]) if a["selections_map"] else {}
        except Exception:
            sel_map = {}

        # Map (workshop -> slot escolhido por essa pessoa)
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
            rows.append((wname, hora, a["full_name"], a["email"]))

    # Ordena por Oficina, Horário, Nome
    rows.sort(key=lambda r: (r[0].lower(), r[1], r[2].lower()))

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Oficina", "Horário", "Nome", "E-mail"])
    for r in rows:
        writer.writerow(r)

    mem = io.BytesIO(output.getvalue().encode("utf-8")); mem.seek(0)
    resp = make_response(mem.read())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=nomes_por_oficina_e_horario_linha_a_linha.csv"
    return resp

# =========================
# Execução local
# =========================
if __name__ == "__main__":
    app.run(debug=True)
