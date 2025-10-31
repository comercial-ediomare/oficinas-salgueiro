from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
import sqlite3, json, os, datetime, csv, io
from contextlib import closing
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

# --- Config ---
APP_SECRET = os.environ.get("APP_SECRET", "changeme")
ADMIN_USER  = os.environ.get("ADMIN_USER", "admin")
# Em produção prefira ADMIN_PASS_HASH; se ADMIN_PASS vier, geramos o hash no bootstrap
ADMIN_PASS_HASH = os.environ.get("ADMIN_PASS_HASH")
ADMIN_PASS      = os.environ.get("ADMIN_PASS")

app = Flask(__name__)
app.secret_key = APP_SECRET
DB_PATH = os.environ.get("DB_PATH", "inscricoes.db")
FALLBACK_DB = "inscricoes.db"   # usado se /data não estiver montado

# --- Utils / FS (sem tentar criar /data à força) ---
def _is_writable_dir(dirpath: str) -> bool:
    return os.path.isdir(dirpath) and os.access(dirpath, os.W_OK)

def _can_use_path(path: str) -> bool:
    """
    Verifica se o caminho do banco pode ser usado.
    - NUNCA tenta criar /data no Render (evita PermissionError).
    - Se for um caminho com diretório inexistente diferente de /data, tenta criar.
    """
    dirpath = os.path.dirname(path)
    if not dirpath:
        # Sem diretório (arquivo na raiz do app): ok
        return True

    # Se for /data (ou subpasta) e não for gravável, não tenta criar: retorna False
    if dirpath.startswith("/data"):
        return _is_writable_dir(dirpath)

    # Para outros diretórios, tenta criar e depois checa gravabilidade
    try:
        if not os.path.exists(dirpath):
            os.makedirs(dirpath, exist_ok=True)
    except Exception:
        return False
    return _is_writable_dir(dirpath)

def _choose_db_path(primary: str, fallback: str) -> str:
    """Escolhe DB_PATH se utilizável; caso contrário, usa fallback local."""
    if _can_use_path(primary):
        return primary
    if _can_use_path(fallback):
        return fallback
    # Último recurso: arquivo na raiz
    return "inscricoes.db"

# --- DB Helpers ---
def get_db():
    """Abre conexão SQLite usando caminho válido (com fallback local)."""
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
            selections TEXT NOT NULL,      -- JSON de lista de IDs
            created_at TEXT NOT NULL
        );
        """)
        # Seed inicial (só se estiver vazio)
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
                    (n, 40, 0)  # capacidade inicial 15
                )
        conn.commit()

# --- Horários e restrições ---
SLOTS = [
    {
        "id": 1,
        "hora": "14h00",
        "bloqueadas": ["FORTALECENDO-SE NO PODER DO ESPÍRITO"],
    },
    {
        "id": 2,
        "hora": "15h50",
        "bloqueadas": [
            "TRANSFORMANDO COMPORTAMENTOS DESTRUTIVOS",
            "VENCENDO AS MENTIRAS COM A VERDADE",
        ],
    },
    {
        "id": 3,
        "hora": "19h00",
        "bloqueadas": [
            "CUIDANDO DO CORPO ONDE O ESPÍRITO HABITA",
            "DA FRAQUEZA À VITÓRIA: TORNANDO-SE FORTE NA PALAVRA",
        ],
    },
    {
        "id": 4,
        "hora": "20h50",
        "bloqueadas": [
            "RAÍZES QUE PRECISAM SER ARRANCADAS",
            "DOMINANDO AS EMOÇÕES PARA QUE O ESPÍRITO SANTO GOVERNE",
        ],
    },
]

# --- Bootstrap (Flask 3: sem before_first_request) ---
app.config["BOOTSTRAPPED"] = False

@app.before_request
def _bootstrap_once():
    if not app.config["BOOTSTRAPPED"]:
        init_db()
        global ADMIN_PASS_HASH
        if not ADMIN_PASS_HASH and ADMIN_PASS:
            ADMIN_PASS_HASH = generate_password_hash(ADMIN_PASS)
        app.config["BOOTSTRAPPED"] = True

# --- Auth helper ---
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
    # Passa os slots para o template para filtrar por horário
    return render_template("index.html", workshops=workshops, slots=SLOTS)

@app.route("/inscrever", methods=["POST"])
def inscrever():
    full_name = (request.form.get("full_name") or "").strip()
    email     = (request.form.get("email") or "").strip().lower()
    consent   = request.form.get("consent") == "on"

    # Cada horário tem um campo radio slot_{id}
    selected_per_slot = {}
    chosen_ids = []
    for slot in SLOTS:
        val = request.form.get(f"slot_{slot['id']}")
        if val:
            wid = int(val)
            selected_per_slot[slot["id"]] = wid
            chosen_ids.append(wid)

    # Validações (mín. 1, máx. 4 | 1 por horário | sem repetição de oficina)
    if not consent:
        flash("Você precisa concordar com o tratamento dos seus dados.", "error")
        return redirect(url_for("index"))
    if not full_name:
        flash("Informe seu nome completo.", "error")
        return redirect(url_for("index"))
    if not email or "@" not in email:
        flash("Informe um e-mail válido.", "error")
        return redirect(url_for("index"))

    if len(chosen_ids) < 1:
        flash("Selecione pelo menos 1 oficina (uma por horário).", "error")
        return redirect(url_for("index"))
    if len(chosen_ids) > 4:
        flash("Você pode selecionar no máximo 4 oficinas (uma por horário).", "error")
        return redirect(url_for("index"))

    # Sem duplicidade de oficina entre horários
    if len(chosen_ids) != len(set(chosen_ids)):
        flash("Você não pode escolher a mesma oficina em horários diferentes.", "error")
        return redirect(url_for("index"))

    # Segurança extra: impedir oficina bloqueada no horário
    with closing(get_db()) as conn:
        ws = conn.execute("SELECT id, name, capacity, registered FROM workshops").fetchall()
        id_to_name = {row["id"]: row["name"] for row in ws}
        id_to_cap  = {row["id"]: (row["capacity"], row["registered"]) for row in ws}

    for slot in SLOTS:
        wid = selected_per_slot.get(slot["id"])
        if not wid:
            continue
        wname = id_to_name.get(wid, "")
        if wname in slot["bloqueadas"]:
            flash(f"A oficina '{wname}' não está disponível no horário das {slot['hora']}.", "error")
            return redirect(url_for("index"))

    # --- Persistência com checagem de vagas (transação) ---
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.cursor()

        # Evita e-mail duplicado
        cur.execute("SELECT 1 FROM attendees WHERE email = ?", (email,))
        if cur.fetchone():
            conn.execute("ROLLBACK")
            flash("Este e-mail já está inscrito.", "error")
            return redirect(url_for("index"))

        # Verifica e reserva vagas (somente nas oficinas escolhidas)
        for wid in chosen_ids:
            cur.execute("SELECT capacity, registered FROM workshops WHERE id = ?", (wid,))
            row = cur.fetchone()
            if not row:
                conn.execute("ROLLBACK")
                flash("Oficina inválida.", "error")
                return redirect(url_for("index"))
            cap, reg = row["capacity"], row["registered"]
            if reg >= cap:
                conn.execute("ROLLBACK")
                flash("Uma das oficinas esgotou enquanto você enviava. Selecione outra.", "error")
                return redirect(url_for("index"))
            cur.execute("UPDATE workshops SET registered = registered + 1 WHERE id = ?", (wid,))

        # Registra participante
        now = datetime.datetime.utcnow().isoformat()
        cur.execute(
            "INSERT INTO attendees(full_name, email, selections, created_at) VALUES (?, ?, ?, ?)",
            (full_name, email, json.dumps(chosen_ids), now)
        )

        conn.execute("COMMIT")
        return redirect(url_for("sucesso"))
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        flash("Erro ao processar inscrição. Tente novamente.", "error")
        return redirect(url_for("index"))
    finally:
        conn.close()

@app.route("/sucesso")
def sucesso():
    return render_template("success.html")

# --- Rotas de admin ---
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = (request.form.get("username") or "").strip()
        pwd  = request.form.get("password") or ""
        if user != ADMIN_USER:
            error = "Usuário ou senha inválidos."
        elif not ADMIN_PASS_HASH:
            error = "Senha não configurada no servidor. Defina ADMIN_PASS_HASH ou ADMIN_PASS."
        elif not check_password_hash(ADMIN_PASS_HASH, pwd):
            error = "Usuário ou senha inválidos."
        else:
            session["admin_logged"] = True
            flash("Login realizado com sucesso.", "message")
            nxt = request.args.get("next") or url_for("admin")
            return redirect(nxt)
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
            SELECT id, name, capacity, registered, (capacity-registered) AS remaining
            FROM workshops ORDER BY id
        """).fetchall()
        attendees = conn.execute("""
            SELECT full_name, email, selections, created_at
            FROM attendees
            ORDER BY created_at DESC
        """).fetchall()

    parsed = []
    for a in attendees:
        try:
            sels = json.loads(a["selections"]) or []
        except Exception:
            sels = []
        parsed.append({
            "full_name": a["full_name"],
            "email": a["email"],
            "selections": sels,
            "created_at": a["created_at"],
        })
    return render_template("admin.html", workshops=ws, attendees=parsed)

@app.route("/export.csv")
@login_required
def export_csv():
    # Gera um CSV com duas seções (workshops e attendees)
    output = io.StringIO()
    writer = csv.writer(output)

    with closing(get_db()) as conn:
        ws = conn.execute("SELECT id, name, capacity, registered FROM workshops ORDER BY id").fetchall()
        at = conn.execute("SELECT full_name, email, selections, created_at FROM attendees ORDER BY created_at DESC").fetchall()

    writer.writerow(["WORKSHOPS"])
    writer.writerow(["id", "name", "capacity", "registered", "remaining"])
    for w in ws:
        writer.writerow([w["id"], w["name"], w["capacity"], w["registered"], w["capacity"] - w["registered"]])

    writer.writerow([])
    writer.writerow(["ATTENDEES"])
    writer.writerow(["full_name", "email", "selections_ids", "created_at"])
    for a in at:
        writer.writerow([a["full_name"], a["email"], a["selections"], a["created_at"]])

    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    mem.seek(0)

    resp = make_response(mem.read())
    resp.headers.set("Content-Type", "text/csv; charset=utf-8")
    resp.headers.set("Content-Disposition", "attachment", filename="inscricoes.csv")
    return resp

# --- Dev local ---
if __name__ == "__main__":
    # Em produção (Render) quem inicia é o Gunicorn
    app.run(debug=True)
