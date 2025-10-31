from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
import sqlite3, json, os, datetime, csv, io
from contextlib import closing
from werkzeug.security import check_password_hash, generate_password_hash


APP_SECRET = os.environ.get("APP_SECRET", "changeme")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
# Para segurança, use hash no ADMIN_PASS_HASH. Para testes locais, se ADMIN_PASS estiver presente, um hash será gerado no boot.
ADMIN_PASS_HASH = os.environ.get("ADMIN_PASS_HASH")
ADMIN_PASS = os.environ.get("ADMIN_PASS")


app = Flask(__name__)
app.secret_key = APP_SECRET
DB_PATH = os.environ.get("DB_PATH", "inscricoes.db")


# --- Helpers DB ---
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
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

# Seed das 7 oficinas (apenas se estiver vazio)
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
    cur.execute("INSERT INTO workshops(name, capacity, registered) VALUES (?, ?, ?)",(n, 40, 0), # capacidade inicial 40
)


# --- Auth simples (session) ---
@app.before_first_request
def _init():
init_db()
global ADMIN_PASS_HASH
if not ADMIN_PASS_HASH and ADMIN_PASS:
ADMIN_PASS_HASH = generate_password_hash(ADMIN_PASS)


from functools import wraps


def login_required(view):
@wraps(view)
def wrapped(*args, **kwargs):
if not session.get("admin_logged"):
return redirect(url_for("login", next=request.path))
return view(*args, **kwargs)
return wrapped
app.run(debug=True)




