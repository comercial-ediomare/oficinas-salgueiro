from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
"INSERT INTO attendees(full_name, email, selections, created_at) VALUES (?, ?, ?, ?)",
(full_name, email, json.dumps(chosen_ids), now),
)


conn.execute("COMMIT")
return redirect(url_for("sucesso"))
except Exception:
try:
conn.execute("ROLLBACK")
except:
pass
flash("Erro ao processar inscrição. Tente novamente.", "error")
return redirect(url_for("index"))
finally:
conn.close()


@app.route("/sucesso")
def sucesso():
return render_template("success.html")


# --- Admin ---
@app.route("/admin")
@login_required
def admin():
with closing(get_db()) as conn:
ws = conn.execute(
"""
SELECT id, name, capacity, registered, (capacity-registered) AS remaining
FROM workshops ORDER BY id
"""
).fetchall()
attendees = conn.execute(
"SELECT full_name, email, selections, created_at FROM attendees ORDER BY created_at DESC"
).fetchall()


parsed = []
for a in attendees:
try:
sels = json.loads(a["selections"]) or []
except:
sels = []
parsed.append(
{
"full_name": a["full_name"],
"email": a["email"],
"selections": sels,
"created_at": a["created_at"],
}
)
return render_template("admin.html", workshops=ws, attendees=parsed)


@app.route("/export.csv")
@login_required
def export_csv():
# Exporta duas abas lógicas: Workshops e Attendees (em dois blocos no mesmo CSV, separados por linha em branco)
output = io.StringIO()
writer = csv.writer(output)


with closing(get_db()) as conn:
ws = conn.execute("SELECT id, name, capacity, registered FROM workshops ORDER BY id").fetchall()
at = conn.execute(
"SELECT full_name, email, selections, created_at FROM attendees ORDER BY created_at DESC"
).fetchall()


writer.writerow(["WORKSHOPS"])
writer.writerow(["id", "name", "capacity", "registered", "remaining"])
for w in ws:
remaining = w["capacity"] - w["registered"]
writer.writerow([w["id"], w["name"], w["capacity"], w["registered"], remaining])


writer.writerow([])
writer.writerow(["ATTENDEES"])
writer.writerow(["full_name", "email", "selections_ids", "created_at"])
for a in at:
writer.writerow([a["full_name"], a["email"], a["selections"], a["created_at"]])


mem = io.BytesIO()
mem.write(output.getvalue().encode("utf-8"))
mem.seek(0)


resp = make_response(mem.read())
resp.headers.set("Content-Type", "text/csv; charset=utf-8")
resp.headers.set("Content-Disposition", "attachment", filename="inscricoes.csv")
return resp


if __name__ == "__main__":
app.run(debug=True)