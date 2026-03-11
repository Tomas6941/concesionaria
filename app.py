from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import mysql.connector
from mysql.connector import Error
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = 'motorprime_secret_2024'

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'concesionaria_db'
}

def get_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    conn = get_db()
    destacados = []
    if conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM autos WHERE disponible=1 AND destacado=1 LIMIT 6")
        destacados = cur.fetchall()
        conn.close()
    return render_template('index.html', destacados=destacados)

@app.route('/catalogo')
def catalogo():
    conn = get_db()
    autos = []
    marcas = []
    if conn:
        cur = conn.cursor(dictionary=True)
        marca = request.args.get('marca', '')
        tipo = request.args.get('tipo', '')
        precio_max = request.args.get('precio_max', '')
        query = "SELECT * FROM autos WHERE disponible=1"
        params = []
        if marca:
            query += " AND marca=%s"
            params.append(marca)
        if tipo:
            query += " AND tipo=%s"
            params.append(tipo)
        if precio_max:
            query += " AND precio<=%s"
            params.append(int(precio_max))
        query += " ORDER BY destacado DESC, id DESC"
        cur.execute(query, params)
        autos = cur.fetchall()
        cur.execute("SELECT DISTINCT marca FROM autos WHERE disponible=1 ORDER BY marca")
        marcas = [r['marca'] for r in cur.fetchall()]
        conn.close()
    return render_template('catalogo.html', autos=autos, marcas=marcas,
                           filtros=request.args)

@app.route('/auto/<int:id>')
def auto_detalle(id):
    conn = get_db()
    auto = None
    relacionados = []
    if conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM autos WHERE id=%s", (id,))
        auto = cur.fetchone()
        if auto:
            cur.execute("SELECT * FROM autos WHERE tipo=%s AND id!=%s AND disponible=1 LIMIT 3",
                        (auto['tipo'], id))
            relacionados = cur.fetchall()
        conn.close()
    if not auto:
        return redirect(url_for('catalogo'))
    return render_template('auto_detalle.html', auto=auto, relacionados=relacionados)

@app.route('/test-drive', methods=['GET', 'POST'])
def test_drive():
    conn = get_db()
    autos = []
    if conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, marca, modelo, anio FROM autos WHERE disponible=1 ORDER BY marca")
        autos = cur.fetchall()
        conn.close()
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        email = request.form.get('email', '').strip()
        telefono = request.form.get('telefono', '').strip()
        auto_id = request.form.get('auto_id', '')
        fecha = request.form.get('fecha', '')
        mensaje = request.form.get('mensaje', '')
        if nombre and email and auto_id and fecha:
            conn = get_db()
            if conn:
                cur = conn.cursor()
                cur.execute("""INSERT INTO test_drives (nombre, email, telefono, auto_id, fecha, mensaje)
                               VALUES (%s,%s,%s,%s,%s,%s)""",
                            (nombre, email, telefono, auto_id, fecha, mensaje))
                conn.commit()
                conn.close()
            flash('¡Tu solicitud de test drive fue enviada! Te contactaremos pronto.', 'success')
            return redirect(url_for('test_drive'))
        else:
            flash('Por favor completá todos los campos obligatorios.', 'error')
    return render_template('test_drive.html', autos=autos)

@app.route('/contacto', methods=['GET', 'POST'])
def contacto():
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        email = request.form.get('email', '').strip()
        telefono = request.form.get('telefono', '')
        asunto = request.form.get('asunto', '')
        mensaje = request.form.get('mensaje', '')
        if nombre and email and mensaje:
            conn = get_db()
            if conn:
                cur = conn.cursor()
                cur.execute("""INSERT INTO contactos (nombre, email, telefono, asunto, mensaje)
                               VALUES (%s,%s,%s,%s,%s)""",
                            (nombre, email, telefono, asunto, mensaje))
                conn.commit()
                conn.close()
            flash('¡Mensaje enviado! Te responderemos a la brevedad.', 'success')
            return redirect(url_for('contacto'))
        flash('Completá todos los campos requeridos.', 'error')
    return render_template('contacto.html')

@app.route('/nosotros')
def nosotros():
    return render_template('nosotros.html')

@app.route('/financiacion')
def financiacion():
    return render_template('financiacion.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form.get('usuario') == 'admin' and request.form.get('password') == 'motorprime2024':
            session['admin'] = True
            return redirect(url_for('admin_panel'))
        flash('Credenciales incorrectas.', 'error')
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin_panel():
    conn = get_db()
    stats = {}
    autos = []
    test_drives = []
    contactos = []
    if conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT COUNT(*) as total FROM autos WHERE disponible=1")
        stats['autos'] = cur.fetchone()['total']
        cur.execute("SELECT COUNT(*) as total FROM test_drives")
        stats['test_drives'] = cur.fetchone()['total']
        cur.execute("SELECT COUNT(*) as total FROM contactos")
        stats['contactos'] = cur.fetchone()['total']
        cur.execute("SELECT * FROM autos ORDER BY id DESC LIMIT 20")
        autos = cur.fetchall()
        cur.execute("""SELECT td.*, a.marca, a.modelo FROM test_drives td
                       LEFT JOIN autos a ON td.auto_id=a.id ORDER BY td.id DESC LIMIT 10""")
        test_drives = cur.fetchall()
        cur.execute("SELECT * FROM contactos ORDER BY id DESC LIMIT 10")
        contactos = cur.fetchall()
        conn.close()
    return render_template('admin.html', stats=stats, autos=autos,
                           test_drives=test_drives, contactos=contactos)

@app.route('/admin/auto/nuevo', methods=['GET', 'POST'])
@login_required
def admin_auto_nuevo():
    if request.method == 'POST':
        data = {k: request.form.get(k, '') for k in [
            'marca', 'modelo', 'anio', 'precio', 'km', 'tipo',
            'transmision', 'combustible', 'color', 'descripcion', 'imagen_url'
        ]}
        data['disponible'] = 1 if request.form.get('disponible') else 0
        data['destacado'] = 1 if request.form.get('destacado') else 0
        conn = get_db()
        if conn:
            cur = conn.cursor()
            cur.execute("""INSERT INTO autos (marca, modelo, anio, precio, km, tipo, transmision,
                           combustible, color, descripcion, imagen_url, disponible, destacado)
                           VALUES (%(marca)s,%(modelo)s,%(anio)s,%(precio)s,%(km)s,%(tipo)s,
                           %(transmision)s,%(combustible)s,%(color)s,%(descripcion)s,
                           %(imagen_url)s,%(disponible)s,%(destacado)s)""", data)
            conn.commit()
            conn.close()
        flash('Auto agregado correctamente.', 'success')
        return redirect(url_for('admin_panel'))
    return render_template('admin_auto_form.html', auto=None)

@app.route('/admin/auto/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def admin_auto_editar(id):
    conn = get_db()
    auto = None
    if conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM autos WHERE id=%s", (id,))
        auto = cur.fetchone()
        conn.close()
    if not auto:
        return redirect(url_for('admin_panel'))
    if request.method == 'POST':
        data = {k: request.form.get(k, '') for k in [
            'marca', 'modelo', 'anio', 'precio', 'km', 'tipo',
            'transmision', 'combustible', 'color', 'descripcion', 'imagen_url'
        ]}
        data['disponible'] = 1 if request.form.get('disponible') else 0
        data['destacado'] = 1 if request.form.get('destacado') else 0
        data['id'] = id
        conn = get_db()
        if conn:
            cur = conn.cursor()
            cur.execute("""UPDATE autos SET marca=%(marca)s, modelo=%(modelo)s, anio=%(anio)s,
                           precio=%(precio)s, km=%(km)s, tipo=%(tipo)s, transmision=%(transmision)s,
                           combustible=%(combustible)s, color=%(color)s, descripcion=%(descripcion)s,
                           imagen_url=%(imagen_url)s, disponible=%(disponible)s, destacado=%(destacado)s
                           WHERE id=%(id)s""", data)
            conn.commit()
            conn.close()
        flash('Auto actualizado.', 'success')
        return redirect(url_for('admin_panel'))
    return render_template('admin_auto_form.html', auto=auto)

@app.route('/admin/auto/eliminar/<int:id>', methods=['POST'])
@login_required
def admin_auto_eliminar(id):
    conn = get_db()
    if conn:
        cur = conn.cursor()
        cur.execute("UPDATE autos SET disponible=0 WHERE id=%s", (id,))
        conn.commit()
        conn.close()
    flash('Auto eliminado del catálogo.', 'success')
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    app.run(debug=True)
