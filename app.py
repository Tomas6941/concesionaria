from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import sqlite3
import os
from datetime import datetime
import threading

app = Flask(__name__)
app.secret_key = "super_secret_key"

# Configuración de email (Gmail)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = '' #Tu correo
app.config['MAIL_PASSWORD'] = '' # Tu clave de apliación
app.config['MAIL_DEFAULT_SENDER'] = '' #Tu correo

# Serializer para tokens
app.config['SECURITY_PASSWORD_SALT'] = '' #

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

DATABASE = "database.db"
UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            foto TEXT,
            email_verified INTEGER DEFAULT 0,
            verification_token TEXT,
            pending_email TEXT,
            pending_nombre TEXT,
            pending_password TEXT,
            change_token TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id, nombre, email, password, foto, email_verified):
        self.id = id
        self.nombre = nombre
        self.email = email
        self.password = password
        self.foto = foto
        self.email_verified = email_verified

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user["id"], user["nombre"], user["email"], user["password"], user["foto"], user["email_verified"])
    return None

# Función para enviar emails
def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_verification_email(user_email, token, tipo="registro"):
    try:
        if tipo == "registro":
            verify_url = url_for('verify_email', token=token, _external=True)
            subject = "Verifica tu cuenta - MotoShop"
            html = f"""
            <h2>¡Bienvenido a MotoShop!</h2>
            <p>Gracias por registrarte. Por favor, verifica tu cuenta haciendo clic en el siguiente enlace:</p>
            <p><a href="{verify_url}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verificar mi cuenta</a></p>
            <p>Si no creaste esta cuenta, ignora este mensaje.</p>
            """
        elif tipo == "cambio_email":
            verify_url = url_for('verify_email_change', token=token, _external=True)
            subject = "Confirma tu nuevo email - MotoShop"
            html = f"""
            <h2>Cambio de email solicitado</h2>
            <p>Has solicitado cambiar tu email. Confirma haciendo clic en:</p>
            <p><a href="{verify_url}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Confirmar cambio de email</a></p>
            """
        else:
            verify_url = url_for('verify_data_change', token=token, _external=True)
            subject = "Confirma los cambios en tu cuenta - MotoShop"
            html = f"""
            <h2>Cambios en tu cuenta</h2>
            <p>Has solicitado modificar los datos. Confirma haciendo clic en:</p>
            <p><a href="{verify_url}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Confirmar cambios</a></p>
            """
        
        msg = Message(subject, recipients=[user_email])
        msg.html = html
        thr = threading.Thread(target=send_async_email, args=[app, msg])
        thr.start()
        return True
    except Exception as e:
        print(f"Error enviando email: {e}")
        return False

@app.context_processor
def inject_year():
    return {"year": datetime.now().year}

@app.route("/")
def home():
    return render_template("inicio.html")

@app.route("/catalogo")
def catalogo():
    motos = [
        {"nombre": "Yamaha R7", "cilindrada": "689cc", "descripcion": "Deportiva ligera y equilibrada.", "foto": "img/motos/r7.jpg"},
        {"nombre": "Ducati Panigale V2", "cilindrada": "955cc", "descripcion": "Superbike italiana elegante.", "foto": "img/motos/panigale.jpg"},
        {"nombre": "Kawasaki Z900", "cilindrada": "948cc", "descripcion": "Naked agresiva y moderna.", "foto": "img/motos/z900.jpg"},
        {"nombre": "Honda CBR650R", "cilindrada": "649cc", "descripcion": "Versátil para uso diario.", "foto": "img/motos/cbr650r.jpg"},
        {"nombre": "BMW S1000RR", "cilindrada": "999cc", "descripcion": "Tecnología alemana de competición.", "foto": "img/motos/s1000rr.jpg"},
        {"nombre": "Suzuki GSX-8S", "cilindrada": "776cc", "descripcion": "Respuesta potente y estable.", "foto": "img/motos/gsx8s.jpg"},
        {"nombre": "KTM RC 390", "cilindrada": "373cc", "descripcion": "Ligera y divertida.", "foto": "img/motos/rc390.jpg"},
        {"nombre": "Triumph Street Triple RS", "cilindrada": "765cc", "descripcion": "Carácter británico.", "foto": "img/motos/street_triple.jpg"},
        {"nombre": "Aprilia RS 660", "cilindrada": "659cc", "descripcion": "Tecnológica y precisa.", "foto": "img/motos/rs660.jpg"},
        {"nombre": "Ducati Monster", "cilindrada": "937cc", "descripcion": "Minimalista y potente.", "foto": "img/motos/monster.jpg"},
        {"nombre": "Yamaha MT-09", "cilindrada": "889cc", "descripcion": "Aceleración explosiva.", "foto": "img/motos/mt09.jpg"},
        {"nombre": "Honda CB1000R", "cilindrada": "998cc", "descripcion": "Diseño neo-sport.", "foto": "img/motos/cb1000r.jpg"},
        {"nombre": "Kawasaki Ninja ZX-6R", "cilindrada": "636cc", "descripcion": "Lista para pista.", "foto": "img/motos/zx6r.jpg"},
        {"nombre": "BMW F900R", "cilindrada": "895cc", "descripcion": "Cómoda y versátil.", "foto": "img/motos/f900r.jpg"},
        {"nombre": "MV Agusta F3 800", "cilindrada": "798cc", "descripcion": "Arte italiano sobre ruedas.", "foto": "img/motos/f3_800.jpg"}
    ]
    return render_template('catalogo.html', motos=motos)

@app.route("/accesorios")
def accesorios():
    accesorios = [
        {"nombre": "Casco Integral AGV K1", "tipo": "Casco", "descripcion": "Ligero, aerodinámico y certificado.", "foto": "img/accesorios/casco1.png"},
        {"nombre": "Casco Shoei NXR2", "tipo": "Casco", "descripcion": "Alta gama con excelente ventilación.", "foto": "img/accesorios/casco2.png"},
        {"nombre": "Guantes Alpinestars SP-8", "tipo": "Guantes", "descripcion": "Protección y agarre profesional.", "foto": "img/accesorios/guantes1.png"},
        {"nombre": "Guantes Dainese Carbon 4", "tipo": "Guantes", "descripcion": "Cuero premium con refuerzos de carbono.", "foto": "img/accesorios/guantes2.png"},
        {"nombre": "Chaqueta Revit Eclipse", "tipo": "Chaqueta", "descripcion": "Ideal para verano y ciudad.", "foto": "img/accesorios/chaqueta1.png"},
        {"nombre": "Chaqueta Alpinestars T-GP Plus", "tipo": "Chaqueta", "descripcion": "Deportiva con protecciones CE.", "foto": "img/accesorios/chaqueta2.png"},
        {"nombre": "Botas TCX S-TR1", "tipo": "Botas", "descripcion": "Comodidad y seguridad en carretera.", "foto": "img/accesorios/botas1.png"},
        {"nombre": "Botas Alpinestars SMX-6", "tipo": "Botas", "descripcion": "Diseñadas para conducción deportiva.", "foto": "img/accesorios/botas2.png"},
        {"nombre": "Mochila Kriega R20", "tipo": "Mochila", "descripcion": "Resistente al agua y ergonómica.", "foto": "img/accesorios/mochila1.png"},
        {"nombre": "Intercomunicador Cardo Freecom 4X", "tipo": "Electrónico", "descripcion": "Comunicación Bluetooth avanzada.", "foto": "img/accesorios/intercom1.png"}
    ]
    return render_template("accesorios.html", accesorios=accesorios)

@app.route("/informacion")
def informacion():
    return render_template("informacion.html")

@app.route("/contacto")
def contacto():
    return render_template("contacto.html")

# ========== REGISTRO - SIN LOGIN AUTOMÁTICO ==========
@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre = request.form["nombre"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        # Generar token de verificación
        token = serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

        conn = get_db_connection()
        try:
            # Verificar si el usuario ya existe
            usuario_existente = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if usuario_existente:
                flash("El email ya está registrado", "danger")
                conn.close()
                return redirect(url_for('registro'))
            
            # Insertar nuevo usuario con email_verified = 0 (NO VERIFICADO)
            conn.execute("""
                INSERT INTO users (nombre, email, password, verification_token, email_verified) 
                VALUES (?, ?, ?, ?, ?)
            """, (nombre, email, password, token, 0))
            conn.commit()
            conn.close()
            
            # Enviar email de verificación
            if send_verification_email(email, token, "registro"):
                flash("Cuenta creada correctamente. Por favor, verifica tu email antes de iniciar sesión.", "success")
            else:
                flash("Cuenta creada pero hubo un problema al enviar el email de verificación. Contacta con soporte.", "warning")
            
            # Evitar login automático
            logout_user()
            print(f"Usuario {email} registrado correctamente - Email NO verificado")
            return redirect(url_for("login", registered="true"))
            
        except Exception as e:
            print(f"Error en registro: {e}")
            flash("Error al crear la cuenta. Intenta nuevamente.", "danger")
            conn.close()
            return redirect(url_for('registro'))
    
    return render_template("registro.html")

@app.route("/verify/<token>")
def verify_email(token):
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except SignatureExpired:
        flash("El enlace de verificación ha expirado. Solicita uno nuevo.", "danger")
        return redirect(url_for("login"))
    except BadSignature:
        flash("Enlace de verificación inválido.", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE email = ? AND verification_token = ?", 
                       (email, token)).fetchone()
    
    if user:
        # Marcar como verificado
        conn.execute("UPDATE users SET email_verified = 1, verification_token = NULL WHERE email = ?", 
                    (email,))
        conn.commit()
        print(f"Email {email} verificado correctamente")
        flash("¡Email verificado correctamente! Ya puedes iniciar sesión.", "success")
    else:
        print(f"Token inválido para email: {email}")
        flash("Usuario no encontrado o ya verificado.", "danger")
    
    conn.close()
    return redirect(url_for("login"))

# ========== LOGIN - SOLO PARA EMAILS VERIFICADOS ==========
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        # Verificar si el usuario existe
        if not user:
            flash("Credenciales incorrectas", "danger")
            return redirect(url_for("login"))
        
        # Verificar si la contraseña es correcta
        if not check_password_hash(user["password"], password):
            flash("Credenciales incorrectas", "danger")
            return redirect(url_for("login"))
        
        # VERIFICACIÓN ESTRICTA - SOLO SI email_verified = 1
        if user["email_verified"] != 1:
            print(f"Intento de login con email NO verificado: {email}")
            flash("Por favor, verifica tu email antes de iniciar sesión. Revisa tu bandeja de entrada o spam.", "warning")
            return redirect(url_for("login"))

        # Si llegamos aquí, todo está bien
        print(f"Login exitoso para usuario verificado: {email}")
        user_obj = User(user["id"], user["nombre"], user["email"], user["password"], user["foto"], user["email_verified"])
        login_user(user_obj)
        return redirect(url_for("home"))

    return render_template("login.html")

@app.route("/resend-verification", methods=["POST"])
def resend_verification():
    email = request.form.get("email")
    
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE email = ? AND email_verified = 0", 
                       (email,)).fetchone()
    
    if user:
        token = serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])
        conn.execute("UPDATE users SET verification_token = ? WHERE email = ?", 
                    (token, email))
        conn.commit()
        
        if send_verification_email(email, token, "registro"):
            flash("Se ha enviado un nuevo enlace de verificación a tu email.", "success")
        else:
            flash("Error al enviar el email. Intenta más tarde.", "danger")
    else:
        flash("Email no registrado o ya verificado.", "danger")
    
    conn.close()
    return redirect(url_for("login"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"png", "jpg", "jpeg", "gif"}

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        nuevo_nombre = request.form.get("nombre")
        nuevo_email = request.form.get("email")
        nueva_password = request.form.get("password")
        foto = request.files.get("foto")

        # Manejar la foto
        filename = current_user.foto
        if foto and allowed_file(foto.filename):
            filename = f"{current_user.id}_{secure_filename(foto.filename)}"
            foto.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            
            conn = get_db_connection()
            conn.execute("UPDATE users SET foto = ? WHERE id = ?", (filename, current_user.id))
            conn.commit()
            conn.close()

        # Verificar cambios
        cambios = {}
        if nuevo_nombre and nuevo_nombre != current_user.nombre:
            cambios['nombre'] = nuevo_nombre
        if nuevo_email and nuevo_email != current_user.email:
            cambios['email'] = nuevo_email
        if nueva_password:
            cambios['password'] = generate_password_hash(nueva_password)

        if cambios:
            token = serializer.dumps(current_user.email, salt=app.config['SECURITY_PASSWORD_SALT'])
            
            conn = get_db_connection()
            conn.execute("""
                UPDATE users 
                SET pending_nombre = ?,
                    pending_email = ?,
                    pending_password = ?,
                    change_token = ?
                WHERE id = ?
            """, (
                cambios.get('nombre'),
                cambios.get('email'),
                cambios.get('password'),
                token,
                current_user.id
            ))
            conn.commit()
            conn.close()

            email_destino = cambios.get('email') if 'email' in cambios else current_user.email
            
            if 'email' in cambios:
                send_verification_email(email_destino, token, "cambio_email")
                flash("Se ha enviado un enlace de verificación al nuevo email.", "success")
            else:
                send_verification_email(email_destino, token, "cambio_datos")
                flash("Se ha enviado un enlace de verificación a tu email.", "success")

            return redirect(url_for("account", changes_sent="true"))

        elif not foto:
            flash("No se realizaron cambios", "info")
            
        return redirect(url_for("account"))

    return render_template("account.html")

@app.route("/verify-data-change/<token>")
def verify_data_change(token):
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except SignatureExpired:
        flash("El enlace ha expirado. Solicita los cambios nuevamente.", "danger")
        return redirect(url_for("account"))
    except BadSignature:
        flash("Enlace inválido.", "danger")
        return redirect(url_for("account"))

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE change_token = ?", (token,)).fetchone()
    
    if user:
        updates = []
        params = []
        
        if user['pending_nombre']:
            updates.append("nombre = ?")
            params.append(user['pending_nombre'])
        if user['pending_email']:
            updates.append("email = ?")
            params.append(user['pending_email'])
        if user['pending_password']:
            updates.append("password = ?")
            params.append(user['pending_password'])
        
        if updates:
            updates.append("pending_nombre = NULL")
            updates.append("pending_email = NULL")
            updates.append("pending_password = NULL")
            updates.append("change_token = NULL")
            
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            params.append(user['id'])
            
            conn.execute(query, params)
            conn.commit()
            
            flash("¡Cambios confirmados correctamente!", "success")
            
            if user['pending_email'] or user['pending_password']:
                logout_user()
                return redirect(url_for("login", changes_confirmed="true"))
        else:
            flash("No hay cambios pendientes.", "info")
    else:
        flash("Token no válido.", "danger")
    
    conn.close()
    return redirect(url_for("account", changes_confirmed="true"))

@app.route("/verify-email-change/<token>")
def verify_email_change(token):
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except SignatureExpired:
        flash("El enlace ha expirado. Solicita el cambio nuevamente.", "danger")
        return redirect(url_for("account"))
    except BadSignature:
        flash("Enlace inválido.", "danger")
        return redirect(url_for("account"))

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE pending_email = ? AND change_token = ?", 
                       (email, token)).fetchone()
    
    if user:
        conn.execute("""
            UPDATE users 
            SET email = pending_email,
                pending_email = NULL,
                change_token = NULL,
                email_verified = 1
            WHERE id = ?
        """, (user['id'],))
        conn.commit()
        
        flash("¡Email cambiado correctamente! Inicia sesión con tu nuevo email.", "success")
        logout_user()
        return redirect(url_for("login", changes_confirmed="true"))
    else:
        flash("Token no válido.", "danger")
    
    conn.close()
    return redirect(url_for("account"))

if __name__ == "__main__":
    app.run(debug=True)
