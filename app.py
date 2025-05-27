import logging
from flask import Flask, render_template, request, redirect, flash, url_for, session, abort
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)
from flask_ldap3_login import LDAP3LoginManager
import pymysql
from ldap3 import Server, Connection, SUBTREE
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# --- Application Setup ---
app = Flask(__name__)

# Si arrancamos bajo Gunicorn, usar su logger
if 'gunicorn.error' in logging.root.manager.loggerDict:
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)

# Clave secreta de Flask (cambiala por una aleatoria segura)
app.secret_key = "REEMPLAZAR_POR_SECRET_KEY"

# --- Load Configuration ---
from config import Config
app.config.from_object(Config)

# --- Flask-Login Manager ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- LDAP3 Login Manager ---
ldap_manager = LDAP3LoginManager(app)

# --- User Model ---
class User(UserMixin):
    def __init__(self, dn, username, memberships, role_id=None):
        self.dn = dn
        self.id = username
        self.memberships = memberships
        self.role_id = role_id

@login_manager.user_loader
def load_user(user_id):
    # Reconstruye el usuario desde sesión
    u = session.get('user_info')
    if not u or u.get('username') != user_id:
        return None
    # Obtener role_id desde DB si no está en sesión
    role_id = u.get('role_id')
    if role_id is None:
        con = db_conn()
        with con.cursor() as c:
            c.execute("SELECT role_id FROM user_app WHERE username=%s", (user_id,))
            row = c.fetchone()
        role_id = row[0] if row else None
    return User(u['dn'], u['username'], u['memberships'], role_id)

@ldap_manager.save_user
def save_user(dn, username, data, memberships):
    # Guardar información mínima en sesión
    session['user_info'] = {
        'dn': dn,
        'username': username,
        'memberships': memberships,
        'role_id': None
    }
    return User(dn, username, memberships)

# --- Role-Based Access Decorator ---
def roles_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            user_groups = [dn.split(',')[0].split('=')[1] for dn in current_user.memberships]
            role_map = {'Administradores': 1, 'Desarrolladores': 2, 'Clientes': 3}
            # LDAP group
            if any(r in user_groups for r in roles):
                return fn(*args, **kwargs)
            # role_id
            if current_user.role_id and any(role_map.get(r) == current_user.role_id for r in roles):
                return fn(*args, **kwargs)
            abort(403)
        return decorated_view
    return wrapper

# --- Database Connection ---
def db_conn():
    return pymysql.connect(
        host=app.config['DB_HOST'],
        user=app.config['DB_USER'],
        password=app.config['DB_PASS'],
        db=app.config['DB_NAME'],
        cursorclass=pymysql.cursors.DictCursor
    )

# --- Routes ---
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = request.form['username'].strip()
        # Verificar existencia en LDAP
        if not ldap_user_exists(u):
            flash('Ese usuario no existe en LDAP', 'danger')
            return redirect(url_for('register'))
        # Insertar en BD sin guardar contraseña local
        con = db_conn()
        with con.cursor() as c:
            c.execute("SELECT 1 FROM user_app WHERE username=%s", (u,))
            if c.fetchone():
                flash(f'El usuario {u} ya está registrado.', 'warning')
                return redirect(url_for('register'))
            c.execute(
                "INSERT INTO user_app (username, role_id) VALUES (%s, %s)",
                (u, 3)
            )
            con.commit()
        flash('Usuario registrado en la base de datos', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u, p = request.form['username'], request.form['password']
        try:
            result = ldap_manager.authenticate(u, p)
        except Exception:
            app.logger.exception("Error autenticando LDAP")
            flash('Error interno durante autenticación', 'danger')
            return render_template('login.html')
        if result.status != 'success':
            flash('Credenciales LDAP inválidas', 'danger')
            return render_template('login.html')
        ldap_groups = list(result.user_groups)
        # Determinar role_id
        if 'Administradores' in ldap_groups:
            role_id = 1
        else:
            con = db_conn()
            with con.cursor() as c:
                c.execute("SELECT role_id FROM user_app WHERE username=%s", (u,))
                row = c.fetchone()
            if not row:
                flash('Debes solicitar tu alta al Administrador', 'warning')
                return render_template('login.html')
            role_id = row['role_id']
        # Preparar sesión y login
        user = result.user
        user.role_id = role_id
        session['user_info']['role_id'] = role_id
        login_user(user)
        flash(f'Bienvenido, {u}!', 'success')
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_info', None)
    flash('Sesión cerrada', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    groups = [dn.split(',')[0].split('=')[1] for dn in current_user.memberships]
    return render_template('index.html', groups=groups)

@app.route('/cliente')
@login_required
@roles_required('Clientes')
def cliente_panel():
    return render_template('cliente.html')

@app.route('/desarrollador')
@login_required
@roles_required('Desarrolladores')
def dev_panel():
    return render_template('desarrollador.html')

@app.route('/admin/usuarios', methods=['GET','POST'])
@login_required
@roles_required('Administradores')
def admin_usuarios():
    # Obtener uids LDAP
    server = Server(app.config['LDAP_HOST'])
    conn = Connection(
        server,
        user=app.config['LDAP_BIND_USER_DN'],
        password=app.config['LDAP_BIND_USER_PASSWORD'],
        auto_bind=True
    )
    conn.search(
        search_base=f"{app.config['LDAP_USER_DN']},{app.config['LDAP_BASE_DN']}",
        search_filter='(uid=*)',
        search_scope=SUBTREE,
        attributes=['uid']
    )
    ldap_uids = [e.uid.value for e in conn.entries]
    conn.unbind()
    # Filtrar existentes
    con = db_conn()
    with con.cursor() as c:
        c.execute("SELECT username FROM user_app")
        existing = {r['username'] for r in c.fetchall()}
    pending = sorted(u for u in ldap_uids if u not in existing)
    if request.method == 'POST':
        selected = request.form.getlist('uids')
        role_id  = int(request.form.get('role_id', 3))
        if not selected:
            flash('No ha seleccionado usuarios', 'warning')
            return redirect(url_for('admin_usuarios'))
        with con.cursor() as c:
            for uid in selected:
                c.execute(
                    "INSERT IGNORE INTO user_app (username, role_id) VALUES (%s, %s)",
                    (uid, role_id)
                )
            con.commit()
        flash(f'Se han dado de alta {len(selected)} usuario(s)', 'success')
        return redirect(url_for('admin_usuarios'))
    return render_template('admin_usuarios.html', pending=pending)

# --- LDAP helper ---
def ldap_user_exists(username):
    server = Server(app.config['LDAP_HOST'])
    conn = Connection(
        server,
        user=app.config['LDAP_BIND_USER_DN'],
        password=app.config['LDAP_BIND_USER_PASSWORD'],
        auto_bind=True
    )
    conn.search(
        f"{app.config['LDAP_USER_DN']},{app.config['LDAP_BASE_DN']}",
        f'(uid={username})',
        search_scope=SUBTREE,
        attributes=['uid']
    )
    exists = bool(conn.entries)
    conn.unbind()
    return exists

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
