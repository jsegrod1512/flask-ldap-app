from flask import Flask, render_template, request, redirect, flash, url_for, session, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_ldap3_login import LDAP3LoginManager
from ldap3 import Server, Connection, SUBTREE
import pymysql
from functools import wraps
from pymysql.err import IntegrityError

# --- Application Setup ---
app = Flask(__name__)
app.secret_key = "cámbiame"

# --- Load Configuration ---
from config import Config
app.config.from_object(Config)
# Alias for LDAP_HOST if necessary
if 'LDAP_SERVER' in app.config and 'LDAP_HOST' not in app.config:
    app.config['LDAP_HOST'] = app.config['LDAP_SERVER']

# --- Flask-Login Manager ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- LDAP3 Login Manager ---
ldap_manager = LDAP3LoginManager(app)

# --- User Model ---
class User(UserMixin):
    def __init__(self, dn, username, data, memberships, role_id=None):
        self.dn = dn
        self.id = username
        self.data = data
        self.memberships = memberships
        self.role_id = role_id

@login_manager.user_loader
def load_user(user_id):
    return session.get('user_obj')

@ldap_manager.save_user
def save_user(dn, username, data, memberships):
    # Almacena temporalmente el objeto User en sesión
    user = User(dn, username, data, memberships)
    session['user_obj'] = user
    return user

# --- Role-Based Access Decorator ---
def roles_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            user_groups = [dn.split(',')[0].split('=')[1] for dn in current_user.memberships]
            role_map = {'Administradores':1, 'Desarrolladores':2, 'Clientes':3}
            # Comprueba grupos LDAP
            if any(r in user_groups for r in roles):
                return fn(*args, **kwargs)
            # Comprueba role_id de base de datos
            if current_user.role_id and any(role_map.get(r)==current_user.role_id for r in roles):
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
        db=app.config['DB_NAME']
    )

# --- Routes ---
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']

        # 1) Comprobar existencia en LDAP
        if not ldap_user_exists(u):
            flash('Ese usuario no existe en LDAP', 'danger')
            return redirect(url_for('register'))

        con = db_conn()
        with con.cursor() as c:
            # 2) Comprobar duplicado en MySQL
            c.execute("SELECT 1 FROM user_app WHERE username=%s", (u,))
            if c.fetchone():
                flash(f'El usuario {u} ya está registrado en la aplicación.', 'warning')
                return redirect(url_for('register'))
            # 3) Insertar nuevo registro
            try:
                c.execute(
                    "INSERT INTO user_app (username, password_hash, role_id) "
                    "VALUES (%s, SHA2(%s,512), %s)",
                    (u, p, 3)  # role_id=3 (Cliente) por defecto
                )
                con.commit()
            except IntegrityError:
                flash(f'Error: el usuario {u} ya existe (integrity error).', 'warning')
                return redirect(url_for('register'))

        flash('Usuario creado en la base de datos', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u, p = request.form['username'], request.form['password']
        try:
            # 1) Autenticar contra LDAP
            result = ldap_manager.authenticate(u, p)
            if result.status != 'success':
                flash('Credenciales LDAP inválidas', 'danger')
                return render_template('login.html')

            # 2) Extraer grupos LDAP
            ldap_groups = [dn.split(',')[0].split('=')[1] for dn in result.user.memberships]

            # 3) Si es Administrador, le damos acceso directo:
            if 'Administradores' in ldap_groups:
                role_id = 1
            else:
                # 4) Para el resto, chequeamos en MySQL
                con = db_conn()
                with con.cursor() as c:
                    c.execute("SELECT role_id FROM user_app WHERE username=%s", (u,))
                    row = c.fetchone()
                if not row:
                    flash('Debes solicitar tu alta al Administrador', 'warning')
                    return render_template('login.html')
                role_id = row[0]

            # 5) Completar objeto User y loguear
            user = result.user
            user.role_id = role_id
            session['user_obj'] = user
            login_user(user)
            flash(f'Bienvenido, {u}!', 'success')
            return redirect(url_for('index'))

        except Exception:
            flash('Error de autenticación', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_obj', None)
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
    # 1) Obtener todos los usuarios LDAP
    server = Server(app.config['LDAP_HOST'])
    conn = Connection(
        server,
        user=app.config['LDAP_BIND_DN'],
        password=app.config['LDAP_BIND_PW'],
        auto_bind=True
    )
    conn.search(
        search_base=app.config['LDAP_USER_DN'],
        search_filter='(uid=*)',
        search_scope=SUBTREE,
        attributes=['uid']
    )
    ldap_uids = [e.uid.value for e in conn.entries]
    conn.unbind()

    # 2) Usuarios ya en MySQL
    con = db_conn()
    with con.cursor() as c:
        c.execute("SELECT username FROM user_app")
        existing = {r[0] for r in c.fetchall()}

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
                    "INSERT IGNORE INTO user_app (username, password_hash, role_id) "
                    "VALUES (%s, SHA2(%s,512), %s)",
                    (uid, uid, role_id)
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
        user=app.config['LDAP_BIND_DN'],
        password=app.config['LDAP_BIND_PW'],
        auto_bind=True
    )
    conn.search(
        app.config['LDAP_USER_DN'],
        f'(uid={username})',
        search_scope=SUBTREE,
        attributes=['uid']
    )
    exists = bool(conn.entries)
    conn.unbind()
    return exists

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
