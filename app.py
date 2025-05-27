import logging
from flask import Flask, render_template, request, redirect, flash, url_for, session, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_ldap3_login import LDAP3LoginManager
from ldap3 import Server, Connection, SUBTREE
import pymysql
from functools import wraps

# --- App Setup ---
app = Flask(__name__)
app.config.from_object('config.Config')
app.secret_key = app.config.get('SECRET_KEY')

# Logging level
logging.basicConfig(level=logging.DEBUG)
logging.getLogger('ldap3').setLevel(logging.DEBUG)

# Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# LDAP3 Login
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
    data = session.get('user_info')
    if not data or data.get('username') != user_id:
        return None
    return User(data['dn'], data['username'], data['memberships'], data.get('role_id'))

@ldap_manager.save_user
def save_user(dn, username, data, memberships):
    # Store minimal info
    session['user_info'] = {
        'dn': dn,
        'username': username,
        'memberships': memberships,
        'role_id': None
    }
    return User(dn, username, memberships)

# --- Database Connection ---
def db_conn():
    return pymysql.connect(
        host=app.config['DB_HOST'],
        user=app.config['DB_USER'],
        password=app.config['DB_PASS'],
        db=app.config['DB_NAME'],
        cursorclass=pymysql.cursors.DictCursor
    )

# --- Role Decorator ---
def roles_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            groups = [dn.split(',')[0].split('=')[1] for dn in current_user.memberships]
            role_map = {'Administradores':1,'Desarrolladores':2,'Clientes':3}
            # LDAP group check
            if any(r in groups for r in roles):
                return fn(*args, **kwargs)
            # DB role_id check
            if current_user.role_id and any(role_map[r]==current_user.role_id for r in roles):
                return fn(*args, **kwargs)
            abort(403)
        return decorated
    return wrapper

# --- Routes ---
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            result = ldap_manager.authenticate(username, password)
        except Exception as e:
            app.logger.exception('LDAP auth error')
            flash('Error interno en autenticación', 'danger')
            return render_template('login.html')
        if result.status != 'success':
            flash('Credenciales LDAP inválidas', 'danger')
            return render_template('login.html')
        # Determine role
        groups = list(result.user_groups)
        if 'Administradores' in groups:
            role_id = 1
        else:
            conn = db_conn()
            with conn.cursor() as c:
                c.execute('SELECT role_id FROM user_app WHERE username=%s', (username,))
                row = c.fetchone()
            if not row:
                flash('Solicita alta al Administrador', 'warning')
                return render_template('login.html')
            role_id = row['role_id']
        # Save and login
        user = result.user
        user.role_id = role_id
        session['user_info']['role_id'] = role_id
        login_user(user)
        flash(f'Bienvenido, {username}!', 'success')
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_info', None)
    flash('Sesión cerrada', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        # Verify LDAP existence
        server = Server(app.config['LDAP_HOST'], port=app.config['LDAP_PORT'], use_ssl=app.config['LDAP_USE_SSL'])
        conn = Connection(server, user=app.config['LDAP_BIND_USER_DN'], password=app.config['LDAP_BIND_USER_PASSWORD'], auto_bind=True)
        conn.search(
            search_base=f"{app.config['LDAP_USER_DN']},{app.config['LDAP_BASE_DN']}",
            search_filter=f'(uid={username})',
            search_scope=SUBTREE,
            attributes=['uid']
        )
        if not conn.entries:
            flash('Usuario no existe en LDAP', 'danger')
            return redirect(url_for('register'))
        conn.unbind()
        # Insert as Cliente
        conn_db = db_conn()
        with conn_db.cursor() as c:
            c.execute('SELECT 1 FROM user_app WHERE username=%s', (username,))
            if c.fetchone():
                flash('Usuario ya registrado', 'warning')
                return redirect(url_for('register'))
            c.execute('INSERT INTO user_app (username, role_id) VALUES (%s,3)', (username,))
            conn_db.commit()
        flash('Usuario dado de alta', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/')
@login_required
def index():
    groups = [dn.split(',')[0].split('=')[1] for dn in current_user.memberships]
    return render_template('index.html', groups=groups)

@app.route('/admin/usuarios', methods=['GET','POST'])
@login_required
@roles_required('Administradores')
def admin_usuarios():
    # Fetch LDAP uids
    server = Server(app.config['LDAP_HOST'], port=app.config['LDAP_PORT'], use_ssl=app.config['LDAP_USE_SSL'])
    conn = Connection(server, user=app.config['LDAP_BIND_USER_DN'], password=app.config['LDAP_BIND_USER_PASSWORD'], auto_bind=True)
    conn.search(
        search_base=f"{app.config['LDAP_USER_DN']},{app.config['LDAP_BASE_DN']}",
        search_filter='(uid=*)',
        search_scope=SUBTREE,
        attributes=['uid']
    )
    ldap_uids = [e.uid.value for e in conn.entries]
    conn.unbind()
    # Filter pending
    db = db_conn()
    with db.cursor() as c:
        c.execute('SELECT username FROM user_app')
        existing = {r['username'] for r in c.fetchall()}
    pending = sorted(u for u in ldap_uids if u not in existing)
    if request.method == 'POST':
        selected = request.form.getlist('uids')
        role_id = int(request.form.get('role_id', 3))
        if not selected:
            flash('No has seleccionado usuarios', 'warning')
            return redirect(url_for('admin_usuarios'))
        with db.cursor() as c:
            for uid in selected:
                c.execute('INSERT IGNORE INTO user_app (username, role_id) VALUES (%s,%s)', (uid, role_id))
            db.commit()
        flash(f'Se han dado de alta {len(selected)} usuarios', 'success')
        return redirect(url_for('admin_usuarios'))
    return render_template('admin_usuarios.html', pending=pending)

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
