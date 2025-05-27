import logging
from flask import Flask, render_template, request, redirect, flash, url_for, session, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from ldap3 import Server, Connection, SUBTREE
import pymysql
from functools import wraps

# --- App Setup ---
app = Flask(__name__)
app.config.from_object('config.Config')
app.secret_key = app.config['SECRET_KEY']

# Forzar nivel DEBUG
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)
logging.getLogger('ldap3').setLevel(logging.DEBUG)

# Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- User Model ---
class User(UserMixin):
    def __init__(self, dn, username, groups, role_id=None):
        self.dn = dn
        self.id = username
        self.groups = groups
        self.role_id = role_id

@login_manager.user_loader
def load_user(user_id):
    data = session.get('user_info')
    if not data or data.get('username') != user_id:
        return None
    return User(data['dn'], data['username'], data['groups'], data.get('role_id'))

# --- DB Connection ---
def db_conn():
    return pymysql.connect(
        host=app.config['DB_HOST'],
        user=app.config['DB_USER'],
        password=app.config['DB_PASS'],
        db=app.config['DB_NAME'],
        cursorclass=pymysql.cursors.DictCursor
    )

# --- Roles decorator ---
def roles_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            if any(r in current_user.groups for r in roles) or \
               (current_user.role_id and any(r == current_user.role_id for r in roles)):
                return fn(*args, **kwargs)
            abort(403)
        return decorated
    return wrapper

# --- Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        app.logger.debug('+++ LOGIN POST para usuario: %s', u)

        # 1) Bind manual LDAP con DN usuario
        user_dn = f"uid={u},{app.config['LDAP_USER_DN']},{app.config['LDAP_BASE_DN']}"
        try:
            server = Server(app.config['LDAP_HOST'],
                            port=app.config['LDAP_PORT'],
                            use_ssl=app.config['LDAP_USE_SSL'])
            conn = Connection(server,
                              user=user_dn,
                              password=p,
                              auto_bind=True)
            app.logger.info("🔓 Bind exitoso para %s", user_dn)
        except Exception:
            app.logger.warning("❌ Credenciales LDAP inválidas para %s", user_dn)
            flash('Credenciales LDAP inválidas', 'danger')
            return render_template('login.html')

        # 2) Búsqueda manual de grupos usando memberUid
        try:
            with conn:
                base = f"{app.config['LDAP_GROUP_DN']},{app.config['LDAP_BASE_DN']}"
                flt  = f"(&(objectClass=posixGroup)(memberUid={u}))"
                app.logger.info('📁 LDAP search base=%s filter=%s', base, flt)

                found = conn.search(base, flt, SUBTREE, attributes=['cn'])
                if not found or not conn.entries:
                    app.logger.warning('❌ No se encontraron grupos para %s', u)
                    groups = []
                else:
                    groups = [e.cn.value for e in conn.entries]
                    app.logger.info('✅ Grupos encontrados: %s', groups)

                # Diagnóstico en UI
                flash(f"[DEBUG] grupos: {groups}", 'info')
        except Exception:
            app.logger.exception('💥 Error al buscar grupos LDAP')
            flash('Error interno buscando tus grupos', 'danger')
            return render_template('login.html')

        # 3) Determinar role_id
        if 'Administradores' in groups:
            role_id = 1
        else:
            with db_conn().cursor() as c:
                c.execute('SELECT role_id FROM user_app WHERE username=%s', (u,))
                row = c.fetchone()
            if not row:
                flash('Solicita tu alta al administrador', 'warning')
                return render_template('login.html')
            role_id = row['role_id']

        # 4) Crear user, guardar sesión y login
        user = User(user_dn, u, groups, role_id)
        session['user_info'] = {
            'dn': user_dn,
            'username': u,
            'groups': groups,
            'role_id': role_id
        }
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form['username'].strip()
        # Verificar existencia en LDAP
        server = Server(app.config['LDAP_HOST'], port=app.config['LDAP_PORT'], use_ssl=app.config['LDAP_USE_SSL'])
        conn = Connection(server,
                          user=app.config['LDAP_BIND_USER_DN'],
                          password=app.config['LDAP_BIND_USER_PASSWORD'],
                          auto_bind=True)
        conn.search(f"{app.config['LDAP_USER_DN']},{app.config['LDAP_BASE_DN']}",
                    f"(uid={u})", SUBTREE, attributes=['uid'])
        if not conn.entries:
            flash('Usuario no existe', 'danger')
            return redirect(url_for('register'))
        conn.unbind()

        # Alta en BD
        db = db_conn()
        with db.cursor() as c:
            c.execute('SELECT 1 FROM user_app WHERE username=%s', (u,))
            if c.fetchone():
                flash('Ya registrado', 'warning')
                return redirect(url_for('register'))
            c.execute('INSERT INTO user_app(username,role_id) VALUES(%s,3)', (u,))
            db.commit()
        flash('Usuario dado de alta', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/')
@login_required
def index():
    return render_template('index.html', groups=current_user.groups)

@app.route('/admin/usuarios', methods=['GET', 'POST'])
@login_required
@roles_required('Administradores')
def admin_usuarios():
    server = Server(app.config['LDAP_HOST'], port=app.config['LDAP_PORT'], use_ssl=app.config['LDAP_USE_SSL'])
    conn = Connection(server,
                      user=app.config['LDAP_BIND_USER_DN'],
                      password=app.config['LDAP_BIND_USER_PASSWORD'],
                      auto_bind=True)
    conn.search(f"{app.config['LDAP_USER_DN']},{app.config['LDAP_BASE_DN']}",
                '(uid=*)', SUBTREE, attributes=['uid'])
    ldap_uids = [e.uid.value for e in conn.entries]
    conn.unbind()

    db = db_conn()
    with db.cursor() as c:
        c.execute('SELECT username FROM user_app')
        existing = {r['username'] for r in c.fetchall()}
    pending = [u for u in ldap_uids if u not in existing]

    if request.method == 'POST':
        sel = request.form.getlist('uids')
        rid = int(request.form.get('role_id', 3))
        if not sel:
            flash('Nada seleccionado', 'warning')
            return redirect(url_for('admin_usuarios'))
        with db.cursor() as c:
            for uid in sel:
                c.execute('INSERT IGNORE INTO user_app(username,role_id) VALUES(%s,%s)', (uid, rid))
            db.commit()
        flash(f'{len(sel)} usuarios dados de alta', 'success')
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
