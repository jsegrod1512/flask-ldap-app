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

# Logging
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
               (current_user.role_id and any(str(r) == str(current_user.role_id) for r in roles)):
                return fn(*args, **kwargs)
            abort(403)
        return decorated
    return wrapper

# --- Routes ---
@app.route('/')
@login_required
def index():
    return render_template('index.html', groups=current_user.groups)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # existing login code here...
    pass

@app.route('/logout')
@login_required
def logout():
    # existing logout code here...
    pass

# --------------- ADMIN PANEL ---------------
@app.route('/admin/usuarios', methods=['GET', 'POST'])
@login_required
@roles_required('Administradores')
def admin_usuarios():
    """
    Gestión de usuarios registrados en la app:
    - Listar todos los usuarios de la tabla user_app
    - Cambiar role_id
    - Desactivar (eliminar) usuarios
    """
    db = db_conn()
    with db.cursor() as c:
        c.execute("SELECT username, role_id, created_at FROM user_app ORDER BY username")
        users = c.fetchall()

    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')
        if action == 'delete':
            with db.cursor() as c:
                c.execute("DELETE FROM user_app WHERE username=%s", (username,))
                db.commit()
            flash(f'Usuario {username} eliminado', 'warning')
        elif action == 'change_role':
            new_role = int(request.form.get('role_id'))
            with db.cursor() as c:
                c.execute("UPDATE user_app SET role_id=%s WHERE username=%s", (new_role, username))
                db.commit()
            flash(f'Rol de {username} cambiado a {new_role}', 'success')
        return redirect(url_for('admin_usuarios'))

    # Opciones de roles disponibles
    role_choices = [
        (1, 'Administrador'),
        (2, 'Desarrollador'),
        (3, 'Cliente')
    ]

    return render_template('admin_usuarios.html', users=users, role_choices=role_choices)

# --------------- CLIENTE & DEV ---------------
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
