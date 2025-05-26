from flask import Flask, render_template, request, redirect, flash
import ldap3, pymysql

app = Flask(__name__)
app.secret_key = "cámbiame"

# --- Carga de config.py generado por Ansible ---
from config import Config
app.config.from_object(Config)

def ldap_bind(username, password):
    server = ldap3.Server(app.config['LDAP_SERVER'])
    dn = f"uid={username},{app.config['LDAP_USER_DN']}"
    conn = ldap3.Connection(server, dn, password, auto_bind=True)
    conn.unbind()
    return True

def db_conn():
    return pymysql.connect(
        host=app.config['DB_HOST'],
        user=app.config['DB_USER'],
        password=app.config['DB_PASS'],
        db=app.config['DB_NAME']
    )

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']

        # 1) Comprobar en LDAP
        if not ldap_user_exists(u):
            flash('Ese usuario no existe en LDAP', 'danger')
            return redirect('/register')

        # 2) Si existe → dar de alta en MySQL
        con = db_conn()
        with con.cursor() as c:
            c.execute(
              "INSERT INTO user_app (username, password_hash, role_id) "
              "VALUES (%s, SHA2(%s,512), %s)",
              (u, p, 3)
            )
            con.commit()

        flash('Usuario creado en la base de datos', 'success')
        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        u,p = request.form['username'], request.form['password']
        try:
            if ldap_bind(u,p):
                flash('Login OK', 'success')
                return '¡Bienvenido '+u+'!'
        except:
            flash('Credenciales inválidas', 'danger')
    return render_template('login.html')

from ldap3 import Server, Connection, SUBTREE

def ldap_user_exists(username):
    """
    Comprueba si un uid ya existe en LDAP bajo ou=Users.
    """
    server = Server(app.config['LDAP_SERVER'])
    conn = Connection(
        server,
        user=app.config['LDAP_BIND_DN'],
        password=app.config['LDAP_BIND_PW'],
        auto_bind=True
    )
    search_base = app.config['LDAP_USER_DN']
    # Busca el uid exacto
    conn.search(
        search_base,
        f'(uid={username})',
        search_scope=SUBTREE,
        attributes=['uid']
    )
    exists = bool(conn.entries)
    conn.unbind()
    return exists


if __name__=='__main__':
    app.run(host='0.0.0.0', port=8080)
