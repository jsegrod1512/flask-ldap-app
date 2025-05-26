from flask import Flask, render_template, request, redirect, flash
import ldap3, pymysql

app = Flask(__name__)
app.secret_key = "cámbiame"

# --- Carga de config.py generado por Ansible ---
app.config.from_pyfile('config.py')

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
        # Alta en MySQL
        con = db_conn()
        with con.cursor() as c:
            c.execute(
              "INSERT INTO user_app (username, password_hash, role_id) VALUES (%s, SHA2(%s,512), %s)",
              (u, p, 3)
            )
            con.commit()
        flash('Usuario creado', 'success')
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

if __name__=='__main__':
    app.run(host='0.0.0.0', port=8080)
