import os
import base64
import sqlite3
import werkzeug.security
from flask import Flask, g, render_template, request, flash, make_response, url_for, session, jsonify
from flask_session import Session
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from forms import RegisterForm, LoginForm
import time
import ssl

app = Flask(__name__)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('certificate.crt', 'private.key')

app.config.from_object(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 900
Session(app)
DATABASE = 'database.db'

# https://www.quickprogrammingtips.com/python/aes-256-encryption-and-decryption-in-python.html
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


def get_private_key(password, salt):
    kdf = PBKDF2(password, salt, 64, 1000)
    key = kdf[:32]
    return key


def encrypt(raw, password, salt):
    private_key = get_private_key(password, salt)
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw.encode("utf-8")))


def decrypt(enc, password, salt):
    private_key = get_private_key(password, salt)
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))


def redirect(url, status=301):
    response = make_response('', status)
    response.headers['Location'] = url
    return response


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


def check_user():
    if session.get('user') is None:
        flash('Zaloguj się, aby mieć dostęp do tej strony.', 'error')
        return redirect(url_for('welcome'))


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


@app.after_request
def modify_header_security(res):
    res.headers['Server'] = 'server.company.com'
    return res


@app.route('/')
def welcome():
    return render_template('welcome.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hash_pw = werkzeug.security.generate_password_hash(password=form.password.data,
                                                           method='pbkdf2:sha256:200000')
        try:
            with sqlite3.connect("database.db") as con:
                cur = con.cursor()
                cur.execute("INSERT INTO users (login, password, email) VALUES (?,?,?)",
                            [form.login.data, hash_pw, form.email.data])
                con.commit()
                flash('Konto zostało utworzone!', 'success')
        except:
            con.rollback()
            flash("Wystąpił błąd z połączeniem z bazą danych.", 'error')
            return redirect(url_for('register'))
        finally:
            con.close()
        return redirect(url_for('login'))

    return render_template('registration.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('login_tries') is None:
        session['login_tries'] = 0

    form = LoginForm()
    if form.validate_on_submit():
        if session['login_tries'] <= 10:
            g.db = sqlite3.connect('database.db')
            cur = g.db.execute('select * from users where login = ?', [form.login.data])
            user = cur.fetchone()
            if user is not None:
                if werkzeug.security.check_password_hash(user[1], form.password.data):
                    session['user'] = user[0]
                    return redirect(url_for('dashboard'))
                else:
                    time.sleep(3)
                    session['login_tries'] = session['login_tries'] + 1
                    flash('Niepoprawne dane logowania.', 'error')
            else:
                time.sleep(3)
                session['login_tries'] = session['login_tries'] + 1
                flash('Niepoprawne dane logowania.', 'error')
        else:
            time.sleep(3)
            flash('Blokada logowania, spróbuj ponownie za 15 minut.', 'error')

    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET'])
def dashboard():
    if session.get('user') is None:
        flash('Zaloguj się, aby mieć dostęp do tej strony.', 'error')
        return redirect(url_for('welcome'))

    g.db = sqlite3.connect('database.db')
    cur = g.db.execute('SELECT * FROM sites WHERE user = ?', [session['user']])
    sites = cur.fetchone()
    if sites is not None:
        cur = g.db.execute('SELECT * FROM sites WHERE user = ?', [session['user']])
        sites = [dict(id=row[0], site=row[2], password='***** ***') for row in cur.fetchall()]
    else:
        sites = []

    return render_template('dashboard.html', sites=sites)


@app.route('/dashboard/site', methods=['POST'])
def dashboard_site():
    check_user()
    g.db = sqlite3.connect('database.db')
    cur = g.db.execute('select * from sites where site = ? AND user = ?',
                       [request.form['site'], session['user']])
    site = cur.fetchone()
    if site is None:
        try:
            salt = os.urandom(8)
            encrypted = encrypt(request.form['password'], session['masterPassword'], salt)
            with sqlite3.connect("database.db") as con:
                cur = con.cursor()
                cur.execute("INSERT INTO sites (user, site, password, salt) VALUES (?,?,?,?)",
                            [session['user'], request.form['site'], encrypted, salt])
                con.commit()
                flash('Dodano witrynę!', 'success')
        except:
            con.rollback()
            flash("Wystąpił błąd z połączeniem z bazą danych.", 'error')
            return redirect(url_for('dashboard'))
        finally:
            con.close()
    else:
        flash('Posiadasz już zapisane hasło do tej witryny!', 'error')

    return redirect(url_for('dashboard'))


@app.route('/dashboard/site/<site_id>', methods=['GET'])
def dashboard_site_reveal(site_id):
    check_user()
    if session['user'] is not None and session['masterPassword'] is not None:
        g.db = sqlite3.connect('database.db')
        cur = g.db.execute('select * from sites where id = ? AND user = ?',
                           [site_id, session['user']])
        site = cur.fetchone()
        decrypted = decrypt(site[3], session['masterPassword'], site[4])
        return jsonify(bytes.decode(decrypted))
    else:
        flash('Niepoprawne dane autoryzacyjne.', 'error')
        return redirect(url_for('welcome'))


@app.route('/dashboard/master-password-set', methods=['POST'])
def dashboard_master_password_set():
    check_user()
    if request.method == 'POST':
        session['masterPassword'] = request.form['masterPassword']
        flash('Twoje hasło odszyfrowujące zostało ustawione.', 'success')
        return redirect(url_for('dashboard'))


@app.route('/dashboard/master-password-flush', methods=['POST'])
def dashboard_master_password_flush():
    check_user()
    if request.method == 'POST':
        session.pop('masterPassword')
        return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    if session.get('masterPassword') is not None:
        session.pop('masterPassword')
    if session.get('user') is not None:
        session.pop('user')
    if session.get('csrf_token') is not None:
        session.pop('csrf_token')
    flash("Wylogowano pomyślnie.", 'success')
    return redirect(url_for('welcome'))


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', ssl_context=context)
