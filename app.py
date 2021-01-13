import json
import redis
import base64
import sqlite3
import werkzeug.security
from flask import Flask, g, render_template, request, flash, make_response, url_for, session, jsonify
from flask_redis import FlaskRedis
from flask_session import Session
from os import getenv
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired, EqualTo
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, TextField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, Email
from forms import RegisterForm, LoginForm

app = Flask(__name__)

app.config.from_object(__name__)
app.secret_key = getenv('SECRET_KEY')
app.config['SECRET_KEY'] = getenv('SECRET_KEY')
app.config['SESSION_TYPE'] = 'filesystem'
# redis_client = FlaskRedis(app)
# app.config['SESSION_REDIS'] = redis_client
Session(app)
DATABASE = 'database.db'

# https://www.quickprogrammingtips.com/python/aes-256-encryption-and-decryption-in-python.html
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


# class RegisterForm(FlaskForm):
#     login = StringField(
#         'Login',
#         [
#             DataRequired(message='Wpisz swój login.')
#         ]
#     )
#     email = StringField(
#         'Email',
#         [
#             Email(message='Niepoprawny adres email.'),
#             DataRequired(message='Wpisz email.')
#          ]
#     )
#     password = PasswordField(
#         'Haslo',
#         [
#             DataRequired(message='Wpisz hasło.'),
#             Length(min=8,
#                    message='Twoje hasło jest za krótkie.')
#         ]
#     )
#     password_repeat = PasswordField(
#         'Powtórz hasło',
#         [
#             EqualTo('password', message='Hasła muszą się zgadzać.')
#         ]
#     )
#     # recaptha = RecaptchaField()
#     submit = SubmitField('Utwórz konto')


def get_private_key(password):
    salt = b"this is a salt"
    kdf = PBKDF2(password, salt, 64, 1000)
    key = kdf[:32]
    return key


def encrypt(raw, password):
    private_key = get_private_key(password)
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw.encode("utf-8")))


def decrypt(enc, password):
    private_key = get_private_key(password)
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


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


@app.route('/')
def welcome():
    print(session)
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
    form = LoginForm()
    if form.validate_on_submit():
        g.db = sqlite3.connect('database.db')
        cur = g.db.execute('select * from users where login = ?', [form.login.data])
        user = cur.fetchone()
        if user is not None:
            if werkzeug.security.check_password_hash(user[1], form.password.data):
                session['user'] = user[0]
                return redirect(url_for('dashboard'))
            else:
                flash('Niepoprawne dane logowania.', 'error')
        else:
            flash('Niepoprawne dane logowania.', 'success')
    return render_template('login.html', form=form)
    # if request.method == 'GET':
    #     return render_template('login.html')
    #
    # if request.method == 'POST':
    #     g.db = sqlite3.connect('database.db')
    #     cur = g.db.execute('select * from users where login = ?', [request.form['login']])
    #     user = cur.fetchone()
    #     # user = dict(login=row[0], password=row[1]) for row in cur.fetchall()
    #     if user is not None:
    #         print(user)
    #         print('weryfikacja hasla:')
    #         print(werkzeug.security.check_password_hash(user[1], request.form['password']))
    #         if werkzeug.security.check_password_hash(user[1], request.form['password']):
    #             print(app.secret_key)
    #             session['user'] = user[0]
    #             return redirect(url_for('dashboard'))
    #
    #     flash('Niewłaściwe dane logowania.', 'error')
    #     return redirect(url_for('login'))
    #
    # else:
    #     flash("Wystąpił bład - niewłaściwy typ żądania", 'error')
    #     return redirect(url_for('welcome'))


@app.route('/dashboard', methods=['GET'])
def dashboard():
    if request.method == 'GET':
        g.db = sqlite3.connect('database.db')
        cur = g.db.execute('SELECT * FROM sites WHERE user = ?', [session['user']])
        sites = cur.fetchone()
        if sites is not None:
            cur = g.db.execute('SELECT * FROM sites WHERE user = ?', [session['user']])
            sites = [dict(id=row[0], site=row[2], password='***** ***') for row in cur.fetchall()]
        else:
            print('brak zapisanych stron')

        return render_template('dashboard.html', sites=sites)
    else:
        flash("Wystąpił błąd - niewłaściwy typ żądania", 'error')
        return redirect(url_for(welcome))


@app.route('/dashboard/site', methods=['POST'])
def dashboard_site():
    if request.method == 'POST':
        g.db = sqlite3.connect('database.db')
        cur = g.db.execute('select * from sites where site = ? AND user = ?',
                           [request.form['site'], session['user']])
        site = cur.fetchone()
        if site is None:
            try:
                encrypted = encrypt(request.form['password'], session['masterPassword'])
                with sqlite3.connect("database.db") as con:
                    cur = con.cursor()
                    cur.execute("INSERT INTO sites (user, site, password) VALUES (?,?,?)",
                                [session['user'], request.form['site'], encrypted])
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
    if request.method == 'GET':
        if session['user'] is not None and session['masterPassword'] is not None:
            g.db = sqlite3.connect('database.db')
            cur = g.db.execute('select * from sites where id = ? AND user = ?',
                               [site_id, session['user']])
            site = cur.fetchone()
            decrypted = decrypt(site[3], session['masterPassword'])
            return jsonify(bytes.decode(decrypted))
    return redirect(url_for('dashboard'))


@app.route('/dashboard/master-password-set', methods=['POST'])
def dashboard_master_password_set():
    if request.method == 'POST':
        session['masterPassword'] = request.form['masterPassword']
        print('Twoje hasło odszyfrowujące zostało ustawione.')
        flash('Twoje hasło odszyfrowujące zostało ustawione.', 'success')
        return redirect(url_for('dashboard'))


@app.route('/dashboard/master-password-flush', methods=['POST'])
def dashboard_master_password_flush():
    if request.method == 'POST':
        session.pop('masterPassword')
        return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    if session.get('masterPassword') is not None:
        session.pop('masterPassword')
    session.pop('user')
    flash("Wylogowano pomyślnie.", 'success')
    return redirect(url_for('welcome'))


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', ssl_context='adhoc')
