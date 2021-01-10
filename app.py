import json
import redis
import sqlite3
import werkzeug
from flask import Flask, g, render_template, request, flash, make_response, url_for, session
from flask_redis import FlaskRedis
from flask_session import Session
from os import getenv


app = Flask(__name__)

app.config.from_object(__name__)
app.secret_key = getenv('SECRET_KEY')
app.config['SECRET_KEY'] = getenv('SECRET_KEY')
app.config['SESSION_TYPE'] = 'filesystem'
# redis_client = FlaskRedis(app)
# app.config['SESSION_REDIS'] = redis_client
Session(app)
DATABASE = 'database.db'


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
    print("stawiam baze")
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
    print("baza postawiona")


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
    if request.method == 'GET':
        return render_template('registration.html')

    if request.method == 'POST':
        hash_pw = werkzeug.security.generate_password_hash(password=request.form['password'], method='pbkdf2:sha256:200000')
        try:
            with sqlite3.connect("database.db") as con:
                cur = con.cursor()
                cur.execute("INSERT INTO users (login, password) VALUES (?,?)", (request.form['login'], hash_pw))
                con.commit()
        except:
            con.rollback()
            flash("Wystąpił błąd z połączeniem z bazą danych.")
            return redirect(url_for(register))
        finally:
            con.close()

        return redirect(url_for('login'))

    else:
        flash("Wystąpił bład - niewłaściwy typ żądania")
        return redirect(url_for(welcome))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        g.db = sqlite3.connect('database.db')
        cur = g.db.execute('select * from users where login = ?', [request.form['login']])
        user = cur.fetchone()
        # user = dict(login=row[0], password=row[1]) for row in cur.fetchall()
        if user is not None:
            print(user)
            print('weryfikacja hasla:')
            print(werkzeug.security.check_password_hash(user[1], request.form['password']))
            if werkzeug.security.check_password_hash(user[1], request.form['password']):
                print(app.secret_key)
                session['user'] = user[0]
                return redirect(url_for('dashboard'))

        flash('Niewłaściwe dane logowania.')
        return redirect(url_for('login'))

    else:
        flash("Wystąpił bład - niewłaściwy typ żądania")
        return redirect(url_for(welcome))


@app.route('/dashboard', methods=['GET'])
def dashboard():
    print(session)

    return render_template('dashboard.html')


@app.route('/dashboard/site', methods=['POST'])
def dashboard_site():
    if request.method == 'POST':
        g.db = sqlite3.connect('database.db')
        cur = g.db.execute('select * from sites where site = ? AND user = ?', [request.form['site'], session['user']])
        site = cur.fetchone()
        print(session['user'])
        print(site)
        if site is None:
            try:
                print('dodaje witryne')
                with sqlite3.connect("database.db") as con:
                    cur = con.cursor()
                    cur.execute("INSERT INTO sites (user, site) VALUES (?,?)", [session['user'], request.form['site']])
                    con.commit()
                    flash('Dodano witrynę!')
            except:
                print('cos poszlo nie tak')
                con.rollback()
                flash("Wystąpił błąd z połączeniem z bazą danych.")
                return redirect(url_for('dashboard'))
            finally:
                con.close()
        else:
            flash('Posiadasz już zapisane hasło do tej witryny!')
        return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.pop('user')
    flash("Wylogowano pomyślnie.")
    return redirect(url_for('welcome'))


if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', ssl_context='adhoc')
