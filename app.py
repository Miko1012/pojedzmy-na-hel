import datetime
import json
import sqlite3
from flask import Flask, g, render_template, request, flash, make_response, url_for

app = Flask(__name__)
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
    return render_template('welcome.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('registration.html')

    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']

        try:
            with sqlite3.connect("database.db") as con:
                cur = con.cursor()
                cur.execute("INSERT INTO users (login, password) VALUES (?,?)", (login, password))
                con.commit()
        except:
            con.rollback()
            flash("Wystąpił błąd z połączeniem z bazą danych.")
            return redirect(url_for(register))
        finally:
            con.close()

        return redirect(url_for(login))

    else:
        flash("Wystąpił bład - niewłaściwy typ żądania")
        return redirect(url_for(welcome))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        # login = request.form['login']
        # password = request.form['password']

        # con = sqlite3.connect("database.db")
        # con.row_factory = sqlite3.Row
        #
        # cur = con.cursor()
        # cur.execute("SELECT * FROM users WHERE users.login = (?)", request.form['login'])
        #
        # rows = cur.fetchall()

        # rows = query_db("select * from users where users.login = (?)", login)
        # print(rows)

        # print(rows)
        g.db = sqlite3.connect('database.db')
        cur = g.db.execute('select * from users where login = ?', [request.form['login']])
        user = cur.fetchone()
        # user = dict(login=row[0], password=row[1]) for row in cur.fetchall()
        print(user[0])

        return json.dumps(user)

    else:
        flash("Wystąpił bład - niewłaściwy typ żądania")
        return redirect(url_for(welcome))


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', ssl_context='adhoc')
