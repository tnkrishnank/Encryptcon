from flask import Flask, render_template, url_for, redirect, session, make_response, request
from authlib.common.security import generate_token
from authlib.integrations.flask_client import OAuth
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import uuid
import os

app = Flask(__name__)
app.secret_key = os.urandom(12)

oauth = OAuth(app)

uri = "mongodb+srv://encryptcon:hackathon@encryptcon.cbj7goz.mongodb.net/?retryWrites=true&w=majority"
conn = MongoClient(uri, server_api=ServerApi('1'))
db = conn.TrojanBucket

@app.route("/messageCard", methods = ["GET"])
def messageCard():
    return render_template("messageCard.html", title = session['title'], message = session['message'], login = session['login'])

@app.route('/', methods = ["GET"])
def index():
    session['title'] = "Message Card"
    session['message'] = "Hello Message !"
    session['login'] = True

    try:
        if 'cUser' in request.cookies:
            return redirect("/dashboard")

        return render_template('index.html')
    except:
        if 'cUser' not in request.cookies:
            return redirect("/")

        session['title'] = "404 ERROR"
        session['message'] = "404 ERROR. PAGE NOT FOUND !!!"
        session['login'] = True
        return redirect("/messageCard")

@app.route("/signup", methods = ["GET"])
def signup():
    session['title'] = "Message Card"
    session['message'] = "Hello Message !"
    session['login'] = True

    try:
        if 'cUser' in request.cookies:
            return redirect("/dashboard")

        return render_template('signup.html')
    except:
        if 'cUser' not in request.cookies:
            return redirect("/")

        session['title'] = "404 ERROR"
        session['message'] = "404 ERROR. PAGE NOT FOUND !!!"
        session['login'] = True
        return redirect("/messageCard")

@app.route('/googleOAuth')
def googleOAuth():
    session['title'] = "Message Card"
    session['message'] = "Hello Message !"
    session['login'] = True

    try:
        if 'cUser' in request.cookies:
            return redirect("/dashboard")

        GOOGLE_CLIENT_ID = '907651305848-0jp4po8dotp5n5ff4vvrs8bueaek78dh.apps.googleusercontent.com'
        GOOGLE_CLIENT_SECRET = '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'

        CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
        oauth.register(
            name='google',
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            server_metadata_url=CONF_URL,
            client_kwargs={
                'scope': 'openid email profile'
            }
        )

        session['nonce'] = generate_token()
        redirect_uri = url_for('googleOAuth_auth', _external=True)

        return oauth.google.authorize_redirect(redirect_uri, nonce=session['nonce'])
    except:
        if 'cUser' not in request.cookies:
            return redirect("/")

        session['title'] = "404 ERROR"
        session['message'] = "404 ERROR. PAGE NOT FOUND !!!"
        session['login'] = True
        return redirect("/messageCard")

@app.route('/googleOAuth/auth')
def googleOAuth_auth():
    session['title'] = "Message Card"
    session['message'] = "Hello Message !"
    session['login'] = True

    try:
        if 'cUser' in request.cookies:
            return redirect("/dashboard")

        token = oauth.google.authorize_access_token()
        user = oauth.google.parse_id_token(token, nonce=session['nonce'])

        collection = db.UserInfo
        dataInDB = collection.find_one({ "email": user['email'] })

        if dataInDB is None:
            u = str(uuid.uuid4())
            userData = {
                "uuid": u,
                "email": user['email'],
                "name": user['given_name'] + " " + user['family_name']
            }
            collection.insert_one(userData)
        else:
            u = dataInDB['uuid']

        resp = make_response(redirect('/dashboard'))
        resp.set_cookie('cUser', u, max_age=604800)

        return resp
    except:
        if 'cUser' not in request.cookies:
            return redirect("/")

        session['title'] = "404 ERROR"
        session['message'] = "404 ERROR. PAGE NOT FOUND !!!"
        session['login'] = True
        return redirect("/messageCard")

@app.route("/dashboard", methods = ["GET", "POST"])
def dashboard():
    session['title'] = "Message Card"
    session['message'] = "Hello Message !"
    session['login'] = True

    try:
        if 'cUser' not in request.cookies:
            return redirect("/")

        if request.method == "POST":
            if request.form["logout"] == "signout":

                resp = make_response(redirect('/'))
                resp.set_cookie('cUser', '', max_age=0)

                return resp
            else:
                pass
        else:
            collection = db.UserInfo
            dataInDB = collection.find_one({ "uuid": request.cookies.get('cUser') })

            if dataInDB is not None:
                return render_template("dashboard.html", welcome = dataInDB['name'])
            else:
                session['title'] = "ACCOUNT ERROR"
                session['message'] = "ACCOUNT NOT FOUND. LOGIN OR SIGNUP !!!"
                session['login'] = True

                resp = make_response(redirect('/messageCard'))
                resp.set_cookie('cUser', '', max_age=0)

                return resp
    except:
        if 'cUser' in request.cookies:
            return redirect("/dashboard")

        session['title'] = "404 ERROR"
        session['message'] = "404 ERROR. PAGE NOT FOUND !!!"
        session['login'] = False
        return redirect("/messageCard")

@app.route("/settings", methods = ["GET"])
def settings():
    session['title'] = "Message Card"
    session['message'] = "Hello Message !"
    session['login'] = True

    try:
        if 'cUser' not in request.cookies:
            return redirect("/")

        return render_template("settings.html")
    except:
        if 'cUser' in request.cookies:
            return redirect("/dashboard")

        session['title'] = "404 ERROR"
        session['message'] = "404 ERROR. PAGE NOT FOUND !!!"
        session['login'] = False
        return redirect("/messageCard")

@app.route("/profile", methods = ["GET"])
def profile():
    session['title'] = "Message Card"
    session['message'] = "Hello Message !"
    session['login'] = True

    try:
        if 'cUser' not in request.cookies:
            return redirect("/")

        collection = db.UserInfo
        dataInDB = collection.find_one({ "uuid": request.cookies.get('cUser') })

        if dataInDB is not None:
            return render_template("profile.html", name = dataInDB['name'], email = dataInDB['email'])
        else:
            session['title'] = "ACCOUNT ERROR"
            session['message'] = "ACCOUNT NOT FOUND. LOGIN OR SIGNUP !!!"
            session['login'] = True

            resp = make_response(redirect('/messageCard'))
            resp.set_cookie('cUser', '', max_age=0)

            return resp
    except:
        if 'cUser' in request.cookies:
            return redirect("/dashboard")

        session['title'] = "404 ERROR"
        session['message'] = "404 ERROR. PAGE NOT FOUND !!!"
        session['login'] = False
        return redirect("/messageCard")

@app.route("/deleteAccount", methods = ["GET"])
def deleteAccount():
    session['title'] = "Message Card"
    session['message'] = "Hello Message !"
    session['login'] = True

    try:
        if 'cUser' not in request.cookies:
            return redirect("/")

        collection = db.UserInfo
        dataInDB = collection.find_one({ "uuid": request.cookies.get('cUser') })

        if dataInDB is not None:
            collection.delete_one({ "uuid": request.cookies.get('cUser') })

            session['title'] = "ACCOUNT DELETION"
            session['message'] = "ACCOUNT DELETED SUCCESSFULLY !!!"
            session['login'] = True

            resp = make_response(redirect('/messageCard'))
            resp.set_cookie('cUser', '', max_age=0)

            return resp
        else:
            session['title'] = "ACCOUNT ERROR"
            session['message'] = "ACCOUNT NOT FOUND. LOGIN OR SIGNUP !!!"
            session['login'] = True

            resp = make_response(redirect('/messageCard'))
            resp.set_cookie('cUser', '', max_age=0)

            return resp
    except:
        if 'cUser' in request.cookies:
            return redirect("/dashboard")

        session['title'] = "404 ERROR"
        session['message'] = "404 ERROR. PAGE NOT FOUND !!!"
        session['login'] = False
        return redirect("/messageCard")

if __name__ == '__main__':
    app.run(
        host = '0.0.0.0',
        debug = True,
        port = 8080
    )