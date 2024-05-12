# ZERO KNOWLEDGE PROOF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    message = message.encode('utf-8')
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature(public_key, message, signature):
    message = message.encode('utf-8')
    public_key.verify(
        signature,
        message,
        ec.ECDSA(hashes.SHA256())
    )

def generate_zero_knowledge_proof(private_key, statement):
    commitment = sign_message(private_key, statement)
    return commitment

def verify_zero_knowledge_proof(public_key, statement, commitment):
    try:
        verify_signature(public_key, statement, commitment)
        return True
    except Exception:
        return False


# BLOCKCHAIN IMPLEMENTATION
import hashlib
import datetime

class Block:
    def __init__(self, index, previous_hash, timestamp, username, password, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.username = username
        self.password = hashlib.sha256(password.encode()).hexdigest()
        self.hash = hash

def calculate_hash(index, previous_hash, timestamp, username):
    value = str(index) + str(previous_hash) + str(timestamp) + str(username)
    return hashlib.sha256(value.encode()).hexdigest()

def create_genesis_block():
    return Block(0, "0", datetime.datetime.now(), "Genesis Block", "Genesis block", calculate_hash(0, "0", datetime.datetime.now(), "Genesis Block"))

def create_new_block(username, password):
    index = previous_block.index + 1
    timestamp = datetime.datetime.now()
    hash = calculate_hash(index, previous_block.hash, timestamp, username)
    return Block(index, previous_block.hash, timestamp, username, password, hash)

def create_blockchain_user(username, passwd):
    new_block = create_new_block(username, passwd)
    blockchain.append(new_block)
    previous_block = new_block

def authenticate_blockchain_user(username,passwd):
    for i in range(1, len(blockchain)):
        if blockchain[i].username == username:
            if (hashlib.sha256(passwd.encode()).hexdigest()) == blockchain[i].password:
                current_block = blockchain[i]
                previous_block = blockchain[i - 1]

                if current_block.previous_hash == previous_block.hash:
                    calculated_hash = calculate_hash(current_block.index, current_block.previous_hash, current_block.timestamp, current_block.username)
                    if current_block.hash == calculated_hash:
                        return True
    return False

blockchain = [create_genesis_block()]
previous_block = blockchain[0]


# DATA IN MOTION
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import hashlib

def generate_key():
    return os.urandom(32)

def encrypt(message, key):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext, nonce, encryptor.tag

def decrypt(ciphertext, key, nonce, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    
    return plaintext.decode('utf-8')

def hash_function(x):
    return hashlib.sha256(x.encode('utf-8')).digest()

def functional_encrypt(message, key, function_key):
    hashed_function_key = hash_function(function_key)
    modified_message = message + hashed_function_key.decode('latin-1')  # Convert bytes to str
    ciphertext, nonce, tag = encrypt(modified_message, key)
    return ciphertext, nonce, tag

def functional_decrypt(ciphertext, key, function_key, nonce, tag):
    hashed_function_key = hash_function(function_key)
    modified_message = decrypt(ciphertext, key, nonce, tag)
    if hashed_function_key.decode('latin-1') in modified_message:
        return modified_message.replace(hashed_function_key.decode('latin-1'), '')
    else:
        return False

master_key = generate_key()
function_key = "AuthorizedFunction"


# DATA ENCRYPTION AND DECRYPTION
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher_suite = Fernet(key)

def data_encrypt(value):
    value = str(value)
    return cipher_suite.encrypt(value.encode('utf-8'))

def data_decrypt(value):
    return float(cipher_suite.decrypt(value.decode('utf-8')))

# WEB APPLICATION
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

def isValidUsername(s):
    special_characters = "\\!@#$%^&*()-+?_=,<>/'"

    if len(s) >= 5:
        for i in s:
            if i in special_characters:
                return False
    else:
        return False

    return True

def isValidPassword(s):
    if len(s) >= 8:
        for i in s:
            if i.isupper():
                return True

    return False

@app.route("/messageCard", methods = ["GET"])
def messageCard():
    return render_template("messageCard.html", title = session['title'], message = session['message'], login = session['login'])

@app.route('/', methods = ["GET", "POST"])
def index():
    session['title'] = "Message Card"
    session['message'] = "Hello Message !"
    session['login'] = True

    try:
        if 'cUser' in request.cookies:
            return redirect("/dashboard")

        if request.method == "POST":
            username = request.form["username"]
            password = request.form["password"]

            if(authenticate_blockchain_user(username, password)):
                collection = db.UserInfo
                dataInDB = collection.find_one({ "username": username })

                resp = make_response(redirect('/dashboard'))
                resp.set_cookie('cUser', dataInDB['uuid'], max_age=604800)

                return resp
            else:
                return render_template("index.html", invalidMsg = "INVALID USERNAME OR PASSWORD !")
        else:
            return render_template('index.html')
    except:
        if 'cUser' not in request.cookies:
            return redirect("/")

        session['title'] = "404 ERROR"
        session['message'] = "404 ERROR. PAGE NOT FOUND !!!"
        session['login'] = True
        return redirect("/messageCard")

@app.route("/signup", methods = ["GET", "POST"])
def signup():
    session['title'] = "Message Card"
    session['message'] = "Hello Message !"
    session['login'] = True

    try:
        if 'cUser' in request.cookies:
            return redirect("/dashboard")

        if request.method == "POST":
            name = request.form["name"]
            username = request.form["username"]
            email = request.form["email"]
            password = request.form["password"]
            reTypePassword = request.form["re-password"]

            if isValidUsername(username):
                if isValidPassword(password):
                    if password == reTypePassword:
                        collection = db.UserInfo

                        dataInDB = collection.find_one({ "username": username })
                        if dataInDB is not None:
                            return render_template("signup.html", usernameMsg = "USER ALREADY EXISTS !")

                        dataInDB = collection.find_one({ "email": email })
                        if dataInDB is not None:
                            return render_template("signup.html", emailMsg = "EMAIL ALREADY EXISTS !")

                        u = str(uuid.uuid4())
                        userData = {
                            "uuid": u,
                            "name": name,
                            "username": username,
                            "email": email,
                            "password": hashlib.sha256(password.encode()).hexdigest(),
                            "account_number": str(collection.count_documents({}) + 1),
                            "balance": data_encrypt(1000.0)
                        }
                        collection.insert_one(userData)

                        create_blockchain_user(username, password)

                        resp = make_response(redirect('/dashboard'))
                        resp.set_cookie('cUser', u, max_age=604800)
                        
                        return resp
                    else:
                        return render_template("signup.html", rePasswordMsg = "PASSWORDS DO NOT MATCH !")
                else:
                    return render_template("signup.html", passwordMsg = "Atleast 8 characters. Atleast one character in Uppercase !")
            else:
                return render_template("signup.html", usernameMsg = "Atleast 5 characters. No special characters allowed !")
        else:
            return render_template('signup.html')
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

@app.route("/balance", methods = ["GET"])
def balance():
    session['title'] = "Message Card"
    session['message'] = "Hello Message !"
    session['login'] = True

    try:
        if 'cUser' not in request.cookies:
            return redirect("/")

        collection = db.UserInfo
        dataInDB = collection.find_one({ "uuid": request.cookies.get('cUser') })

        session['title'] = "BALANCE"
        session['message'] = "YOUR ACCOUNT BALANCE IS RS. " + str(data_decrypt(dataInDB['balance']))
        session['login'] = False
        return redirect("/messageCard")
    except:
        if 'cUser' in request.cookies:
            return redirect("/dashboard")

        session['title'] = "404 ERROR"
        session['message'] = "404 ERROR. PAGE NOT FOUND !!!"
        session['login'] = False
        return redirect("/messageCard")

@app.route("/send", methods = ["GET", "POST"])
def send():
    session['title'] = "Message Card"
    session['message'] = "Hello Message !"
    session['login'] = True

    try:
        if 'cUser' not in request.cookies:
            return redirect("/")

        if request.method == "POST":
            account_number = request.form["account_number"]
            amount = request.form["amount"]
            amount = float(amount)

            collection = db.UserInfo

            dataInDB = collection.find_one({ "account_number": account_number })
            if dataInDB is not None:
                dataInDB = collection.find_one({ "uuid": request.cookies.get('cUser') })
                if amount < data_decrypt(dataInDB['balance']) and amount > 0:
                    ciphertext, nonce, tag = functional_encrypt(str(amount), master_key, function_key)
                    amount = float(functional_decrypt(ciphertext, master_key, function_key, nonce, tag))

                    private_key, public_key = generate_key_pair()
                    statement = str(amount)
                    commitment = generate_zero_knowledge_proof(private_key, statement)
                    is_valid_proof = verify_zero_knowledge_proof(public_key, statement, commitment)

                    if is_valid_proof:
                        dataInDB = collection.find_one({ "account_number": account_number })
                        q = { "account_number": account_number }
                        n = { "$set": { "balance": data_encrypt(data_decrypt(dataInDB['balance']) + amount) } }
                        collection.update_one(q, n)
                        
                        dataInDB = collection.find_one({ "uuid": request.cookies.get('cUser') })
                        q = { "uuid": request.cookies.get('cUser') }
                        n = { "$set": { "balance": data_encrypt(data_decrypt(dataInDB['balance']) - amount) } }
                        collection.update_one(q, n)

                        session['title'] = "TRANSACTION"
                        session['message'] = "TRANSACTION OF AMOUNT RS. " + str(amount) + " TO ACCOUNT NUMBER " + account_number + " DONE SUCCESSFULLY."
                        session['login'] = False
                        return redirect("/messageCard")
                    else:
                        session['title'] = "TRANSACTION"
                        session['message'] = "TRANSACTION OF AMOUNT RS. " + str(amount) + " TO ACCOUNT NUMBER " + account_number + " FAILED."
                        session['login'] = False
                        return redirect("/messageCard")
                else:
                    return render_template("send.html", amountMsg = "INSUFFICIENT BALANCE OR INVALID ENTRY !")
            else:
                return render_template("send.html", account_numberMsg = "INVALID ACCOUNT NUMBER !")
        else:
            return render_template('send.html')
        collection = db.UserInfo
        dataInDB = collection.find_one({ "uuid": request.cookies.get('cUser') })

        session['title'] = "BALANCE"
        session['message'] = "YOUR ACCOUNT BALANCE IS RS. " + str(dataInDB['balance'])
        session['login'] = False
        return redirect("/messageCard")
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
            return render_template("profile.html", name = dataInDB['name'], username = dataInDB['username'], email = dataInDB['email'])
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