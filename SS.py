from flask import Flask, request, jsonify, abort, url_for, g, session
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
#from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
#from database import *
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
from flask_session import Session
import json
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

app = Flask(__name__)

app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dg'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///devices.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


SESSION_TYPE = 'redis'
app.config.from_object(__name__)
Session(app)

db = SQLAlchemy(app)
auth = HTTPBasicAuth()
class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key = True)
    device_name = db.Column(db.String(32), index = True)
    messages = relationship("Message")
    
    def generate_auth_token(self, expiration = 3600):
        s = Serializer(app.config['SECRET_KEY'], expires_in = expiration)
        return s.dumps({ 'id': self.id })
    
    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None # valid token, but expired
        except BadSignature:
            return None # invalid token
        device = Device.query.get(data['id'])
        return device
    
    def __repr__(self):
        return '<Device %r>' % self.device_name
    
class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key = True)
    message_content = db.Column(db.Text())
    device_id = Column(Integer, ForeignKey('device.id'))
    def __repr__(self):
        return '<Message %r>' % self.id

@app.route("/")
def hello():
    return "Hello World!"

@app.route('/api/new_connection', methods = ['POST'])
def new_connection():
    message = request.json.get('messageForSS')
    c = request.json.get('c')
    h = request.json.get('h')
    if c is None:
        abort(400)
    key = app.config['PRIVATE_KEY_SS']
    k2 = key.decrypt(message)
    if k2 is None:
        abort(400)
    k = RSA.importKey(k2['key'])
    pkey = RSA.importKey(k2['pkey'])
    m = k.decrypt(c)
    hc = SHA256.new()
    hc.update(m)
    if hc.hexdigest()!=h:
        abort(400)
    obj = json.loads(m)
    session['AES_KEY'] = obj['AESkey']

    device = Device.query.filter_by(device_name = obj['device_name']).first()
    if device is None:
        device = Device(device_name = obj['device_name'])
    db.session.add(device)
    db.session.commit()
    device = Device.query.filter_by(device_name = obj['device_name']).first()
    token = device.generate_auth_token()

    responseM = jsonify({'AESkey': session['AES_KEY'], 'token': token})
    responseC = pkey.encrypt(responseM)
    h = SHA256.new()
    h.update(responseM)
    return jsonify({'encrypted': responseC, 'hash': h.hexdigest()})
    
@auth.verify_password
def verify_password(token, random_text):
    device = Device.verify_auth_token(token)
    if not device:
        return False
    g.device = device
    return True

@app.route('/api/store_message', methods = ['POST'])
@auth.login_required
def store_message():
    iv = request.json.get('iv')
    request_hash_value = request.json.get('h')
    key = session['AES_KEY']
    message_content_plain_text = AES.new(key, AES.MODE_CFB, iv)

    hash_check = SHA256.new()
    hash_check.update(message_content_plain_text)
    if hash_check.hexdigest() != request_hash_value:
        abort(400)
    message = Message(device_id = g.device.id, message_content = message_content_plain_text)
    db.session.add(message)
    db.session.commit()
    return jsonify({confirm: "success"});

if __name__ == '__main__':
    with open('SS_KEY.pem', 'r') as f:
        app.config['PRIVATE_KEY_SS'] = RSA.importKey(f.read())
    app.debug = True
    app.run(host = '0.0.0.0',port = 5555)
