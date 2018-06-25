from flask import Flask, request, jsonify, abort, url_for, g, session
from flask_session import Session

from flask_sqlalchemy import SQLAlchemy
#from flask_httpauth import HTTPBasicAuth
#from passlib.apps import custom_app_context as pwd_context
#from itsdangerous import (TimedJSONWebSignatureSerializer
#                          as Serializer, BadSignature, SignatureExpired)
#from database import *
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random
import json

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///certs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SESSION_TYPE = 'redis'
app.config.from_object(__name__)
Session(app)

db = SQLAlchemy(app)
#auth = HTTPBasicAuth()

class Certificate(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key = True)
    device_name = db.Column(db.String(32), index = True)
    public_key = db.Column(db.String(128))
    def __repr__(self):
        return '<Device %r>' % self.device_name
    def export_key(self):
        return RSA.importKey(self.public_key)
    def get_id(self):
        return self.id

@app.route("/")
def hello():
    return "Hello World!"

@app.route('/api/register_new_device', methods = ['POST'])
def register_new_device():
    device_name = request.json.get('device_name')
    public_key = request.json.get('public_key')
    if device_name is None or public_key is None:
        abort(400) # missing arguments
    if Certificate.query.filter_by(or_(device_name = device_name, public_key = public_key )).first() is not None:
        abort(400) # existing cert, pkey
    cert = Cert(device_name = device_name, public_key = public_key)
    m = jsonify({ 'device_id': cert.get_id() })
    h = SHA256.new()
    h.update(m)
    pkey = cert.export_key()
    c = pkey.encrypt(m)
    db.session.add(cert)
    db.session.commit()
    return jsonify({ 'c': c, 'h': h.hexdigest() }), 201

@app.route('/api/new_connection')
def new_connection():
    device_name = request.json.get('device_name')
    if device_name is None:
        abort(400) #missing arguments
    cert = Certificate.query.filter_by(device_name = device_name)
    if cert is None:
        abort(400) # not registered device

    #Return device_id and server_pub_key encrypted by Device PublicKey

    #use PublicKey to encrypt ServerPublicKey to reponse
    e = cert.export_key()
    server_public_key = app.config['PUBLIC_KEY'].exportKey()
    randomS = '{0:b}'.format(Random.getrandbits(128))
    Session['RandomS'] = randomS
    m = jsonify({'device_id': str(cert.get_id()),'public-key': server_public_key,'randomS': randomS})
    c = e.encrypt(m)
    
    #calculate hash
    h = SHA256.new()
    h.update(m)
    h = h.hexdigest()
    return jsonify({'c': c, 'h': h})

@app.route('/api/connection_verify', methods = ['POST'])
def connection_request():
    device_name = request.json.get('device_name')
    c_r = request.json.get('c')
    h_r = request.json.get('h')
    if device_name is None or c_r is None or h_r is None:
        abort(400)  # missing arguments

    cert = Certificate.query.filter_by(device_name = device_name)
    if cert is None:
        abort(400) # not registered device
    
    ds = app.config['PRIVATE_KEY']
    mc = ds.decrypt(c_r)
    h = SHA256.new()
    h.update(device_name+mc)
    if h.hexdigest() != hashAll:
        abort(400) # hash is different
    objc = json.loads(mc)
    randomC = objc['randomC']
    
    ess = app.config['PUBLIC_KEY_SS']
    random_generator = Random.new().read
    kuss = RSA.generate(1024, random_generator)

    body = jsonify({'randomC': '%s' % randomC,\
                    'publickeySS': '%s' % kuss.publickey().exportKey(), \
                    'connectIP': '192.168.1.x', \
                    'messageForSS' : "{'key':%s,'pkey':%s}" % (pkss.encrypt(kuss.exportKey()), cert.export_key().export_key())})

    ha = SHA256.new()
    ha.update(body)
    return jsonify({'message': cert.export_key().encrypt(body), 'hash': ha.hexdigest()})
    
if __name__ == '__main__':
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator) #generate public and private keys
    app.config['PUBLIC_KEY'] = key.publickey() # pub key export for exchange
    app.config['PRIVATE_KEY'] = key
    with open('AS_KEY.pem', 'r') as f:
        app.config['PUBLIC_KEY_SS'] = RSA.importKey(f.read())
    app.debug = True
    app.run(host = '0.0.0.0',port = 5000)
