# coding=utf-8
import binascii
import json
from ast import literal_eval

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256, SHAKE256
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode
from pathlib import Path
from GlobalFunction import *


class User(object):
    def __init__(self, dictionary):
        self.__dict__ = dictionary

    def summary(self):
        tmp = self.__dict__
        for key, value in tmp.iteritems():
            tmp[key] = b64encode(value).encode('utf-8')
        return json.dumps(tmp)

    def save(self):
        if Path(get_user_file_path(self.name)).is_file():
            return False
        with open(get_user_file_path(self.name), "w") as f:
            f.write(self.summary())
            return True

    def generate_key(self, key_length, password):
        random_generator = Random.new().read
        key = RSA.generate(key_length, random_generator)
        shake = SHAKE256.new()
        shake.update(password)
        cipher_aes = AES.new(binascii.hexlify(shake.read(16)), AES.MODE_EAX)
        self.private_nonce = cipher_aes.nonce
        self.private_key, self.private_tag = cipher_aes.encrypt_and_digest(key.export_key('PEM'))
        self.public_key = key.publickey().export_key('PEM')

    def get_public_key(self):
        return RSA.import_key(self.public_key)

    def get_private_key(self, password):
        shake = SHAKE256.new()
        shake.update(password)
        cipher_aes = AES.new(binascii.hexlify(shake.read(16)), AES.MODE_EAX,self.private_nonce)
        try:
            private_key = cipher_aes.decrypt_and_verify(self.private_key, self.private_tag)
            return RSA.import_key(private_key)
        except ValueError:
            return None

    def hash_password(self, password):
        self.salt = Random.get_random_bytes(32)
        h = SHA256.new()
        h.update(str(password))
        h.update(str(self.salt))
        self.password = h.hexdigest()

    def verify_password(self, password):
        h = SHA256.new()
        h.update(str(password))
        h.update(str(self.salt))
        return self.password == h.hexdigest()

    def encrypt(self, file_path, alg):
        if alg not in ALG_OPTIONS:
            return False

        with open(file_path, 'rb') as fi, open(file_path + ENCRYPT_EXTEND, 'wb') as fo:
            secret_key = Random.get_random_bytes(16)
            public_key = self.get_public_key()
            cipher_rsa = PKCS1_OAEP.new(public_key)
            msg = {'alg': alg, 'secret_key': cipher_rsa.encrypt(secret_key)}
            if alg == ALG_OPTIONS[0]:
                iv = Random.new().read(AES.block_size)
                cipher_aes = AES.new(secret_key, AES.MODE_CFB, iv)
                cipher_text = cipher_aes.encrypt(fi.read())
                msg.update({'iv': iv, 'cipher_text': cipher_text})
            elif alg == ALG_OPTIONS[1]:
                cipher_aes = AES.new(secret_key, AES.MODE_EAX)
                cipher_text, tag = cipher_aes.encrypt_and_digest(fi.read())
                msg.update({'nonce': cipher_aes.nonce, 'tag': tag, 'cipher_text': cipher_text})
            for key, value in msg.iteritems():
                msg[key] = b64encode(value).encode('utf-8')
            fo.write(json.dumps(msg))
        return True

    def decrypt(self, file_path, password):
        private_key = self.get_private_key(password)
        if private_key is None:
            return {'status': False, 'msg': "Cannot get private key"}
        with open(file_path, 'rb') as fi, open(file_path + DECRYPT_EXTEND, 'wb') as fo:
            try:
                msg = json.loads(fi.read())
            except ValueError:
                return {'status': False, 'msg': "File structure is damaged"}
            for key, value in msg.iteritems():
                msg[key] = b64decode(value)
            secret_key = PKCS1_OAEP.new(private_key).decrypt(msg['secret_key'])
            decrypted_msg = ''
            if msg['alg'] == ALG_OPTIONS[0]:
                cipher_aes = AES.new(secret_key, AES.MODE_CFB, msg['iv'])
                try:
                    decrypted_msg = cipher_aes.decrypt(msg['cipher_text'])
                except ValueError:
                    return {'status': False, 'msg': "Decrypt failed, you are not the owner of this file"}
            elif msg['alg'] == ALG_OPTIONS[1]:
                cipher_aes = AES.new(secret_key, AES.MODE_EAX, msg['nonce'])
                try:
                    decrypted_msg = cipher_aes.decrypt_and_verify(msg['cipher_text'], msg['tag'])
                except ValueError:
                    return {'status': False, 'msg': "Decrypt failed, you are not the owner of this file"}
            fo.write(decrypted_msg)
            return {'status': True, 'msg': "Successfully decrypted file %s" % file_path}

    def sign(self, file_path, password):
        with open(file_path, 'rb') as fi, open(file_path + SIG_EXTEND, 'wb') as fo:
            key = self.get_private_key(password)
            h = SHA256.new(fi.read())
            fo.write(pss.new(key).sign(h))

    def verify_sign(self, file_path, sig_file_path):
        with open(file_path, 'rb') as f, open(sig_file_path, 'rb') as f_sig:
            key = RSA.import_key(self.public_key)
            h = SHA256.new(f.read())
            verifier = pss.new(key)
            try:
                verifier.verify(h, f_sig.read())
                return True
            except (ValueError, TypeError):
                return False

    @staticmethod
    def load(name):
        if not Path(get_user_file_path(name)).is_file():
            return None
        with open(get_user_file_path(name), "r") as f:
            obj = json.loads(f.read())
            for key, value in obj.iteritems():
                obj[key] = b64decode(value)
        return User(obj)
