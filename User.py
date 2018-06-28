# coding=utf-8
import binascii
import json
from base64 import b64encode, b64decode

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP, DES, ARC2, ARC4, ChaCha20, Salsa20
from Crypto.Hash import SHA256, SHAKE256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from pathlib import Path

from GlobalFunction import *


class User(object):
    def __init__(self, dictionary):
        self.email = None
        self.__dict__ = dictionary

    def summary(self):
        tmp = self.__dict__
        for key, value in tmp.iteritems():
            tmp[key] = b64encode(value).encode('utf-8')
        return json.dumps(tmp)

    def update(self, dictionary):
        self.__dict__.update(dictionary)

    def save(self):
        if Path(get_user_file_path(self.email)).is_file():
            return False
        with open(get_user_file_path(self.email), "w") as f:
            f.write(self.summary())
            return True

    def save_force(self):
        with open(get_user_file_path(self.email), "w") as f:
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
        cipher_aes = AES.new(binascii.hexlify(shake.read(16)), AES.MODE_EAX, self.private_nonce)
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
            public_key = self.get_public_key()
            cipher_rsa = PKCS1_OAEP.new(public_key)
            plain_text = fi.read()
            msg = {'alg': alg}
            if alg == ALG_OPTIONS[0]:
                secret_key = Random.get_random_bytes(16)
                cipher = AES.new(secret_key, AES.MODE_EAX)
                msg.update({'nonce': cipher.nonce})
            elif alg == ALG_OPTIONS[1]:
                secret_key = Random.get_random_bytes(16)
                cipher = AES.new(secret_key, AES.MODE_OCB)
                msg.update({'nonce': cipher.nonce})
            elif alg == ALG_OPTIONS[2]:
                secret_key = Random.get_random_bytes(16)
                iv = Random.new().read(AES.block_size)
                cipher = AES.new(secret_key, AES.MODE_CFB, iv)
                msg.update({'iv': iv})
            elif alg == ALG_OPTIONS[3]:
                secret_key = Random.get_random_bytes(16)
                cipher = AES.new(secret_key, AES.MODE_CTR)
                msg.update({'nonce': cipher.nonce})
            elif alg == ALG_OPTIONS[4]:
                secret_key = Random.get_random_bytes(8)
                cipher = DES.new(secret_key, DES.MODE_OFB)
                msg.update({'iv': cipher.iv})
            elif alg == ALG_OPTIONS[5]:
                secret_key = Random.get_random_bytes(16)
                cipher = ARC2.new(secret_key, ARC2.MODE_CFB)
                msg.update({'iv': cipher.iv})
            elif alg == ALG_OPTIONS[6]:
                secret_key = Random.get_random_bytes(40)
                cipher = ARC4.new(secret_key)
            elif alg == ALG_OPTIONS[7]:
                secret_key = Random.get_random_bytes(32)
                cipher = ChaCha20.new(key=secret_key)
                msg.update({'nonce': cipher.nonce})
            elif alg == ALG_OPTIONS[8]:
                secret_key = Random.get_random_bytes(32)
                cipher = Salsa20.new(key=secret_key)
                msg.update({'nonce': cipher.nonce})
            else:
                return False

            if alg in ALG_OPTIONS[0:1]:
                cipher_text, tag = cipher.encrypt_and_digest(plain_text)
            elif alg in ALG_OPTIONS[2:]:
                cipher_text = cipher.encrypt(plain_text)
                tag = SHA256.new(plain_text).hexdigest()
            else:
                return False
            print 'here'
            msg.update({'secret_key': cipher_rsa.encrypt(secret_key), 'cipher_text': cipher_text, 'tag': tag})
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
            try:
                # init cipher
                if msg['alg'] == ALG_OPTIONS[0]:
                    cipher = AES.new(secret_key, AES.MODE_EAX, msg['nonce'])
                elif msg['alg'] == ALG_OPTIONS[1]:
                    cipher = AES.new(secret_key, AES.MODE_OCB, msg['nonce'])
                elif msg['alg'] == ALG_OPTIONS[2]:
                    cipher = AES.new(secret_key, AES.MODE_CFB, msg['iv'])
                elif msg['alg'] == ALG_OPTIONS[3]:
                    cipher = AES.new(secret_key, AES.MODE_CTR, msg['nonce'])
                elif msg['alg'] == ALG_OPTIONS[4]:
                    cipher = DES.new(secret_key, DES.MODE_OFB, iv=msg['iv'])
                elif msg['alg'] == ALG_OPTIONS[5]:
                    cipher = ARC2.new(secret_key, ARC2.MODE_CFB)
                elif msg['alg'] == ALG_OPTIONS[6]:
                    cipher = ARC4.new(secret_key)
                elif msg['alg'] == ALG_OPTIONS[7]:
                    cipher = ChaCha20.new(key=secret_key, nonce=msg['nonce'])
                elif msg['alg'] == ALG_OPTIONS[8]:
                    cipher = Salsa20.new(key=secret_key, nonce=msg['nonce'])
                else:
                    return {'status': False, 'msg': "Cannot define the algorithm used to encrypt this file"}

                # decrypt and verify
                if msg['alg'] in ALG_OPTIONS[0:1]:
                    decrypted_msg = cipher.decrypt_and_verify(msg['cipher_text'], msg['tag'])
                elif msg['alg'] in ALG_OPTIONS[2:]:
                    decrypted_msg = cipher.decrypt(msg['cipher_text'])
                    SHA256.new(decrypted_msg).hexdigest(), msg['tag']
                    if SHA256.new(decrypted_msg).hexdigest() != msg['tag']:
                        raise ValueError
                else:
                    return {'status': False, 'msg': "Cannot define the algorithm used to encrypt this file"}
            except ValueError, KeyError:
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
    def load(email):
        if not Path(get_user_file_path(email)).is_file():
            return None
        with open(get_user_file_path(email), "r") as f:
            obj = json.loads(f.read())
            for key, value in obj.iteritems():
                obj[key] = b64decode(value)
        return User(obj)
