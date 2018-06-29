import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random

random_generator = Random.new().read
key = RSA.generate(1024, random_generator) #generate public and private keys

publickey = key.publickey # pub key export for exchange

with open("AS_KEY.pem", "w") as f:
    f.write(key.publickey().exportKey('PEM'))

with open("SS_KEY.pem", "w") as f:
    f.write(key.exportKey('PEM'))
