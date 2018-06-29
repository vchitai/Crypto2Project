# coding=utf-8
from Crypto.Hash import SHA256

import User
from RegisterDialog import RegisterDialog


def register_new_user(self):
    print 'eel'
    name = None
    while name is None:
        name = raw_input("Nhap ho ten: ")
    bday = None
    while bday is None:
        bday = raw_input("Nhap ngay sinh: ")
    phone = None
    while phone is None:
        phone = raw_input("So dien thoai: ")
    address = None
    while address is None:
        address = raw_input("Nhap dia chi: ")
    user = User(name=name, bday=bday, phone=phone, address=address)

    key_length = 0
    while key_length == 0 or key_length % 64 != 0:
        key_length = int(raw_input("Nhap do dai khoa: "))
    user.generate_key(key_length)

    password = None
    while password is None:
        password = raw_input("Nhap password: ")
    user.hash_password(password)
    user.save()


def authentication_check():
    name = None
    while name is None:
        name = raw_input("Nhap ho ten: ")
    user = User.load(name)
    password = None
    while password is None:
        password = raw_input("Nhap password: ")
    if user.verify_password(password):
        return user
    return None


def edit_info(self):
    new = RegisterDialog()
    user = authentication_check()
    if user is not None:
        name = None
        while name is None:
            name = raw_input("Nhap ho ten: ")
        bday = None
        while bday is None:
            bday = raw_input("Nhap ngay sinh: ")
        phone = None
        while phone is None:
            phone = raw_input("So dien thoai: ")
        address = None
        while address is None:
            address = raw_input("Nhap dia chi: ")
        password = None
        while password is None:
            password = raw_input("Nhap password: ")
        user.hash_password(password)
        user.save()
    return user


def start_encrypt():
    name = None
    while name is None:
        name = raw_input("Nhap ho ten: ")
    user = User.load(name)
    if user is None:
        return False
    file_path = None
    while file_path is None:
        file_path = raw_input("Nhap duong dan file: ")
    alg = None
    while alg is None:
        alg = raw_input("Nhap thuat toan: ")
    user.start_encrypt(file_path, alg)


def start_decrypt():
    user = authentication_check()
    if user is not None:
        file_path = None
        while file_path is None:
            file_path = raw_input("Nhap duong dan file: ")
        alg = None
        while alg is None:
            alg = raw_input("Nhap thuat toan: ")
        user.decrypt(file_path, alg)
    return user


def start_sign():
    user = authentication_check()
    if user is not None:
        file_path = None
        while file_path is None:
            file_path = raw_input("Nhap duong dan file: ")
        user.sign(file_path)
    return user


def verify_sign():
    name = None
    while name is None:
        name = raw_input("Nhap ho ten: ")
    user = User.load(name)
    if user is not None:
        file_path = None
        while file_path is None:
            file_path = raw_input("Nhap duong dan file: ")
        with open(file_path, 'rb') as f:
            h = SHA256.new(f.read())
        print user.verify_sign(file_path + '.sig', h.hexdigest())
    return user
