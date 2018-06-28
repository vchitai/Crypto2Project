# coding=utf-8
import re
import time
from os import walk
import tkMessageBox

USER_PATH = "user/"
USER_EXTEND = ".usr"
SIG_EXTEND = ".sig"
ENCRYPT_EXTEND = ".e"
DECRYPT_EXTEND = ".d"
NAME_REGEX = "[A-za-z\s]{3,}"
PASSWORD_REGEX = "^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$"
EMAIL_REGEX = "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
PHONE_REGEX = "^[\d]{11}$|^[\d]{10}$|^[\d]{7}$"
ALG_OPTIONS = [
    "AES_MODE_EAX (Block Cipher)",
    "AES_MODE_OCB (Block Cipher)",
    "AES_MODE_CFB (Block Cipher)",
    "AES_MODE_CTR (Block Cipher)",
    "Single DES (Block Cipher)",
    "RC2 (Block Cipher)",
    "ARC4 (Stream Cipher)",
    "ChaCha20 (Stream Cipher)",
    "Salsa20 (Stream Cipher)"
]


def get_user_list():
    users = []
    for (dir_path, dir_names, file_names) in walk('user/'):
        user_ex = USER_EXTEND[1:]
        for file_name in file_names:
            file_name_c = file_name.rsplit('.',1)
            if len(file_name_c) != 2:
                continue
            if file_name_c[1] == user_ex:
                users.append(file_name_c[0])
        break
    return users


def is_valid_email(email):
    return re.compile(EMAIL_REGEX).match(email)


def is_valid_name(name):
    return re.compile(NAME_REGEX).match(name)


def is_valid_password(password):
    return re.compile(PASSWORD_REGEX).match(password)


def is_valid_phone(phone):
    return re.compile(PHONE_REGEX).match(phone)


def is_valid_date(date):
    try:
        time.strptime(date, '%d/%m/%Y')
        return True
    except ValueError:
        return False


def any_is_none(*args):
    if any(arg is None for arg in args):
        return True
    return False


def any_is_empty(*args):
    if any(arg == '' for arg in args):
        return True
    return False


def get_user_file_path(name):
    return USER_PATH + name + USER_EXTEND


def start_about_us():
    tkMessageBox.showinfo("Team Information", "1. 1512387 - Đỗ Thành Nhơn \n2. 1512474 - Vòng Chí Tài \n")