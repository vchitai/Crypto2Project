# coding=utf-8
import re
import time
from os import walk

USER_PATH = "user/"
USER_EXTEND = ".usr"
SIG_EXTEND = ".sig"
ENCRYPT_EXTEND = ".e"
DECRYPT_EXTEND = ".d"
NAME_REGEX = "[\w\d]{3,}"
PASSWORD_REGEX = "^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$"
PHONE_REGEX = "^[\d]{11}$|^[\d]{10}$|^[\d]{7}$"
ALG_OPTIONS = [
    "AES_MODE_CFB",
    "AES_MODE_EAX",
    "DES"
]


def get_user_list():
    user = []
    for (dir_path, dir_names, file_names) in walk('user/'):
        user_ex = USER_EXTEND[1:]
        for file_name in file_names:
            file_name_c = file_name.split('.')
            if len(file_name_c) != 2:
                continue
            if file_name_c[1] == user_ex:
                user.append(file_name_c[0])
        break
    return user


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
