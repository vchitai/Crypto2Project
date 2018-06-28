# coding=utf-8
import tkMessageBox
from User import *
from os import walk


def verify_sign(arguments):
    file_path = arguments['file_path']
    sig_file_path = arguments['sig_file_path']
    users = []
    for (dir_path, dir_names, file_names) in walk('user/'):
        user_ex = USER_EXTEND[1:]
        for file_name in file_names:
            file_name_c = file_name.split('.')
            if len(file_name_c) != 2:
                continue
            if file_name_c[1] == user_ex:
                users.append(User.load(file_name_c[0]))
        break
    for user in users:
        if user is not None and user.verify_sign(file_path, sig_file_path):
            tkMessageBox.showinfo("Success", "This file is signed by %s" % user.name)
            return True
    tkMessageBox.showinfo("Failed", "Cannot defined who signed this file")
