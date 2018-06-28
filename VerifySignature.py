# coding=utf-8
import tkMessageBox
from User import *
from os import walk


def verify_sign(arguments):
    file_path = arguments['file_path']
    sig_file_path = arguments['sig_file_path']
    users = get_user_list()
    for user in users:
        user = User.load(user)
        if user is not None and user.verify_sign(file_path, sig_file_path):
            tkMessageBox.showinfo("Success", "This file is signed by %s" % user.name)
            return True
    tkMessageBox.showinfo("Failed", "Cannot defined who signed this file")
