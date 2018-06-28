# coding=utf-8
import tkMessageBox


def create_signature(arguments):
    file_path = arguments['file_path']
    user = arguments['user']
    password = arguments['password']
    user.sign(file_path)
    tkMessageBox.showinfo("Success", "Successfully created signature on file %s" % file_path)
