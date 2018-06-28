# coding=utf-8
import tkMessageBox


def decrypt(arguments):
    file_path = arguments['file_path']
    user = arguments['user']
    password = arguments['password']
    res = user.decrypt(file_path, password)
    if res['status']:
        tkMessageBox.showinfo("Success", res['msg'])
    else:
        tkMessageBox.showerror("Error", res['msg'])
