# coding=utf-8
import tkMessageBox

from DropListFrame import *
from FileSelectFrame import *
from GlobalFunction import *
from User import *


# print USER_OPTIONS


class EncryptDialog(Toplevel):
    def start_encrypt(self):
        file_path = self.file_frame.get_content()
        if file_path == '':
            tkMessageBox.showerror("Error", "Please choose a file", parent=self)
            return False
        alg = self.alg_frame.get_content()
        if alg == '':
            tkMessageBox.showerror("Error", "Please choose a algorithm", parent=self)
            return False
        receiver = self.receiver_frame.get_content()
        if receiver == '':
            tkMessageBox.showerror("Error", "Please choose a receiver", parent=self)
        user = User.load(receiver)
        if user is None:
            tkMessageBox.showerror("Error", "Receiver cannot be found", parent=self)
        if user.encrypt(file_path, alg):
            self.withdraw()
            tkMessageBox.showinfo("Success", "Successfully encrypted file %s" % file_path, parent=self)
        else:
            tkMessageBox.showerror("Error", "Encryption error", parent=self)

    def create_widgets(self):
        self.cancel_button.pack(side=RIGHT, padx=5, pady=5)
        self.save_button.pack(side=RIGHT)

    def __init__(self, master=None):
        # init
        Toplevel.__init__(self, master)
        self.title("Encrypt File")
        self.geometry("300x150+600+300")
        # setup entries
        self.file_frame = FileSelectFrame(self)
        self.alg_frame = DropListFrame("Algorithm", ALG_OPTIONS, self)
        self.receiver_frame = DropListFrame("Receiver", get_user_list(), self)
        # setup buttons
        frame = ttk.Frame(self, relief=RAISED, borderwidth=1)
        frame.pack(fill=BOTH, expand=True)
        self.save_button = ttk.Button(frame, text="Encrypt", command=self.start_encrypt)
        self.cancel_button = ttk.Button(frame, text="Cancel", command=self.withdraw)
        # design views
        self.create_widgets()
