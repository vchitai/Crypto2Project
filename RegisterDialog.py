# coding=utf-8
import tkMessageBox

from TextInputFrame import *
from User import *
from GlobalFunction import *


class RegisterDialog(Toplevel):
    def save_user(self):
        name = self.name_frame.get_content()
        if not is_valid_name(name):
            tkMessageBox.showerror("Error", "Name is not valid, only accept character and number", parent=self)
            return False
        password = self.pass_frame.get_content()
        if not is_valid_password(password):
            tkMessageBox.showerror("Error",
                                   "Password must have at least 6 character with at least 1 letter and 1 digit",
                                   parent=self)
            return False
        birthday = self.birthday_frame.get_content()
        if birthday != '' and not is_valid_date(birthday):
            tkMessageBox.showerror("Error", "Birthday is not a valid date format(dd/mm/YYYY)", parent=self)
            return False
        phone = self.phone_frame.get_content()
        if phone != '' and not is_valid_phone(phone):
            tkMessageBox.showerror("Error", "Phone number must have 7,10 or 11 digits", parent=self)
            return False
        address = self.address_frame.get_content()
        key_length = self.key_length_frame.get_content()
        if key_length == '' or not key_length.isdigit():
            tkMessageBox.showerror("Error", "RSA modulus length must be a multiple of 256 and >= 1024", parent=self)
            return False
        key_length = int(key_length)
        if key_length < 1024 or key_length % 256 != 0:
            tkMessageBox.showerror("Error", "RSA modulus length must be a multiple of 256 and >= 1024", parent=self)
            return False
        user = User({'name': name, 'birthday': birthday, 'phone': phone, 'address': address})
        user.generate_key(key_length, password)
        user.hash_password(password)
        if user.save():
            self.withdraw()
            tkMessageBox.showinfo("Success", "Successfully created user %s" % name, parent=self)
        else:
            tkMessageBox.showerror("Error", "This user is existing", parent=self)

    def create_widgets(self):

        self.cancel_button.pack(side=RIGHT, padx=5, pady=5)
        self.save_button.pack(side=RIGHT)

    def __init__(self, master=None):
        # init
        Toplevel.__init__(self, master)
        self.title("Register New User")
        self.geometry("300x300+600+300")
        # setup entries
        self.name_frame = TextInputFrame("Name", self)
        self.address_frame = TextInputFrame("Address", self)
        self.phone_frame = TextInputFrame("Phone", self)
        self.birthday_frame = TextInputFrame("Birthday", self)
        self.key_length_frame = TextInputFrame("Key length", self)
        self.pass_frame = TextInputFrame("Passphrase", self, '', '*')
        # setup buttons
        frame = ttk.Frame(self, relief=RAISED, borderwidth=1)
        frame.pack(fill=BOTH, expand=True)
        self.save_button = ttk.Button(frame, text="Save", command=self.save_user)
        self.cancel_button = ttk.Button(frame, text="Cancel", command=self.withdraw)
        # design views
        self.create_widgets()
