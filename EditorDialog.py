# coding=utf-8
import tkMessageBox
from TextInputFrame import *
from User import *
from GlobalFunction import *


class EditorDialog(Toplevel):
    def save_user(self):
        name = self.name_frame.get_content()
        if not is_valid_name(name):
            tkMessageBox.showerror("Error", "Name is not valid, only accept character and number", parent=self)
            return False
        password = self.pass_frame.get_content()
        if password != "Insert if want to change" and not is_valid_password(password):
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

        user = User({'name': name, 'birthday': birthday, 'phone': phone, 'address': address})
        if password != "Insert if want to change":
            user.hash_password(password)
        user.save()
        tkMessageBox.showinfo("Success", "Successfully edited user %s" % name, parent=self)

    def create_widgets(self):
        self.cancel_button.pack(side=RIGHT, padx=5, pady=5)
        self.save_button.pack(side=RIGHT)

    def __init__(self, arguments=None, master=None):
        # init
        Toplevel.__init__(self, master)
        self.title("Edit user information")
        self.geometry("300x300+300+300")
        # setup entries
        self.user = arguments['user']
        self.name_frame = TextInputFrame("Name", self, self.user.name)
        self.pass_frame = TextInputFrame("Passphrase", self, "Insert if want to change", '*')
        self.birthday_frame = TextInputFrame("Birthday", self, self.user.birthday)
        self.phone_frame = TextInputFrame("Phone", self, self.user.phone)
        self.address_frame = TextInputFrame("Address", self, self.user.address)
        # setup buttons
        frame = ttk.Frame(self, relief=RAISED, borderwidth=1)
        frame.pack(fill=BOTH, expand=True)
        self.cancel_button = ttk.Button(frame, text="Cancel", command=self.withdraw)
        self.save_button = ttk.Button(frame, text="Save", command=self.save_user)
        # design views
        self.create_widgets()
