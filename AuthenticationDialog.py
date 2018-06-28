# coding=utf-8
import inspect
import tkMessageBox
from TextInputFrame import *
from User import *


def show_authentication_error_box():
    tkMessageBox.showerror("Authentication", "Name or password is wrong!")


class AuthenticationDialog(Toplevel):

    def authentication(self):
        email = self.email_frame.get_content()
        password = self.pass_frame.get_content()
        if any_is_empty(email, password):
            show_authentication_error_box()
            return

        user = User.load(email)
        if user is None:
            show_authentication_error_box()

        if user.verify_password(password):
            self.arguments['user'] = user
            if self.cls is not None:
                if not inspect.isclass(self.cls):
                    self.arguments['password'] = password
                self.cls(self.arguments)
            self.withdraw()
        else:
            show_authentication_error_box()
            return

    def create_widgets(self):
        self.cancel_button.pack(side=RIGHT, padx=5, pady=5)
        self.save_button.pack(side=RIGHT)

    def __init__(self, cls=None, arguments=None, master=None):
        # init
        Toplevel.__init__(self, master)
        self.arguments = arguments
        if arguments is None:
            self.arguments = {}
        self.title("Authentication")
        self.geometry("300x150+600+300")
        self.cls = cls
        # setup entries
        self.email_frame = TextInputFrame("Email", self)
        self.pass_frame = TextInputFrame("Passphrase", self, '', '*')
        # setup buttons
        frame = ttk.Frame(self, relief=RAISED, borderwidth=1)
        frame.pack(fill=BOTH, expand=True)
        self.save_button = ttk.Button(frame, text="Authenticate", command=self.authentication)
        self.cancel_button = ttk.Button(frame, text="Cancel", command=self.withdraw)
        # design views
        self.create_widgets()
