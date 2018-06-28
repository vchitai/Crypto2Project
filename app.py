# coding=utf-8
from CreateSignature import *
from Decryption import *
from EncryptDialog import *
from RegisterDialog import *
from EditorDialog import *
from AuthenticationDialog import *
from VerifySignature import *
import ttk


def start_register():
    RegisterDialog()


def start_editor():
    AuthenticationDialog(EditorDialog)


def start_encrypt():
    EncryptDialog()


def start_decrypt():
    file_path = tkFileDialog.askopenfilename()
    if file_path != '':
        AuthenticationDialog(decrypt, {'file_path': file_path})


def start_create_signature():
    file_path = tkFileDialog.askopenfilename()
    if file_path != '':
        AuthenticationDialog(create_signature, {'file_path': file_path})


def start_verify_signature():
    file_path = tkFileDialog.askopenfilename()
    if file_path == '':
        return
    sig_file_path = tkFileDialog.askopenfilename(title="Select signature file",
                                                 filetypes=(("signature files", "*.sig"), ("all files", "*.*")))
    if sig_file_path != '':
        verify_sign({'file_path': file_path, 'sig_file_path': sig_file_path})


class Application(ttk.Frame):

    def create_widgets(self):
        self.columnconfigure(0, pad=3, weight=1)
        self.columnconfigure(1, pad=3, weight=1)

        self.rowconfigure(0, pad=3, weight=1)
        self.rowconfigure(1, pad=3, weight=1)
        self.rowconfigure(2, pad=3, weight=1)

        self.register.grid(row=0, column=0, sticky=N + S + E + W, padx=3, pady=3)
        self.edit.grid(row=0, column=1, sticky=N + S + E + W, padx=3, pady=3)
        self.encrypt.grid(row=1, column=0, sticky=N + S + E + W, padx=3, pady=3)
        self.decrypt.grid(row=1, column=1, sticky=N + S + E + W, padx=3, pady=3)
        self.sign.grid(row=2, column=0, sticky=N + S + E + W, padx=3, pady=3)
        self.verify.grid(row=2, column=1, sticky=N + S + E + W, padx=3, pady=3)

    def __init__(self, master=None):
        # init
        ttk.Frame.__init__(self, master)
        self.pack(fill='both', expand=True)
        # setup ttk.Buttons
        self.verify = ttk.Button(self, text="Verify signature", command=start_verify_signature)
        self.sign = ttk.Button(self, text="Create signature", command=start_create_signature)
        self.decrypt = ttk.Button(self, text="Decrypt file", command=start_decrypt)
        self.encrypt = ttk.Button(self, text="Encrypt file", command=start_encrypt)
        self.edit = ttk.Button(self, text="Edit existing user", command=start_editor)
        self.register = ttk.Button(self, text="Register New User", command=start_register)
        # design
        self.create_widgets()


def main():
    root = Tk()
    root.geometry("300x300+500+200")
    root.title("Crypto Tool")
    root.style = ttk.Style()
    root.style.theme_use('clam')
    app = Application(master=root)
    app.mainloop()


if __name__ == '__main__':
    main()
