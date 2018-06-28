# coding=utf-8
import tkFileDialog
import ttk
from Tkinter import *


class FileSelectFrame(ttk.Frame):
    def choose_file(self):
        self.file_chose = tkFileDialog.askopenfilename(parent=self.master)
        if self.file_chose != '':
            self.btn.config(text=self.file_chose)

    def get_content(self):
        if hasattr(self, 'file_chose'):
            return self.file_chose
        return ''

    def __init__(self, master=None):
        ttk.Frame.__init__(self, master)
        self.pack(fill=X)

        self.lb = ttk.Label(self, text='Select File', width=10)
        self.lb.pack(side=LEFT, padx=5, pady=5)

        self.btn = ttk.Button(self, text="Browse File", command=self.choose_file)
        self.btn.pack(fill=X, padx=5, expand=True)
