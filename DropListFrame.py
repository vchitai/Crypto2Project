# coding=utf-8
import ttk
from Tkinter import *


class DropListFrame(ttk.Frame):
    def get_content(self):
        return self.var.get()

    def __init__(self, label, l, master=None):
        ttk.Frame.__init__(self, master)
        self.pack(fill=X)

        self.lb = ttk.Label(self, text=label, width=10)
        self.lb.pack(side=LEFT, padx=5, pady=5)

        self.var = StringVar(master)
        if len(l) == 0 or l[0] != '':
            l.insert(0, '')
        self.var.set(l[0])  # default value

        self.dl = ttk.OptionMenu(self, self.var, *l)
        self.dl.pack(fill=X, padx=5, expand=True)
        # self.dl.pack()
