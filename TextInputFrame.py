# coding=utf-8
import ttk
from Tkinter import *


class TextInputFrame(ttk.Frame):
    def get_content(self):
        return self.entry.get()
    
    def __init__(self, label, master=None, default_value='', show=''):
        ttk.Frame.__init__(self, master)
        self.pack(fill=BOTH, expand=True)
        
        self.lb = ttk.Label(self, text=label, width=10)
        self.lb.pack(side=LEFT, padx=5, pady=5)
        
        self.entry = ttk.Entry(self, show=show)
        self.entry.pack(fill=X, padx=5, expand=True)
        self.entry.insert(0, default_value)
