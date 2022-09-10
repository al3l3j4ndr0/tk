#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
from tkinter import ttk, Text
from tkinter import *
from cryptography.fernet import Fernet
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify
import base64


class asemetrica:
    def __init__(self, message=None,si=True):
        self.message = message
        self.si = si
    def llave(self):
        private_key = RSA.generate(1024)
        public_key = private_key.publickey()
        private_pem = private_key.export_key().decode()
        public_pem = public_key.export_key().decode()
        with open('private_pem.pem', 'w') as pr:
            pr.write(private_pem)
        with open('public_pem.pem', 'w') as pu:
            pu.write(public_pem)         
        pr_key = RSA.import_key(open('private_pem.pem', 'r').read())
        pu_key = RSA.import_key(open('public_pem.pem', 'r').read())
        cipher = PKCS1_OAEP.new(key=pu_key)

        if self.si:
            cipher = PKCS1_OAEP.new(key=pu_key)
            cipher_text = cipher.encrypt(bytes(self.message ,'utf-8'))
            decrypt = PKCS1_OAEP.new(key=pr_key)
            decrypted_message = decrypt.decrypt(cipher_text)
            return base64.b64encode(cipher_text).decode() #, decrypted_message.decode()
        else:
            return 'error' 


class simetrica:
    def __init__(self, mensaje,clave=None, decrypt=None, encrypt=None):
        self.clave = None
        self.mensaje = mensaje
        self.decrypt = decrypt
        self.encrypt = encrypt
    def secreto(self):
        if os.path.exists("clave.txt"):
          with open("clave.txt", "r") as clave:
              a = bytes(clave.read(), 'utf-8')
              f = Fernet(a)
              aa = bytes(self.mensaje, 'utf-8')
              if self.encrypt:
                  token = f.encrypt(aa)
                  return token.decode()
              if self.decrypt:
                  des = f.decrypt(aa)
                  return des.decode()
        else:
          clave = Fernet.generate_key()
          with open("clave.txt", "x") as archivo:
            archivo.write(clave.decode())
          f = Fernet(clave)
          a = bytes(self.mensaje, 'utf-8')
          token = f.encrypt(a)
          return token


def simetrica_asimetrica_click():
    try:
        _valor = str(entrada_texto_simetrico.get())
        tree.insert(
            '', 1, text= _valor ,values = (simetrica(mensaje=_valor,encrypt=True).secreto(),
                                           asemetrica(message=_valor).llave()))
    except ValueError:
        etiqueta.config(text="Introduce un frase!")

        
app = Tk()
app.title("Cifrado Asimétrico y Simétrico")
vp = Frame(app)
vp.grid(column=0, row=0, padx=(200,200), pady=(20,20))
vp.columnconfigure(0, weight=1)
vp.rowconfigure(0, weight=1)
etiqueta_uno = Label(vp, text="Introduce una Palabra o Frase")
etiqueta_uno.grid(column=3, row=1, sticky=(W,E))
boton_simetrico = Button(vp, text="Cifrar", command=simetrica_asimetrica_click)
boton_simetrico.grid(column=2, row=2)
valor_simetrico = ""
entrada_texto_simetrico = Entry(vp, width=30, textvariable=valor_simetrico)
entrada_texto_simetrico.grid(column=3, row=2)
tree = ttk.Treeview(height = 30, columns = ('#0','#1'))
tree.grid(row = 20, column = 0, columnspan = 1)
tree.heading('#0', text = 'Contraseña', anchor = CENTER)
tree.heading('#1', text = 'Cifrado simétrico', anchor = CENTER)
tree.heading('#2', text = 'Ciflrado asimétrico', anchor = CENTER)
app.mainloop()
