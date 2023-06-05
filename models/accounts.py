import hashlib
import hmac
import json
import os
import time
import uuid
from functools import wraps

import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import g, current_app
from flask_httpauth import HTTPTokenAuth
from flask_mail import Mail, Message
from jwt import ExpiredSignatureError, InvalidSignatureError
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy import UniqueConstraint

from LogManager import tokenLog

from datab import db
from models.Function import Function

auth = HTTPTokenAuth(scheme="Bearer")
mail = Mail()



user_function = db.Table(
    'user_function',
    db.Column('user_id', db.Integer, db.ForeignKey('accounts.id')),
    db.Column('function_id', db.Integer, db.ForeignKey('functions.id')),
    UniqueConstraint('user_id', 'function_id', name='uq_user_function')
)

class AccountsModel(db.Model):

    __tablename__ = 'accounts'
    username = db.Column(db.String(30), unique=True, nullable=False)
    id = db.Column('id',db.Text(length=36),default=lambda: str(uuid.uuid4()),primary_key=True)
    password = db.Column(db.String(65), nullable=False)
    # 0 not admin/ 1 is admin
    is_admin = db.Column(db.Integer, nullable=False)
    available_money = db.Column(db.Integer)
    email = db.Column(db.String(30), nullable=False)
    code = db.Column(db.String(8))
    posts = db.relationship("PostsModel", back_populates="account", cascade="all, delete-orphan")
    functions = db.relationship('Function', secondary=user_function, backref=db.backref('users', lazy='dynamic'))



    def __init__(self, username,email, available_money=200, is_admin=0):
        self.username = username
        self.available_money = available_money
        self.is_admin = is_admin
        self.email = email
    def json(self):
        return{'username': self.username, 'email':self.email,'is_admin': self.is_admin, 'available_money': self.available_money}

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()
    @classmethod
    def get_by_username(cls, username):
        return AccountsModel.query.filter_by(username = username).first()

    @classmethod
    def get_by_id(cls, id):
        return AccountsModel.query.filter_by(id = id).first()

    @classmethod
    def get_money(cls, username):
        account = cls.query.filter_by(username=username).first()
        if account:
            return account.available_money
        else:
            return None

    def assign_basic_functions(self):
        f = self.functions


        f.append(Function.get_function_by_name('GETaccounts'))
        f.append(Function.get_function_by_name('GETmoney'))
        f.append(Function.get_function_by_name('GETposts'))
        f.append(Function.get_function_by_name('GETinside'))
        f.append(Function.get_function_by_name('DELETEposts'))
        f.append(Function.get_function_by_name('POSTxml_http'))
        f.append(Function.get_function_by_name('POSTemail'))
        f.append(Function.get_function_by_name('GETemail'))
        f.append(Function.get_function_by_name('POSTposts'))



    def generar_codigo(self,t):
        codigo_verificacion = pyotp.random_base32()
        self.code = codigo_verificacion
        self.save_to_db()
        totp = pyotp.TOTP(codigo_verificacion, interval=t)
        codigo = totp.now()
        return codigo
    def enviar_codigo_verificacion(self,intervalo=180):
        destinatario = self.email
        codigo= self.generar_codigo(intervalo)
        if(intervalo==180):
            mensaje = Message('Verification code', sender='tu_correo@gmail.com', recipients=[destinatario])
            mensaje.body = f'Your verification code is: {codigo}'
        else:
            mensaje = Message('Reset code', sender='tu_correo@gmail.com', recipients=[destinatario])
            mensaje.body = f'Your password reset code is: {codigo}'
       # mail.send(mensaje)

        return intervalo

    def rollback(self):
        db.session.rollback()

    def hash_password(self, password):
        self.password = pwd_context.hash(password)


    def verify_password(self, password):
        return pwd_context.verify(password, self.password)











