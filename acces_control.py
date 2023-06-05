import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from functools import wraps


import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import g, current_app, redirect, url_for, abort, jsonify
from flask_httpauth import HTTPTokenAuth
from flask_mail import Mail, Message
from jwt import encode, decode, ExpiredSignatureError, InvalidSignatureError
from LogManager import tokenLog

from datab import db
from models.Function import Function
from models.accounts import AccountsModel

auth = HTTPTokenAuth(scheme="Bearer")
mail = Mail()




def generate_auth_token(id, contexto, expiration=6000):

    if(expiration==180):
        secret1 = current_app.secret_key
        secret2 = current_app.config['SECRET_KEY2']
    else:
        secret1 = current_app.config['SECRET_KEY2']
        secret2 = current_app.secret_key

    token = encode(
        {"id": id,
         "exp": int(time.time()) + expiration,
         "hash_contexto_usuario": contexto},
        secret1,
        algorithm="HS256"
    )
    token_b = json.dumps(token).encode("utf-8")

    aesgcm = AESGCM(str.encode(secret2))

    nonce = secrets.token_bytes(12)

    ciphertext = aesgcm.encrypt(nonce, token_b, None)

    token_bytes = nonce + ciphertext
    token = token_bytes.hex()

    return token


from models.revokedTokens import  RevokedToken
def verify_auth_token(token,ContextoUsuario,bool):
        try:
            a = request
            data = decode_auth_token(token,bool)

        except ExpiredSignatureError:
            tokenLog.token_expired_caller(request)
            return None  # expired token
        except InvalidSignatureError:
            tokenLog.invalid_token_caller(request)
            return None  # invalid token
        except Exception:
            tokenLog.invalid_token_caller(request)
            return None  # bad token (e.g. DecodeError)
        user = AccountsModel.get_by_id(data["id"])
        if data['hash_contexto_usuario'] == hmac.new(current_app.secret_key.encode('utf-8'), ContextoUsuario.encode('utf-8'), hashlib.sha256).hexdigest():
            '''if (a.endpoint == 'closes'):
                token = RevokedToken(data['hash_contexto_usuario'], data['exp'])
                token.save_to_db()
            else:
                token = RevokedToken.get_by_context(data['hash_contexto_usuario'])
                if(token):
                    return None'''
            return user
        tokenLog.invalid_user_context_caller(request,user.username)
        return None








def decode_auth_token(token,bool):
    try:
        token_bytes = bytes.fromhex(token)
        nonce = token_bytes[:12]
        ciphertext = token_bytes[12:]

        # Decrypt payload using AES-GCM
        if(bool):
            secret1= current_app.config['SECRET_KEY2']
            secret2 = current_app.secret_key
        else:
            secret2= current_app.config['SECRET_KEY2']
            secret1 = current_app.secret_key
        k = str.encode(secret1)
        aesgcm = AESGCM(k)
        token_b = aesgcm.decrypt(nonce, ciphertext, None)

        token = json.loads(token_b.decode("utf-8"))
        data = decode(token, secret2, algorithms=["HS256"])

        return data
    except:
        raise
from flask import request

@auth.verify_token
def verify_token(token):
    try:
        a = request
        ctx = request.cookies.get('ctx')
        endpoint = request.endpoint
        if(ctx):
            if(token):
                account = verify_auth_token(token,ctx,endpoint=='email')
                if account is not None:
                    g.user = account
                    return account
                else:
                    #return None
                    raise ValueError("token-fail")
            else:
                tokenLog.missing_token_caller(request)
               # return None
                raise ValueError("token-fail")

        else:
            tokenLog.missing_user_context_caller(request)
            #return None

            raise ValueError("token-fail")

    except Exception as e:
        raise




@auth.get_user_roles
def get_user_roles(user):
    roles = ["user"]
    if user.is_admin:
        roles.append("admin")
    return roles





def user_has_access(user, endpoint,method):
    function = Function.get_function_by_name(method+endpoint)
    boolean =  function in user.functions
    return boolean


def assign_function_to_username(username, function):
    user = AccountsModel.get_by_username(username)
    function = Function.get_function_by_name(function)
    if user and function:
        user.functions.append(function)
        db.session.commit()
        return True
    return False

def assign_function_to_user(user, function):
    function = Function.get_function_by_name(function)
    if user and function:
        user.functions.append(function)
        db.session.commit()
        return True
    return False


from functools import wraps
from flask import request


def require_access(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        endpoint= request.endpoint
        method = request.method
        path = request.path

        if is_public_resource(endpoint, method,path):
            # El recurso es público, no se requiere autenticación ni verificación de acceso
            return view_func(*args, **kwargs)
        try:
            @auth.login_required
            def inner_wrapper():
                if not user_has_access(g.user, endpoint, method):
                    raise ValueError("token-fail")
                return view_func(*args, **kwargs)

            return inner_wrapper()
        except Exception as e:
            if str(e) != "token-fail":
                tokenLog.AuthorizationException_caller(request, str(e))
            if(method == 'GET' and endpoint == 'inside'):
                return redirect('/')
            else:
                return jsonify({'error': 'Token ha fallado'}), 401

    return wrapper

def is_public_resource(endpoint,method,path):
    # Lista de rutas públicas
    public_routes = ['GETrender_vue', 'GETstatic','POSTlogin','POSTemail2','POSTemail3','POSTaccounts']
    st = method+str(endpoint)
    boolean = st in public_routes
    if(not endpoint):
        boolean = (method+path == 'GET/favicon.ico')
    return boolean
