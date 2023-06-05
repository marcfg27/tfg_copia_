import hashlib
import hmac
import re
import secrets
import string
from functools import wraps
from bleach import clean

import pyotp
from flask import g, current_app
from flask import request, jsonify, make_response
from flask_limiter import Limiter, RateLimitExceeded
from flask_restful import Resource, reqparse
from markupsafe import escape
from unidecode import unidecode

from acces_control import generate_auth_token
from lock import lock
from models.accounts import AccountsModel, auth, mail
from LogManager import EmailLog,validation





def verify_verification_code(secret, code,interv=180):
    totp = pyotp.TOTP(secret,interval=interv)
    return totp.verify(code)

class eMail(Resource):
   # @require_access('p_email')
    def post(self):
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('code', type=str, required=True, help="This field cannot be left blanck")
            data = parser.parse_args()
            code = data['code']

            valid_code = re.match(r'^[a-zA-Z0-9]+$', data['code'])
            if not valid_code:
                validation.input_validation_fail_code_caller(g.user,data['code'],request)
                return {'message': 'Invalid Code. Only alphanumeric characters are allowed.'}, 400
            if g.user is not None and True: # verify_verification_code(g.user.code, code):
                g.user.code = None
                g.user.save_to_db()
                username = g.user.username
                acc = AccountsModel.get_by_username(username)
                caracteres = string.ascii_letters + string.digits
                contexto_usuario = ''.join(secrets.choice(caracteres) for i in range(20))

                hash_contexto_usuario =  hmac.new(current_app.secret_key.encode('utf-8'), contexto_usuario.encode('utf-8'), hashlib.sha256).hexdigest()

                token = generate_auth_token(acc.id,hash_contexto_usuario)

                response = jsonify({'correct': True, 'id': username})
                response.headers['Authorization'] = f'Bearer {token}'
                response.headers['Access-Control-Expose-Headers'] = 'Authorization'
                response.headers['Access-Control-Allow-Credentials'] = 'true'
                response.set_cookie('ctx', contexto_usuario, samesite='Strict', secure=True, httponly=True, max_age=6000)
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                response.headers['Pragma'] = 'no-cache'
                return response
            else:
                response = jsonify({'correct': False})
                EmailLog.f2code_fail_caller(g.user,request)
                response.headers['Access-Control-Allow-Credentials'] = 'true'
                return response
        except Exception as e:
            response = jsonify({'message': "Error: " + str(e)}, 409)
            response.status_code = 409
            return response

   # @require_access('g_email')
    def get(self):
        r =request
        with lock.lock:
            if g.user is None:
                return {'message': "Invalid token: " + g.auth_error}, 401
            try:
                    email=g.user.email
                    email_parts = email.split("@")
                    email_username = email_parts[0]
                    email_domain = email_parts[1]
                    username_length = len(email_username)
                    censored_username = email_username[:int(username_length / 3)] + "*" * (
                            username_length - int(username_length / 2))
                    domain_parts = email_domain.split(".")
                    domain_length = len(domain_parts[0])
                    censored_domain = domain_parts[0][:int(domain_length / 2)] + "*" * (
                            domain_length - int(domain_length / 2)) + "." + domain_parts[1]
                    censored_email = censored_username + "@" + censored_domain
                    interv = g.user.enviar_codigo_verificacion()
                    response = jsonify({'email': censored_email,'intervalo': interv})
                    response.status_code = 200
                    response.headers['Access-Control-Allow-Credentials'] = 'true'
                    return response
            except Exception as e:
                response = jsonify({'message': "Error: " + str(e)}, 409)
                response.status_code = 409
                return response

    def options(self):
        r = request
        response = make_response()
       # response.headers['Access-Control-Allow-Credentials'] = 'http://127.0.0.1:5000'
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST,GET')
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response





def get_user():
    try:
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help="This field cannot be left blanck")
        data = parser.parse_args()
        username = data['username']

        if username:
            request.username = username
            return username
        else:
            return None
    except:
        return None

limiter2 = Limiter(key_func=get_user,storage_uri="memory://", strategy="fixed-window-elastic-expiry")

def catch_exceptions(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except RateLimitExceeded as e:
            EmailLog.resetlimit_caller(request.username,request)
            return {'message': str(e)}, 429
    return wrapper

class eMail2(Resource):
    @catch_exceptions
    @limiter2.limit("5/minute")
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help="This field cannot be left blanck")
        data = parser.parse_args()
        username = escape(clean(data['username']))
        username = username.casefold()
        username = unidecode(username)
        user = AccountsModel.get_by_username(username)
        with lock.lock:
            if user is None:
                response = jsonify({'intervalo': 500})
                response.status_code = 200
                response.headers['Access-Control-Allow-Credentials'] = 'true'
                return response
            try:
                interv = user.enviar_codigo_verificacion(500)
                response = jsonify({'intervalo': interv})
                response.status_code = 200
                response.headers['Access-Control-Allow-Credentials'] = 'true'
                return response
            except Exception as e:
                response = jsonify({'message': "Error: " + str(e)}, 409)
                response.status_code = 409
                return response


class eMail3(Resource):
    def post(self):
        try:
            with lock.lock:
                parser = reqparse.RequestParser()
                parser.add_argument('username', type=str, required=True, help="This field cannot be left blanck")
                parser.add_argument('code', type=str, required=True, help="This field cannot be left blanck")
                parser.add_argument('password', type=str, required=True, help="This field cannot be left blanck")
                data = parser.parse_args()
                code = data['code']
                newPas = data['password']
                username = data['username']
                username = escape(clean(data['username']))
                username = username.casefold()
                username = unidecode(username)
                user = AccountsModel.get_by_username(username)


                valid_code = re.match(r'^[a-zA-Z0-9]+$', data['code'])
                if not valid_code:
                    EmailLog.resetfail_caller(username,request.remote_addr)
                    return {'message': 'Invalid Code. Only alphanumeric characters are allowed.'}, 400

                if user is not None and verify_verification_code(user.code, code,500):
                    user.code = None
                    user.save_to_db()
                    user.hash_password(data['password'])
                    user.save_to_db()
                    response = jsonify({'message': 'password changed'})
                    EmailLog.reset_caller(username,request.remote_addr)
                    return response
                else:
                    EmailLog.resetfail_caller(username,request.remote_addr)
                    response = jsonify({'message': 'Error code not valid'})
                    # response.headers['Access-Control-Expose-Headers'] = 'Authorization'
                    response.headers['Access-Control-Allow-Credentials'] = 'true'
                    response.status_code = 401

                    return response
        except Exception as e:
            response = jsonify({'message': "Error: " + str(e)}, 409)
            response.status_code = 409
            return response