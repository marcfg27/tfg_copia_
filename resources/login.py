import hashlib
import hmac
import logging
import secrets
import string
from functools import wraps
from LogManager import LoginLog
from flask import jsonify, make_response, current_app
from flask import request
from flask_limiter import Limiter, RateLimitExceeded
from flask_restful import Resource, reqparse
from markupsafe import escape
from unidecode import unidecode
from bleach import clean

from acces_control import generate_auth_token
from lock import lock
from models.accounts import AccountsModel

#logging.basicConfig(filename='failed_attempts.log', level=logging.INFO)
#failed_attempts = {}

# mostrar missatges per consola
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logging.getLogger('').addHandler(console_handler)


'''def get_remote_address():
    if request.headers.getlist("X-Forwarded-For"):
        ip_address = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip_address = request.remote_addr
    return ip_address
    
'''



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

limiter = Limiter(key_func=get_user,storage_uri="memory://", strategy="fixed-window-elastic-expiry")



def catch_exceptions(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except RateLimitExceeded as e:
            LoginLog.login_limit_caller(request.username, request)
            #logging.warning('Rate limit exceeded for username %s in address %s', request.username, request.remote_addr)
            return {'message': str(e)}, 429
        except Exception as e:
            logging.error('Unexpected error during login: %s', e)
            response = jsonify({"message": "An unexpected error occurred during login"})
            response.status_code = 500
            return response
    return wrapper


class Login(Resource):
    @catch_exceptions
    @limiter.limit("5/minute")
    def post(self):
        try:
            with lock.lock:
                parser = reqparse.RequestParser()
                parser.add_argument('username', type=str, required=True, help="This field cannot be left blanck")
                parser.add_argument('password', type=str, required=True, help="This field cannot be left blanck")
                data = parser.parse_args()
                username = escape(clean(data['username']))
                username = username.casefold()
                username = unidecode(username)
                password=data['password']
                acc = AccountsModel.get_by_username(username)
                if acc:
                    if(acc.verify_password(password)):
                        caracteres = string.ascii_letters + string.digits
                        contexto_usuario = ''.join(secrets.choice(caracteres) for i in range(20))

                        hash_contexto_usuario = hmac.new(current_app.secret_key.encode('utf-8'), contexto_usuario.encode('utf-8'),
                                                         hashlib.sha256).hexdigest()
                        t = 180
                        token = generate_auth_token(acc.id,hash_contexto_usuario,t)
                        response = jsonify({'message': 'Success'})
                        #response.headers['Authorization'] = f'Bearer {token}+{hash_contexto_usuario}'
                        response.headers['Authorization'] = f'Bearer {token}'
                        response.headers['Access-Control-Expose-Headers'] = 'Authorization'
                        response.set_cookie('ctx', contexto_usuario, samesite='Strict', secure=True, httponly=True,max_age=t)
                        LoginLog.registro_exitoso_caller(username,request)

                    else:
                        LoginLog.registro_contrasena_incorrecta_caller(username,request)
                       # logging.warning('Incorrect password for user %s from IP address: %s',
                        #             request.remote_addr, username)

                        response = jsonify({"message": "Login failed; Invalid user ID or password"})

                        #response = jsonify({"message": "Incorrect password for user [{}].".format(username)})
                        response.status_code = 400
                else:
                    LoginLog.registro_usuario_incorrecto_caller(username, request)
                    #logging.warning('Incorrect user:  %s from IP address: %s',
                     #               request.remote_addr, username)
                    #response = jsonify({"message": "Account with username [{}] doesen't exists.".format(username)})
                    response = jsonify({"message": "Login failed; Invalid user ID or password"})
                    response.status_code = 400

            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'

            return response
        except Exception as e:
            logging.error('Unexpected error during login: %s', e)
            response = jsonify({"message": "An unexpected error occurred during login"})
            response.status_code = 500
            return response



    def options(self):
        response = make_response()
        r = request
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response


