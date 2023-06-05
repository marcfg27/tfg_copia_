import logging
import os
import stat
from datetime import datetime

ruta_registro = '/registro/login/registro.log'
permisos_directorio = stat.S_IRWXU | stat.S_IRWXG | stat.S_IROTH | stat.S_IXOTH  # 0755
permisos_archivo = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH  # 0644

directorio = os.path.dirname(ruta_registro)


if not os.path.exists(directorio):
    os.makedirs(directorio, permisos_directorio)

logger = logging.getLogger('registro')
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler(ruta_registro)
file_handler.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)



def registro_exitoso(username, ip, url, method, user_agent, content_type,host,port):
    registro_exitoso = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "authn_login_success:" + username,
        "level": "INFO",
        "description": f"User {username} login successfully",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }

    logger.info(registro_exitoso)

def registro_contrasena_incorrecta(username, ip, url, method, user_agent, content_type,host,port):
    registro_contrasena_incorrecta = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "authn_login_failure_pass:" + username,
        "level": "WARNING",
        "description": f"Incorrect password for user {username}",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type    }

    logger.warning(registro_contrasena_incorrecta)

def registro_usuario_incorrecto(username, ip, url, method, user_agent, content_type,host,port):
    registro_usuario_incorrecto = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "authn_login_failure_user:" + username,
        "level": "WARN",
        "description": f"Incorrect user: {username}",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }

    logger.warning(registro_usuario_incorrecto)

def login_limit(username, ip, url, method, user_agent, content_type,host,port):
    registro_limit = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "authn_login_fail_max:" + username,
        "level": "WARN",
        "description": f"User: {username} reached the login fail limit",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type

    }
    logger.warning(registro_limit)


def registro_exitoso_caller(username,request):
    registro_exitoso(username, request.remote_addr, request.url, request.method,
                              request.headers.get('User-Agent'), request.headers.get('Content-Type'), request.host,
                              request.host.split(":")[-1])


def registro_contrasena_incorrecta_caller(username,request):
    registro_contrasena_incorrecta(username, request.remote_addr, request.url, request.method,
                              request.headers.get('User-Agent'), request.headers.get('Content-Type'), request.host,
                              request.host.split(":")[-1])


def registro_usuario_incorrecto_caller(username,request):
    registro_usuario_incorrecto(username, request.remote_addr, request.url, request.method,
                              request.headers.get('User-Agent'), request.headers.get('Content-Type'), request.host,
                              request.host.split(":")[-1])

def login_limit_caller(username,request):
    login_limit(username, request.remote_addr, request.url, request.method,
                              request.headers.get('User-Agent'), request.headers.get('Content-Type'), request.host,
                              request.host.split(":")[-1])