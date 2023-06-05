import logging
import os
import stat
from datetime import datetime

ruta_registro = '/registro/email/registro.log'
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

def reset(username, ip, url, method, user_agent, content_type,host,port):
    reset = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "authn_password_reset:" + username,
        "level": "INFO",
        "description": f"User {username} has successfully reset their password",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }
    logger.info(reset)


def reset_failed(username, ip, url, method, user_agent, content_type,host,port):
    failed_reset = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "authn_password_reset_fail:" + username,
        "level": "WARN",
        "description": f"User {username} failed to reset their password",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }
    logger.warning(failed_reset)

def reset_limit(username, ip, url, method, user_agent, content_type,host,port):
    registro_limit = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "authn_reset_max:" + username,
        "level": "WARN",
        "description": f"User: {username} reached the resest password fail limit",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type

    }
    logger.warning(registro_limit)

def f2code_fail(username, ip, url, method, user_agent, content_type,host,port):
    f2 = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "authn_code_failed:" + username,
        "level": "WARN",
        "description": f"User: {username} entered an incorrect login code",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type

    }
    logger.warning(f2)

def reset_caller(username,request):
    reset(username, request.remote_addr, request.url, request.method,
                              request.headers.get('User-Agent'), request.headers.get('Content-Type'), request.host,
                              request.host.split(":")[-1])
def resetfail_caller(username,request):
    reset_failed(username, request.remote_addr, request.url, request.method,
                              request.headers.get('User-Agent'), request.headers.get('Content-Type'), request.host,
                              request.host.split(":")[-1])

def resetlimit_caller(username,request):
    reset_limit(username, request.remote_addr, request.url, request.method,
                              request.headers.get('User-Agent'), request.headers.get('Content-Type'), request.host,
                              request.host.split(":")[-1])

def f2code_fail_caller(username,request):
    f2code_fail(username, request.remote_addr, request.url, request.method,
                              request.headers.get('User-Agent'), request.headers.get('Content-Type'), request.host,
                              request.host.split(":")[-1])