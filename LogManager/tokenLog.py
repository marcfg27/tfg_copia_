import logging
import os
import stat
from datetime import datetime

ruta_registro = '/registro/token/registro.log'
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

def token_expired(ip, url, method, user_agent, content_type, host, port):
    token_expired = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "authn_token_expired:" + ip,
        "level": "WARNING",
        "description": f"The token for ip {ip} has expired",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }
    logger.warning(token_expired)


def invalid_token(ip, url, method, user_agent, content_type, host, port):
    invalid_token = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "authn_invalid_token:" + ip,
        "level": "ERROR",
        "description": f"The token for ip {ip} is invalid",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }
    logger.error(invalid_token)

def invalid_user_context(username, ip, url, method, user_agent, content_type, host, port):
    invalid_user_context = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "authn_invalid_user_context:" + username,
        "level": "ERROR",
        "description": f"The user context for user {username} is invalid",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }
    logger.error(invalid_user_context)

def missing_user_context(ip, url, method, user_agent, content_type, host, port):
    missing_user_context = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "authn_missing_user_context:" + ip,
        "level": "ERROR",
        "description": f"The user context for ip {ip} is missing",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }
    logger.error(missing_user_context)

def missing_token(ip, url, method, user_agent, content_type, host, port):
    missing_user_context = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "authn_missing_token:" + ip,
        "level": "ERROR",
        "description": f"The token for ip {ip} is missing",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }
    logger.error(missing_user_context)

def AuthorizationException(ip, url, method, user_agent, content_type, host, port,exc):
    AuthorizationException = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "authn_UNK_Exception:" + ip,
        "level": "ERROR",
        "description": f"Authorization for IP {ip} threw an exception {exc} ",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }
    logger.error(AuthorizationException)
def missing_user_context_caller( request):
    missing_user_context( request.remote_addr, request.url, request.method,
                 request.headers.get('User-Agent'), request.headers.get('Content-Type'), request.host,
                 request.host.split(":")[-1])


def token_expired_caller( request):
    token_expired(
        request.remote_addr,
        request.url,
        request.method,
        request.headers.get('User-Agent'),
        request.headers.get('Content-Type'),
        request.host,
        request.host.split(":")[-1]
    )
def invalid_token_caller(request):
    invalid_token(

        request.remote_addr,
        request.url,
        request.method,
        request.headers.get('User-Agent'),
        request.headers.get('Content-Type'),
        request.host,
        request.host.split(":")[-1]
    )
def invalid_user_context_caller(request,username):
    invalid_user_context(
        username,
        request.remote_addr,
        request.url,
        request.method,
        request.headers.get('User-Agent'),
        request.headers.get('Content-Type'),
        request.host,
        request.host.split(":")[-1]
    )

def missing_token_caller(request):
    missing_token(

        request.remote_addr,
        request.url,
        request.method,
        request.headers.get('User-Agent'),
        request.headers.get('Content-Type'),
        request.host,
        request.host.split(":")[-1]
    )
def AuthorizationException_caller(request,exc):
    AuthorizationException(

        request.remote_addr,
        request.url,
        request.method,
        request.headers.get('User-Agent'),
        request.headers.get('Content-Type'),
        request.host,
        request.host.split(":")[-1],
        exc
    )