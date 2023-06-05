import logging
import os
import stat
from datetime import datetime

ruta_registro = '/registro/validation/registro.log'
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

def input_validation_fail_username(username,ip, url, method, user_agent, content_type, host, port):
    username_failed = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "input_validation_fail:username," + username,
        "level": "WARNING",
        "description": f"User {username} contain data that failed validation on register.",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }
    logger.warning(username_failed)

def input_validation_text(username,ip, url, method, user_agent, content_type, host, port):
    text_fail = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "input_validation_fail:text,",
        "level": "WARNING",
        "description": f"Text input from {username} contain data that failed validation.",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }
    logger.warning(text_fail)

def input_validation_file_size(username,ip, url, method, user_agent, content_type, host, port):
    text_fail = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "input_validation_fail:file_size,",
        "level": "WARNING",
        "description": f"File from {username} contain file that failed validation.",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }
    logger.warning(text_fail)


def input_validation_fail_email(username,email, ip, url, method, user_agent, content_type, host, port):
    username_failed = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "input_validation_fail:email:" + email,
        "level": "WARNING",
        "description": f"User {username} submitted data that failed validation on register.",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }
    logger.warning(username_failed)

def input_validation_fail_password(username, ip, url, method, user_agent, content_type, host, port):
    password_failed = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "input_validation_fail:password:" + username,
        "level": "WARNING",
        "description": f"User {username} submitted an invalid password on register.",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }
    logger.warning(password_failed)

def input_validation_fail_code(username, code, ip, url, method, user_agent, content_type, host, port):
    code_failed = {
        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
        "event": "input_validation_fail:code:" + str(code),
        "level": "WARNING",
        "description": f"User {username} submitted data with failed code validation.",
        "source_ip": ip,
        "request_url": url,
        "request_method": method,
        "host": host,
        "port": port,
        "user_agent": user_agent,
        "content_type": content_type
    }
    logger = logging.getLogger()  # Obtén el objeto logger
    logger.warning(code_failed)


def input_validation_fail_email_caller(username, email , request):
    input_validation_fail_email(
        username,
        request.remote_addr,
        request.url,
        request.method,
        request.headers.get('User-Agent'),
        request.headers.get('Content-Type'),
        request.host,
        request.host.split(":")[-1]
    )


def input_validation_fail_username_caller(username, request):
    input_validation_fail_username(
        username,
        request.remote_addr,
        request.url,
        request.method,
        request.headers.get('User-Agent'),
        request.headers.get('Content-Type'),
        request.host,
        request.host.split(":")[-1]
    )
def input_validation_fail_password_caller(username, request):
    input_validation_fail_password(
        username,
        request.remote_addr,
        request.url,
        request.method,
        request.headers.get('User-Agent'),
        request.headers.get('Content-Type'),
        request.host,
        request.host.split(":")[-1]
    )



def input_validation_fail_code_caller(username, code, request):
    input_validation_fail_code(
        username,
        code,
        request.remote_addr,
        request.url,
        request.method,
        request.headers.get('User-Agent'),
        request.headers.get('Content-Type'),
        request.host,
        request.host.split(":")[-1]
    )
def input_validation_fail_text_caller(username,request):
    input_validation_text(username,
        request.remote_addr,
        request.url,
        request.method,
        request.headers.get('User-Agent'),
        request.headers.get('Content-Type'),
        request.host,
        request.host.split(":")[-1]
    )

def input_validation_fail_file_size_caller(username,request):
    input_validation_file_size(username,
        request.remote_addr,
        request.url,
        request.method,
        request.headers.get('User-Agent'),
        request.headers.get('Content-Type'),
        request.host,
        request.host.split(":")[-1]
    )