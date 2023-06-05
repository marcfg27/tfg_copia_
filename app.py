from flask import Flask, request, redirect
from flask import render_template
from flask_cors import CORS
from flask_migrate import Migrate
from flask_restful import Api
from models.Function import Function
#from datab import db, secret_key, secret_key2, admin_pass, email_pass ,email_user # ,Salt
from resources.accounts import Accounts, AccountsList, money
from resources.email import eMail, eMail2, eMail3, mail, limiter2
from resources.login import Login, limiter
from resources.posts import Posts
from resources.xml import XML_HTTP
from acces_control import require_access
#from flask_sslify import SSLify


# app = Flask(__name__)
app = Flask(
    __name__,
    static_folder="static",
    template_folder="templates"
)
#sslify = SSLify(app)
app.config['SECRET_KEY'] = '1234'
app.config['Admin_Pass'] = '1234'
app.config['SECRET_KEY2'] = '1234'
#app.config['Salt'] = Salt




CORS(app, resources={r'/*': {'origins': '*'}})
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CORS_SUPPORTS_CREDENTIALS'] = True
api = Api(app)
#migrate = Migrate(app, db)
#db.init_app(app)

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = '1234'
app.config['MAIL_PASSWORD'] = '1234'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True


mail.init_app(app)
limiter.init_app(app)
limiter2.init_app(app)

api.add_resource(Accounts, '/account')
api.add_resource(AccountsList, '/accounts')

api.add_resource(Login, '/login')

api.add_resource(eMail, '/email')
api.add_resource(eMail2, '/email2')
api.add_resource(eMail3, '/email3')
api.add_resource(Posts, '/posts')

api.add_resource(XML_HTTP, '/sendxml')
#api.add_resource(cerrarSession, '/closes')


import models.Function as f

api.add_resource(money,'/money')#/<string:username>

from flask_wtf.csrf import  CSRFProtect

csrf = CSRFProtect(app)

'''f.create_function('GETaccounts')
f.create_function('GETmoney')
f.create_function('GETposts')
f.create_function('GETinside')
f.create_function('DELETEposts')
f.create_function('POSTxml_http')
f.create_function('POSTemail')
f.create_function('GETemail')
f.create_function('POSTposts')
f.create_function('DELETEaccounts')
f.create_function('GETaccountslist')
'''
@app.route('/')
def render_vue():
        return render_template("index.html")

@app.route('/inside')
def inside():
    return render_template("index.html")
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'none'"
    return response

@app.before_request
@require_access
def acces_control():
    pass

if __name__ == '__main__':
    app.run()




