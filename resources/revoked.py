from flask_restful import Resource

from models.accounts import auth, g
from flask import request
from lxml import etree
from defusedxml.ElementTree import parse as p


class revoked(Resource):

    def post(self):
        return 'Token revoked',200
