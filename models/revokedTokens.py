from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tokens.db'  # Cambia esto al URI de tu base de datos
db = SQLAlchemy(app)

class RevokedToken(db.Model):
    context = db.Column(db.Integer, primary_key=True)
    expiration_date = db.Column(db.DateTime)

    def __init__(self, context,time):
        self.context = context
        self.expiration_date = time

    @classmethod
    def get_by_context(cls, context):
        return cls.query.filter_by(context=context).first()

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    def rollback(self):
        db.session.rollback()
        db.session.commit()



def cleanup_expired_tokens():
    expired_tokens = RevokedToken.query.filter(RevokedToken.expiration_date < datetime.now()).all()
    for token in expired_tokens:
        db.session.delete(token)
    db.session.commit()

