from datetime import datetime
import uuid

from datab import db
from sqlalchemy.dialects.postgresql import UUID


class PostsModel(db.Model):
    __tablename__ = "posts"

    id = db.Column('id',db.Text(length=36),default=lambda: str(uuid.uuid4()),primary_key=True)
    text = db.Column(db.String(280), unique=False, nullable=False)
    time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    archived = db.Column(db.Integer, nullable=False, default=0)
    account_id = db.Column(db.Integer, db.ForeignKey("accounts.id"), nullable=False)

    # usuari que publica el post
    account = db.relationship("AccountsModel", foreign_keys=[account_id], back_populates="posts")

    '''  def compute_front_end_identifier(self):
          SALT = current_app.config['Salt']
          tmp = SALT + self.id
          f_id = hashlib.sha256(tmp.encode('utf-8')).hexdigest()
          return f_id '''

    def __init__(self, text):
        self.text = text



    def json(self):
        return {
           # "id": self.compute_front_end_identifier(),
            "id": self.id,
            "text": self.text,
            "time": self.time.isoformat(),
            "account_name": self.account.username
        }

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    def rollback(self):
        db.session.rollback()
        db.session.commit()

    @classmethod
    def get_by_id(cls, id):
        return cls.query.filter_by(id=id).first()

    @classmethod
    def get_all(cls):
        return cls.query.all()



    @classmethod
    def get_comments(cls, number=5, off=0):
            return cls.query.order_by(cls.time.desc()).limit(number).offset(off).all()
