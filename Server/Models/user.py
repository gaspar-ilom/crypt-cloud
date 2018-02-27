from db import db
from flask_security import UserMixin
from Models.roles_users import roles_users

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    username = db.Column(db.String(255), unique=True, index=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))
    certificates = db.relationship('Certificate', back_populates="user")
    notifications = db.relationship('Notification', back_populates="user")

    def get_security_payload(self):
        return {
            'username': self.username,
            'email' : self.email,
            'id' : self.id
        }

    @classmethod
    def find_by_name(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id=_id).first()

    @classmethod
    def get_username_by_id(cls, _id):
        return cls.query.filter_by(id=_id).first().username
