from db import db
from flask_security import UserMixin
from Models.joins import roles_users

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    username = db.Column(db.String(255), unique=True, index=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    private_key = db.Column(db.LargeBinary)
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))
    #data = db.relationship('Data_Access', back_populates="user")
    certificates = db.relationship('Certificate', back_populates="user")
    notifications = db.relationship('Notification', back_populates="user")

    def get_private_key(self):
        if self.private_key:
            return {'private_key': str(self.private_key, 'utf-8')}
        return {'private_key': None}

    def set_private_key(self, key):
        self.private_key = bytes(key, 'utf-8')
        db.session.commit()

    def delete_private_key(self):
        self.private_key = None
        db.session.commit()

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
