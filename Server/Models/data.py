from db import db
from flask import Response
from Models.joins import Data_Access
from Models.notification import Notification
from sqlalchemy.dialects.mysql import LONGBLOB

class Data(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship("User", foreign_keys=[user_id])
    key = db.Column(db.LargeBinary, nullable=False)
    data = db.Column(LONGBLOB, nullable=False)

    def __init__(self, name, user_id, key, data, shares=None):
        self.name = name
        self.user_id = user_id
        self.key = key
        self.data = data
        if shares:
            Data_Access(shares, self.id).save_to_db()

    def update(self, name=None, user_id=None, key=None, data=None, shares=None):
        if name:
            self.name = name
        if user_id:
            self.user_id = user_id
        if key:
            self.key = key
        if data:
            self.data = data
        if shares:
            if not Data_Access.get(user_id=shares, data_id=self.id):
                Notification.add("/data/{}/{}".format(self.user.username, self.name), shares)
                Data_Access(shares, self.id).save_to_db()
        db.session.commit()

    def remove_share(self, user_id):
        share = Data_Access.get(user_id=user_id, data_id=self.id)
        if share:
            for s in share:
                Notification.delete(user_id=user_id, data="/data/{}/{}".format(self.user.username, self.name))
                s.delete_from_db()

    def get_shares(self, user_id=None):
        shares = Data_Access.get(user_id=user_id, data_id=self.id)
        resp = []
        if shares:
            for s in shares:
                resp += [s.user.username]
        return resp

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
        return self

    def delete_from_db(self):
        d = Data_Access.get(data_id=self.id)
        if d:
            for item in d:
                Notification.delete(user_id=item.user_id, data="/data/{}/{}".format(self.user.username, self.name))
                item.delete_from_db()
        db.session.delete(self)
        db.session.commit()

    def json(self):
        return {'data': self.data, 'username': self.user.username, 'key': self.key, 'name': self.name}

    def prepare_answer(self):
        answer = self.key + b'_END_KEY_' + self.data + b'_END_DATA_'
        shares = Data_Access.get(data_id=self.id)
        if not shares:
            return Response(answer, status=200, mimetype='application/octet-stream')
        for s in shares:
            answer += bytes(s.user.username, 'utf-8')+b'_'
        return Response(answer[:-1], status=200, mimetype='application/octet-stream')

    @classmethod
    def get_all_by_user(cls, user_id=None, user=None):
        data = None
        if user_id:
            data =cls.query.filter_by(user_id=user_id).all()
        elif user:
            data = cls.query.filter_by(user=user).all()
        if len(data) < 1:
            return None
        return data

    @classmethod
    def get_by_name_and_user(cls, name, user_id=None, user=None):
        result = None
        if user_id:
            result = cls.query.filter_by(name=name, user_id=user_id).all()
        elif user:
            result = cls.query.filter_by(name=name, user=user).all()
        if result and len(result) > 0:
            return result[0]
        return None
