from db import db
from Models.user import User

class Notification(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    data = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship("User", back_populates="notifications")
    unique_constraint = db.UniqueConstraint('data', 'user_id')

    def __init__(self, data, user_id):
        self.data = data
        self.user_id = user_id

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    def json(self, index):
        return {str(index): {'data': self.data, 'id': self.id}}

    @classmethod
    def get_all_by_user(cls, user_id=None, user=None):
        notif = None
        if user_id:
            notif =cls.query.filter_by(user_id=user_id).all()
        else:
            notif = cls.query.filter_by(user=user).all()
        if len(notif) < 1:
            return None
        return notif

    @classmethod
    def add(cls, data, user_id):
        Notification(data, user_id).save_to_db()

    @classmethod
    def delete(cls, user=None, user_id=None, id=None, data=None):
        N = None
        if user:
            N = cls.get_all_by_user(user=user)
        elif user_id:
            N = cls.get_all_by_user(user_id=user_id)
        if not N:
            return
        if id:
            N = filter(lambda x: x.id == id, N)
        elif data:
            N = filter(lambda x: x.data == data, N)
        for n in N:
            n.delete_from_db()
