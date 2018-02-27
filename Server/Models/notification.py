from db import db
from Models.user import User

class Notification(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    data = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship("User", back_populates="notifications")

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
        result = {'username': notif[0].user.username}
        i = 0
        for n in notif:
            result.update(n.json(i))
            i+=1
        return result

    @classmethod
    def add(cls, data, user_id):
        Notification(data, user_id).save_to_db()
