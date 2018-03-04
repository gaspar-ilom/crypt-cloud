from db import db

roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class Data_Access(db.Model):
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'), primary_key=True, default=-1)
    data_id = db.Column(db.Integer(), db.ForeignKey('data.id'), primary_key=True, default=-1)
    user = db.relationship("User", foreign_keys=[user_id])
    data = db.relationship("Data", foreign_keys=[data_id])

    def __init__(self, user_id, data_id):
        self.user_id = user_id
        self.data_id = data_id

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
        return self

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def get(cls, user_id=None, data_id=None):
        if user_id and data_id:
            return cls.query.filter_by(user_id=user_id, data_id=data_id).all()
        if user_id:
            return cls.query.filter_by(user_id=user_id).all()
        if data_id:
            return cls.query.filter_by(data_id=data_id).all()
        return None
