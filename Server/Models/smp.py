from db import db
from Models.user import User
import datetime

class SMP(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    question = db.Column(db.String(255), nullable=False)
    next_step = db.Column(db.Integer(), nullable=False, default=1)
    step1 = db.Column(db.Text)
    step2 = db.Column(db.Text)
    step3 = db.Column(db.Text)
    step4 = db.Column(db.Text)
    initiator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    initiator = db.relationship("User", foreign_keys=[initiator_id])
    replier_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    replier = db.relationship("User", foreign_keys=[replier_id])

    def __init__(self, initiator_id, replier_id, question):
        self.initiator_id = initiator_id
        self.replier_id = replier_id
        self.question = question

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
        return self

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    def json(self, complete=None):
        if complete:
            return {'initiator':self.initiator.username, 'replier': self.replier.username, 'question': self.question, 'created': str(self.created_date), 'next_step': self.next_step, 'step1': self.step1, 'step2': self.step2, 'step3': self.step3, 'step4': self.step4}
        return {'initiator':self.initiator.username, 'replier': self.replier.username, 'question': self.question, 'created': str(self.created_date)}

    @classmethod
    def get_by_users(cls, initiator, replier):
        smp = None
        smp = cls.query.filter_by(initiator=initiator, replier=replier).all()
        if len(smp) < 1:
            return None
        if len(smp) > 1:
            print("More than one SMP entry in Database for the combination of users. This should not happen. Debug! Using first row in database for now.")
        return smp[0]

    def get_data_as_json(self, step):
        data = None
        if step == 1:
            data = {'data': self.step1}
        elif step == 2:
            data = {'data': self.step2}
        elif step == 3:
            data = {'data': self.step3}
        elif step == 4:
            data = {'data': self.step4}
        if not data or not data['data']:
            data = {'no_data': 'True'}
        return data

    def update(self, step, data):
        if not step == self.next_step:
            return False
        if step == 1:
            self.step1 = data
        elif step == 2:
            self.step2 = data
        elif step == 3:
            self.step3 = data
        elif step == 4:
            self.step4 = data
        else:
            return False
        self.next_step = step+1
        db.session.commit()
        return self.json().update(self.get_data_as_json(step))
