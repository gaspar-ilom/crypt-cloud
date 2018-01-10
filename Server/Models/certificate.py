from db import db
from Models.user import User
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import datetime

class Certificate(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    data = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship("User", back_populates="certificates")
    revocation = db.relationship("Revocation", uselist=False, back_populates="certificate")

    # def __init__(self, data, user_id):
    #     self.data = data
    #     self.user_id = user_id

    def json(self):
        if not self.revocation:
            return {'username': self.user.username, 'certificate': self.data, 'valid': 'Valid'}
        return {'username': self.user.username, 'certificate': self.data, 'valid': 'Invalid'}

    def get_certificate(self):
        return cryptography.x509.load_pem_x509_certificate(self.data, default_backend())

    def is_valid(self):
        if self.revocation:
            return False
        cert = self.get_certificate()
        today = datetime.datetime.utcnow().today()
        if cert.not_valid_before > today or cert.not_valid_after < today:
            return False
        return True

    @classmethod
    def get_by_user_id(cls, user_id):
        return filter(lambda x: x.is_valid(), cls.query.filter_by(user_id=user_id)).first()
