from db import db
import datetime

class Revocation(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    revocation_date = db.Column(db.Date, nullable=False)
    cert_id = db.Column(db.Integer, db.ForeignKey('certificate.id'), nullable=False, unique=True)
    certificate = db.relationship("Certificate", back_populates="revocation")

    def __init__(self, cert_id):
        self.revocation_date = datetime.datetime.utcnow().date()
        self.cert_id = cert_id

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def json(self):
        return {'cert_id': self.cert_id, 'certificate': self.certificate.json(), 'revocation_date': str(self.revocation_date)}
