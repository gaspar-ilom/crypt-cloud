from db import db

class Revocation(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    revocation_date = db.Column(db.Date, nullable=False)
    cert_id = db.Column(db.Integer, db.ForeignKey('certificate.id'), nullable=False)
    certificate = db.relationship("Certificate", back_populates="revocation")

    # def __init__(self, date, cert_id):
    #     self.revocation_date = date
    #     self.cert_id = cert_id
    
    def json(self):
        return {'cert_id': self.cert_id, 'certificate': self.certificate.data, 'revocation_date': self.revocation_date}
