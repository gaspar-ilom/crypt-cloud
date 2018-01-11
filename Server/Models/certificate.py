from db import db
from Models.user import User
from Models.revocation import Revocation
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography import x509
import datetime
import cryptography
from functools import reduce

PRIVATE_KEY_PASS = bytes ("SecurePassphrase", 'utf-8')
ISSUER = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Berlin"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Berlin"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"crypt-cloud"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"crypt-cloud"),
    ])

def loadPrivateKey():
    #only create private key if not stored in file on disk!
    try:
        f = open("privateKey.pem", "rb")
        data = f.read()
        f.close()
        return serialization.load_pem_private_key(data, PRIVATE_KEY_PASS, default_backend())
    except FileNotFoundError:
        # Generate our key on first use
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
            )
        # Write our key to disk for safe keeping -> should be stored securely in production
        with open("privateKey.pem", "wb") as f:
            f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(PRIVATE_KEY_PASS),
            ))
        return key

privateKey = loadPrivateKey()

class Certificate(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    data = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship("User", back_populates="certificates")
    revocation = db.relationship("Revocation", uselist=False, back_populates="certificate")

    def __init__(self, data, user_id):
        self.data = data
        self.user_id = user_id

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def json(self):
        if not self.revocation:
            return {'username': self.user.username, 'certificate': str(self.data,'utf-8'), 'valid': 'Valid'}
        return {'username': self.user.username, 'certificate': str(self.data,'utf-8'), 'valid': 'Invalid'}

    @classmethod
    def create(cls, csr, user_id):
        try:
            csr = x509.load_pem_x509_csr(bytes(csr, 'utf-8'), default_backend())
            if not csr.is_signature_valid:
                return None
            cert = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                ISSUER
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
            # Our certificate will be valid for 2 years
                datetime.datetime.utcnow() + datetime.timedelta(days=(2*365))
            ).sign(privateKey, hashes.SHA512(), default_backend())
            data = cert.public_bytes(serialization.Encoding.PEM)
            return Certificate(data, user_id)
        except:
            return None

    def get_certificate(self):
        return cryptography.x509.load_pem_x509_certificate(self.data, default_backend())

    def serial_number(self):
        return self.get_certificate().serial_number

    def not_valid_after(self):
        return self.get_certificate().not_valid_after

    def is_valid(self):
        if self.revocation:
            return False
        cert = self.get_certificate()
        today = datetime.datetime.utcnow().today()
        if cert.not_valid_before > today or cert.not_valid_after < today:
            return False
        return True

    def revoke(self):
        if self.revocation:
            return None
        revocation = Revocation(self.id)
        revocation.save_to_db()
        return revocation

    @classmethod
    def get_all_valid_by_user(cls, user_id=None, user=None):
        certs = None
        if user_id:
            certs =cls.query.filter_by(user_id=user_id).all()
        else:
            certs = cls.query.filter_by(user=user).all()
        if len(certs) < 1:
            return None
        return filter(lambda x: x.is_valid, certs)

    @classmethod
    def get_by_user(cls, user_id=None, user=None):
        certs = cls.get_all_by_user(user_id, user)
        try:
            return reduce(lambda x,y: x if (x.not_valid_after()>y.not_valid_after()) else y, certs)
        except:
            return None
