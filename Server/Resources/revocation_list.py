from flask_restful import Resource
from flask_security import login_required
from Models.user import User
from Models.revocation import Revocation as RevModel
from Models.certificate import Certificate as CertModel
from Models.certificate import ISSUER
from Models.certificate import privateKey
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import datetime

class RevocationList(Resource):
    username = None
    revocation_list = None

    def json(self):
        return {'username': self.username, 'revocation_list': self.revocation_list}

    @login_required
    def get(self, username):
        user = User.find_by_name(username)
        if not user:
            return {'message': "Username '{}' does not exist.".format(username)}, 404
        certs = CertModel.get_all_invalid_by_user(user=user)
        if not certs:
            print("here")
            return {'message': "No revoked certificate for this user."}, 404
        certs = list(certs)
        print("here")
        self.username = username
        self.revocation_list = self.create_revocation_list(certs)
        return self.json()

    @classmethod
    def create_revocation_list(cls, certificate_list):
        revoke_object_list = list(map(lambda x: x.create_revocation_object(), certificate_list))
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ISSUER)
        builder = builder.last_update(datetime.datetime.today())
        #update the list every time it is requested
        builder = builder.next_update(datetime.datetime.today())
        for revoked_cert in revoke_object_list:
            builder = builder.add_revoked_certificate(revoked_cert)
        revocation_list = builder.sign(
            private_key=privateKey, algorithm=hashes.SHA512(),
            backend=default_backend()
        ).public_bytes(serialization.Encoding.PEM)
        return str(revocation_list, 'utf-8')
