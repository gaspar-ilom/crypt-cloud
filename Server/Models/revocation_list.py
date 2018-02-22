from pki import privateKey, issuer
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import datetime

class RevocationList(object):
    username = None
    revocation_list = None

    def __init__(self, username, certificate_list):
        self.username = username
        self.revocation_list = self.create_revocation_list(certificate_list)

    def json(self):
        return {'username': self.username, 'revocation_list': self.revocation_list}

    def create_revocation_list(self, certificate_list):
        revoke_object_list = list(map(lambda x: x.create_revocation_object(), certificate_list))
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(issuer)
        builder = builder.last_update(datetime.datetime.today())
        #update the list every time it is requested
        builder = builder.next_update(datetime.datetime.today())
        for revoked_cert in revoke_object_list:
            builder = builder.add_revoked_certificate(revoked_cert)
        revocation_list = builder.sign(
            private_key=privateKey, algorithm=hashes.SHA256(),
            backend=default_backend()
        ).public_bytes(serialization.Encoding.PEM)
        return str(revocation_list, 'utf-8')
