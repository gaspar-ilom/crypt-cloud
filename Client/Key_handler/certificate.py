from connection import CONN
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding


def get_CA_key():
    f = open("Configuration/CA.pem", "rb")
    cert = f.read()
    f.close()
    return x509.load_pem_x509_certificate(cert, default_backend()).public_key()

class Certificate(object):
    username = None
    verified = False
    certificate = None

    def __init__(self, username):
        self.username = username
        self.certificate = self.get(username)

certificate_list = None
CA_key = get_CA_key()
