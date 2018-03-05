from cryptography import x509
from cryptography.hazmat.backends import default_backend

def get_CA_key():
    f = open("Configuration/CA.pem", "rb")
    cert = f.read()
    f.close()
    return x509.load_pem_x509_certificate(cert, default_backend()).public_key()

SERVER_HOST = 'localhost'
SERVER_PORT = '5000'
CA_KEY = get_CA_key()
