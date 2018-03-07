from cryptography import x509
from cryptography.hazmat.backends import default_backend

def get_CA_key():
    try:
        with open("Configuration/CA.pem", "rb") as f:
            cert = f.read()
            return x509.load_pem_x509_certificate(cert, default_backend()).public_key()
    except FileNotFoundError:
        print("NO CA root certificate at 'Configuration/CA.pem'. The application will misbehave. Copy the valid certificate to that location. You will find it in the Server application's root directory after the first request.")
        return None

SERVER_HOST = 'localhost'
SERVER_PORT = '5000'
CA_KEY = get_CA_key()
