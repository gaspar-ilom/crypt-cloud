from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from Configuration.settings import PRIVATE_KEY_PASS

class PrivateKey(object): #inherit from RSA key?
    key = None
    certificate = None

    def __init__(self):
        self.key = self.load_key()
        if not self.key:
            self.key = self.generate_key()
        self.certificate = self.load_certificate()

    # Generate/load our private key
    @classmethod
    def load_key(cls):
        #only create private key if not stored in file on disk!
        try:
            f = open("Configuration/myPrivateKey.pem", "rb")
            data = f.read()
            f.close()
            return serialization.load_pem_private_key(data, PRIVATE_KEY_PASS, default_backend())
        except FileNotFoundError:
            return None

    @classmethod
    def generate_key(cls):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
            )
        # Write our key to disk for safe keeping -> should be stored securely in production
        with open("Configuration/myPrivateKey.pem", "wb") as f:
            f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(PRIVATE_KEY_PASS),
            ))
        return key

    def load_certificate(self):
        #only create certificate if not stored in file on disk!
        try:
            f = open("Configuration/myCertificate.pem", "rb")
            data = f.read()
            f.close()
            return x509.load_pem_x509_certificate(data, default_backend())
        except FileNotFoundError:
            return None

    def set_certificate(self, certificate):
        self.certificate = x509.load_pem_x509_certificate(certificate, default_backend())
        with open("Configuration/myCertificate.pem", "wb") as f:
            f.write(certificate)

    def revoke():
        pass

    # Generate a CSR, write it to file and return it
    def createCSR(self, username):
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide details about who we are: just username. Email could be added
            x509.NameAttribute(NameOID.COMMON_NAME, username),
            x509.NameAttribute(NameOID.USER_ID, username),
        ])).sign(self.key, hashes.SHA512(), default_backend())
        csr = csr.public_bytes(serialization.Encoding.PEM)
        # Write our CSR out to disk.
        with open("Configuration/csr.pem", "wb") as f:
            f.write(csr)
        return csr
