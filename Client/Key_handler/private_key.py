from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from Configuration.settings import PRIVATE_KEY_PASS
from Configuration.settings import CA_KEY
from os import remove

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

    def revoke(self, resp):
        rev = x509.load_pem_x509_crl(bytes(resp.json()['revocation_list'], 'utf-8'), default_backend())
        if rev.is_signature_valid(CA_KEY):
            for r in rev:
                if r.serial_number == self.certificate.serial_number:
                    remove("Configuration/myCertificate.pem")
                    remove("Configuration/myPrivateKey.pem")
                    self.key = None
                    self.certificate = None
                    print("Your certificate has been revoked succesfully.")
                    return True
        print("Signature check failed for the revocation list of user "+username+"! Make sure you have the right CA (root) certificate. Otherwise there might be a Man in the middle attack or the CA might be misbehaving!")
        return False

    # Generate a CSR, write it to file and return it
    def createCSR(self, username):
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide details about who we are: just username. Email could be added
            x509.NameAttribute(NameOID.COMMON_NAME, username),
            x509.NameAttribute(NameOID.USER_ID, username),
        ])).sign(self.key, hashes.SHA512(), default_backend())
        csr = csr.public_bytes(serialization.Encoding.PEM)
        # Write our CSR out to disk.
        # with open("Configuration/csr.pem", "wb") as f:
        #     f.write(csr)
        return csr
