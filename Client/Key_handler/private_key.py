from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from Configuration.settings import CA_KEY
from functools import reduce
from os import remove
import easygui as gui
import random

class PrivateKey(object): #inherit from RSA key?
    key = None
    certificate = None
    passphrase = None

    def __init__(self):
        self.key = self.load_key()
        if self.key:
            self.certificate = self.load_certificate()

    # Generate/load our private key
    def load_key(self):
        if not self.load_passphrase():
            return None
        #only create private key if not stored in file on disk!
        try:
            f = open("Configuration/myPrivateKey.pem", "rb")
            data = f.read()
            f.close()
            return serialization.load_pem_private_key(data, self.passphrase, default_backend())
        except FileNotFoundError:
            return None

    def load_passphrase(self):
        try:
            with open("Configuration/private_passphrase.txt", "rb") as f:
                self.passphrase = f.read()
            return True
        except FileNotFoundError:
            return None

    def generate_random_words(self):
        with open("Configuration/english.txt", "r") as f:
            words = f.readlines()
        #random.SystemRandom() uses secure os.urandom() to select 12 random words from a 2048 english wordlist
        words = list(map(lambda x: x[:-1], words))
        passphrase = reduce(lambda x, y: x+words[random.SystemRandom().randrange(2048)]+' ', range(12),'')[:-1]
        self.passphrase =  bytes(passphrase, 'utf-8')
        with open("Configuration/private_passphrase.txt", "wb") as f:
            f.write(self.passphrase)
        gui.msgbox("Please note down the following 12-words passphrase and store it in a secure place. In case you lose your private key you may use it to recover your account. It is also necessary to add new devices to your account. As long as you still have access to one device you may always recover this passphrase.",'New Private Key Generated')
        gui.msgbox("{}".format(passphrase),'IMPORTANT: SECURE PASSPHRASE')
        return passphrase

    def generate_key(self):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
            )
        self.generate_random_words()
        # Write our key to disk for safe keeping -> should be stored securely in production
        encrypted_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(self.passphrase),
        )
        with open("Configuration/myPrivateKey.pem", "wb") as f:
            f.write(encrypted_key)
        self.key = key
        return encrypted_key

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

    def enter_passphrase(self):
        passphrase = gui.passwordbox("Please enter your secure 12-words passphrase to decrypt your private key.",'SECURE PASSPHRASE')
        if not passphrase:
            return False
        self.passphrase = bytes(passphrase, 'utf-8')
        with open("Configuration/private_passphrase.txt", "wb") as f:
            f.write(self.passphrase)
        return True

    def delete_passphrase(self):
        self.passphrase = None
        try:
            remove("Configuration/private_passphrase.txt")
        except FileNotFoundError:
            pass

    def set_key(self, key):
        if self.enter_passphrase():
            try:
                self.key = serialization.load_pem_private_key(key, self.passphrase, default_backend())
            except ValueError:
                answer = gui.ynbox("Incorrect Passphrase. Try again?", 'ERROR', ('Yes', 'No'))
                if not answer:
                    self.delete_passphrase()
                    self.key = None
                    return
                self.set_key(key)
            with open("Configuration/myPrivateKey.pem", "wb") as f:
                f.write(key)
        else:
            answer = gui.ynbox("Incorrect Passphrase. Try again?", 'ERROR', ('Yes', 'No'))
            if not answer:
                self.delete_passphrase()
                self.key = None
                return
            self.set_key(key)

    def revoke(self, rev_list):
        rev = x509.load_pem_x509_crl(rev_list, default_backend())
        if rev.is_signature_valid(CA_KEY):
            for r in rev:
                if r.serial_number == self.certificate.serial_number:
                    remove("Configuration/myCertificate.pem")
                    self.certificate = None
                    print("Your certificate has been revoked succesfully.")
                    return True
        print("Signature check failed for the revocation list! Make sure you have the right CA (root) certificate. Otherwise there might be a Man in the middle attack or the CA might be misbehaving!")
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
