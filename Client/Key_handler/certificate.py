from connection import CONN
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
import codecs, os, datetime, pathlib

pathlib.Path('Configuration/Certificates/').mkdir(parents=True, exist_ok=True)

def get_CA_key():
    f = open("Configuration/CA.pem", "rb")
    cert = f.read()
    f.close()
    return x509.load_pem_x509_certificate(cert, default_backend()).public_key()

class Certificate(object):
    verified = False
    certificate = None

    def __init__(self, verified, certificate):
        self.verified = verified
        self.certificate = certificate

    def user(self):
        return self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    def json(self):
        return {'verified': self.verified, 'fingerprint': self.certificate.fingerprint(self.certificate.signature_hash_algorithm).hex()}

    @classmethod
    def retrieve(cls, username):
        resp = CONN.get('/certificate/'+username)
        if not resp.status_code == 200:
            print(resp.text)
            return None
        try:
            r = resp.json()
            assert(r['valid']=='Valid' and r['username']==username)
            cert_pem = bytes(r['certificate'], 'utf-8')
            #load cert and check is valid signature from cert auth
            # get exceptions and returns right!
            cert = Certificate(False, x509.load_pem_x509_certificate(cert_pem, default_backend()))
            if not cert.is_valid():
                return None
            return cert
        except KeyError:
            print("Did not receive a valid certificate for the requested user!")
            return None

    @classmethod
    def load(cls, username):
        with open("Configuration/Certificates/"+username+".pem", "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())

    @classmethod
    def load_list(cls):
        cert_list = {}
        try:
            with open("Configuration/certificate_list", "r") as f:
                for line in f.readlines():
                    line = line[:-1].split(':')
                    v = False
                    if line[1] == 'True':
                        v = True
                    cert = cls.load(line[0])
                    assert(cert.fingerprint(cert.signature_hash_algorithm).hex() == line[2])
                    cert_list.update({line[0]:Certificate(v, cert)})
        except FileNotFoundError:
            pass
        return cert_list

    #Note that certificate revocation lists are not securely implemented in the Cryptography library, as they are only based on the serial_number and not the fingerprint!
    def is_revoked(self):
        cert = self.certificate
        username = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        resp = CONN.get('/revocation_list/'+username)
        if not resp.status_code == 200:
            return False
        rev = x509.load_pem_x509_crl(bytes(resp.json()['revocation_list'], 'utf-8'), default_backend())
        if not rev.is_signature_valid(CA_key):
             print("Signature check failed for the revocation list of user "+username+"! Make sure you have the right CA (root) certificate. Otherwise there might be a Man in the middle attack!")
             return False
        for r in rev:
            if r.serial_number == cert.serial_number:
                return True
        print("Received revoked certificates for user {}, but the one in use is not among them.".format(username))
        return False

    def is_valid(self, username=None):
        cert = self.certificate
        now = datetime.datetime.utcnow()
        try:
            assert(now > cert.not_valid_before and now < cert.not_valid_after)
            if username:
                assert(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == username)
            else:
                assert(not self.is_revoked())
            CA_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,)
            return True
        except AssertionError:
            print("Did not receive a valid certificate for the requested user or certificate has been revoked!")
            return False
        except InvalidSignature:
             print("Signature check failed for the receive certificate of user "+username+"! Make sure you have the right CA (root) certificate. Otherwise there might be a Man in the middle attack!")
             return False

    @classmethod
    def get(cls, username):
        try:
            c = certificate_list[username]
            if not c.is_valid():
                certificate_list.pop(username, None)
                os.remove("Configuration/Certificates/"+username+".pem")
                with open("Configuration/certificate_list", "r") as input:
                    with open("Configuration/new_certificate_list","wb") as output:
                        for line in input:
                            user = line[:-1].split(':')[0]
                            if not user == username:
                                output.write(line)
                os.rename("Configuration/new_certificate_list", "Configuration/certificate_list")
            else:
                return c
        except KeyError:
            pass
        c = cls.retrieve(username)
        if c:
            #save cert to disk!
            with open("Configuration/Certificates/"+username+".pem", "wb") as f:
                f.write(c.certificate.public_bytes(serialization.Encoding.PEM))
            with open("Configuration/certificate_list", "a") as f:
                f.write("{}:{}:{}\n".format(
                username,
                False,
                c.certificate.fingerprint(c.certificate.signature_hash_algorithm).hex()))
        return c

CA_key = get_CA_key()
certificate_list = Certificate.load_list()
