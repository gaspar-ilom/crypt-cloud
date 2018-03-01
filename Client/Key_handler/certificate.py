from connection import CONN
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from app import USER
import os, datetime, pathlib

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
        global certificate_list
        certificate_list = cert_list

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
                print("The user's certificate has been revoked. Try to retrieve a new certificate from the server.")
                return True
        return False

    def is_valid(self, username=None):
        cert = self.certificate
        now = datetime.datetime.utcnow()
        try:
            assert(now > cert.not_valid_before and now < cert.not_valid_after)
            if username:
                assert(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == username)
            if self.is_revoked():
                return False
            CA_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,)
            return True
        except AssertionError:
            print("Did not receive a valid certificate for the requested user!")
            return False
        except InvalidSignature:
             print("Signature check failed for the receive certificate of user "+username+"! Make sure you have the right CA (root) certificate. Otherwise there might be a Man in the middle attack!")
             return False

    def verify(self, smp=None, qr=None):
        if not smp and not qr:
            if self.verified:
                answer = input("Certificate is already verified. Verify again?(Y/n)")
                if not answer = 'Y':
                    return True
            else:
                resp = input('Do you want to verify {}`s certificate now? (Y/n)'.format(self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value))
                if resp == 'n':
                    return False
        #TODO actual verification and making changes permanent!
        if smp:
            s = SMP(self.certificate, USER.private_key.certificate, initiator=False)
            self.verified = s.verify()
            return self.verified
        if qr:
            #TODO imlement qr stuff -> distinguish who is displayer!
            pass
        #TODO ask for verification method to be used and use it 
        return False

    def confirm_using_unverified_certificate(self):
        share = input("Do you want to continue sharing with {} although the certificate is not verified? (Y/n)".format(self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value))
        if share in ['Y', 'y', 'Yes', 'YES', 'yes']:
            return True
        print("An encrypted share is currently not possible because there is no valid verified certificate to use.")
        return False

    @classmethod
    def get_for_share(cls, username):
        c = cls.get(username)
        if not c:
            return None
        if not c.verify():
            if not c.confirm_using_unverified_certificate():
                return None
        else:
            #write to list if verified
            #TODO move this to verify() method!
            with open("Configuration/certificate_list", "r") as input:
                with open("Configuration/new_certificate_list","w") as output:
                    for line in input:
                        split = line[:-1].split(':')
                        if not split[0] == username:
                            output.write(line)
                        else:
                            output.write("{}:{}:{}\n".format(
                            split[0],
                            c.verified,
                            split[2]))
            os.rename("Configuration/new_certificate_list", "Configuration/certificate_list")
            cls.load_list()
            return c


    @classmethod
    def get(cls, username):
        try:
            c = certificate_list[username]
            if not c.is_valid():
                #Delete stored invalid certificate, then try to retrieve a valid one
                print("The invalid certificate of {} will be deleted.".format(username))
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
        print("Trying to retrieve a new certificate for the user {}.".format(username))
        c = cls.retrieve(username)
        if c and c.is_valid():
            #Save certificate to disk
            with open("Configuration/Certificates/"+username+".pem", "wb") as f:
                f.write(c.certificate.public_bytes(serialization.Encoding.PEM))
            with open("Configuration/certificate_list", "a") as f:
                f.write("{}:{}:{}\n".format(
                username,
                c.verified,
                c.certificate.fingerprint(c.certificate.signature_hash_algorithm).hex()))
            cls.load_list()
            return c
        else:
            print("No valid certificate for user {} could be retrieved from the server. Sharing and verification are currently not possible.".format(username))
            return None

CA_key = get_CA_key()
certificate_list = {}
Certificate.load_list()
