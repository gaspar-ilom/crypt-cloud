from connection import CONN
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from Verifier.SMP_verifier import SMP_verifier as SMP
from Verifier.QRCode_verifier import QRCode_verifier as QR
from Configuration.settings import CA_KEY
from Configuration.user import USER
import os, datetime, pathlib
import easygui as gui

pathlib.Path('Configuration/Certificates/').mkdir(parents=True, exist_ok=True)

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
            gui.msgbox(resp.text, 'ERROR')
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
            gui.msgbox("Did not receive a valid certificate for the requested user!", 'Certificate Retrieval Error')
            return None

    @classmethod
    def load(cls, username):
        try:
            with open("Configuration/Certificates/"+username+".pem", "rb") as f:
                return x509.load_pem_x509_certificate(f.read(), default_backend())
        except FileNotFoundError:
            return None

    @classmethod
    def load_list(cls):
        cert_list = {}
        try:
            with open("Configuration/certificate_list", "r") as f:
                with open("Configuration/new_certificate_list","w") as output:
                    for line in f.readlines():
                        line = line[:-1].split(':')
                        v = False
                        if line[1] == 'True':
                            v = True
                        cert = cls.load(line[0])
                        if cert:
                            if cert.fingerprint(cert.signature_hash_algorithm).hex() == line[2]:
                                cert_list.update({line[0]:Certificate(v, cert)})
                                output.write("{}:{}:{}\n".format(
                                line[0],
                                line[1],
                                line[2]))
                            else:
                                os.remove("Configuration/Certificates/"+line[0]+".pem")
            os.rename("Configuration/new_certificate_list", "Configuration/certificate_list")
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
        if not rev.is_signature_valid(CA_KEY):
            gui.msgbox("Signature check failed for the revocation list of user "+username+"! Make sure you have the right CA (root) certificate. Otherwise there might be a Man in the middle attack!", 'FAILED SIGNATURE CHECK')
            return False
        for r in rev:
            if r.serial_number == cert.serial_number:
                gui.msgbox("The user's certificate has been revoked. Try to retrieve a new certificate from the server.", 'REVOKED CERTIFICATE')
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
            CA_KEY.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,)
            return True
        except AssertionError:
            gui.msgbox("Did not receive a valid certificate for the requested user!", 'No valid certificate')
            return False
        except InvalidSignature:
             gui.msgbox("Signature check failed for the receive certificate of user "+username+"! Make sure you have the right CA (root) certificate. Otherwise there might be a Man in the middle attack!", 'Signature check failed')
             return False

    def verify(self, smp=None, qr=None):
        username = self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if not smp and not qr:
            if self.verified:
                answer = gui.ynbox("Certificate is already verified. Verify again?", 'Already verified', ('Yes', 'No'))
                if not answer:
                    return True
            else:
                resp = gui.ynbox('Do you want to verify {}`s certificate now? (Y/n)'.format(username), ('Yes', 'No'))
                if not resp:
                    return False
                resp = gui.buttonbox("Please choose a method for verification:\n\
                SMP - requires you to share a secret word with {} and both be online simultaneously\n\
                QR-Codes - requires you to scan QR codes from each others' devices".format(username), 'Verification Method', ('SMP', 'QR-Code (Display)', 'QR-Code (Scan)', 'Abort'))
                if resp == 'SMP':
                    smp = 1
                elif resp == 'QR-Code (Display)':
                    qr= 1
                elif resp == 'QR-Code (Scan)':
                    qr= 2
                elif resp == 'Abort':
                    return False
        if smp == 1:
            s = SMP(USER.private_key.certificate, self.certificate, initiator=True)
            self.verified = s.verify()
            #return self.verified
        elif smp == 2:
            s = SMP(self.certificate, USER.private_key.certificate, initiator=False)
            self.verified = s.verify()
            #return self.verified
        elif qr == 1:
            self.verified = QR(USER.private_key.certificate, self.certificate).display_qrcode()
        elif qr == 2:
            self.verified = QR(self.certificate, USER.private_key.certificate).verify_qrcode()
        else:
            self.verified = False
        with open("Configuration/certificate_list", "r") as input:
            with open("Configuration/new_certificate_list","w") as output:
                for line in input.readlines():
                    split = line[:-1].split(':')
                    if not split[0] == username:
                        output.write(line)
                    else:
                        output.write("{}:{}:{}\n".format(
                        split[0],
                        self.verified,
                        split[2]))
        os.rename("Configuration/new_certificate_list", "Configuration/certificate_list")
        self.load_list()
        if self.verified:
            gui.msgbox("Certificate was succesfully verified.", 'Info')
        else:
            gui.msgbox("Certificate could not be verified.", 'Info')
        return self.verified

    def confirm_using_unverified_certificate(self):
        share = gui.ynbox("Do you want to continue sharing with {} although the certificate is not verified?".format(self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value), 'Use unverified Certificate?', ('Yes', 'No'))
        if share:
            return True
        gui.msgbox("An encrypted share is currently not possible because there is no valid verified certificate to use.", 'Info')
        return False

    @classmethod
    def get_certificate_list(cls, username_list):
        c_list = []
        for u in username_list:
            c = cls.get_for_share(u)
            if c:
                c_list += [c.certificate]
        return c_list

    @classmethod
    def get_for_share(cls, username):
        c = cls.get(username)
        if not c:
            return None
        if c.verified or c.verify() or c.confirm_using_unverified_certificate():
            return c
        return None

    @classmethod
    def get(cls, username, force_new=False):
        try:
            c = certificate_list[username]
            if not c.is_valid() or force_new:
                #Delete stored invalid certificate, then try to retrieve a valid one
                print("The invalid certificate of {} will be deleted.".format(username))
                certificate_list.pop(username, None)
                os.remove("Configuration/Certificates/"+username+".pem")
                with open("Configuration/certificate_list", "r") as input:
                    with open("Configuration/new_certificate_list","w") as output:
                        for line in input.readlines():
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
            gui.msgbox("No valid certificate for user {} could be retrieved from the server. Sharing and verification are currently not possible.".format(username), 'Info')
            return None

certificate_list = {}
Certificate.load_list()
