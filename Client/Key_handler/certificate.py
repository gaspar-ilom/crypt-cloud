from connection import CONN
from x509

class Certificate(object):
        username = None
        verified = False
        certificate = None

    def __init__(self, username):
        self.username = username
        self.certificate = self.get_certificate(username)

    def get_certificate(self, username):
        resp = CONN.get('/certificate/'+username)
        try:
            r = resp.json()
            assert(r['valid'=='Valid'] and r['username']==username)
            bytes(r['certificate'], 'utf-8')
            #TODO load cert and check is valid signature from cert auth
            get exceptons and returns right!
        except AssertionError:
            return None


class Certificate_List(object):
    certificates = None
