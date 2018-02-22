import json
from bs4 import BeautifulSoup as bs
from connection import CONN
from Key_handler.private_key import PrivateKey
import pathlib
pathlib.Path('Configuration/Certificates/').mkdir(parents=True, exist_ok=True) 

class User(object):
    username = None
    email = None
    password = None
    csrf_token = None
    private_key = None


    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    def __repr__(self):
        return self.username

    def save(self):
        with open("Configuration/user.conf", "w") as f:
            f.write(self.username +" "+ self.email + " " + self.password + '\n')

    @classmethod
    def load(cls):
        try:
            with open("Configuration/user.conf", "r") as f:
                data = f.read().split()
            user = User(data[0], data[1], data[2])
            user.login()
            user.set_private_key()
            return user
        except FileNotFoundError:
            return None

    def set_csrf_token(self, resp):
        soup = bs(resp.text, "html.parser")
        token = [n['value'] for n in soup.find_all('input')
                 if n['name'] == 'csrf_token']
        self.csrf_token = token[0]

    def set_private_key(self):
        self.private_key = PrivateKey()
        if not self.private_key.certificate:
            self.get_certificate()

    def get_certificate(self):
        csr = self.private_key.createCSR(self.username)
        payload = {
            'csr': str(csr, 'utf-8')
        }
        resp = CONN.post('/certificate/'+self.username, data=payload)
        if resp.status_code == 200:
            cert = resp.json()['certificate']
            self.private_key.set_certificate(bytes(cert, 'utf-8'))
            return True
        print(resp)

    #maybe in production use revocation_certificates oder let only those in possession of the private key revoke it
    def revoke_certificate(self, private_key=None):
        data = None
        if private_key:
            data = json.dumps({"cert_serial":str(private_key.certificate.serial_number, 'utf-8')})
            private_key.revoke()
        resp = CONN.delete('/certificate/'+self.username, data=data)
        #TODO verify signature from Cert Authority
        if not private_key:
            self.private_key.revoke()
        print(resp.text)
        # crl = cryptography.x509.load_pem_x509_crl(resp.json()['revocation_list'], backend)
        # if crl.is_signature_valid(public_key):
        #     return True

    def register(self):
        resource = '/register'
        resp = CONN.get(resource)
        self.set_csrf_token(resp)
        payload = {
            'email': self.email,
            'username': self.username,
            'password': self.password,
            'password_confirm': self.password,
            'remember': 'y',
            'csrf_token': self.csrf_token,
            }
        response_post = CONN.post(resource, data=payload)
        if response_post.text == "Logged in as {}.".format(self.username):
            self.save()
            return self.login()
        print(response_post)

    def login(self):
        resource = '/login'
        resp = CONN.get(resource)
        if resp.text == "Logged in as {}.".format(self.username):
            return True
        self.set_csrf_token(resp)
        payload = {
            'email': self.email,
            'username': self.username,
            'password': self.password,
            'remember': 'y',
            'csrf_token': self.csrf_token,
            }
        response_post = CONN.post(resource, data=payload)
        if response_post.status_code == 200:
            return True

    def logout(self):
        resource = '/logout'
        resp = CONN.get(resource)
        if resp.text == "Not logged in.":
            self.csrf_token = None
            return True
        print(resp.text)
