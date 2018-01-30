import json
from bs4 import BeautifulSoup as bs
from connection import CONN
from PKI.private_key import PRIVATE_KEY

class User(object):
    username = None
    email = None
    password = None
    certificate = None
    csrf_token = None
    private_key = None


    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    def __repr__(self):
        return self.username

    def save(self):
        #TODO maybe append user config so it can manage several users?
        with open("Configuration/user.conf", "w") as f:
            f.write(self.username +" "+ self.email + " " + self.password + '\n')

    @classmethod
    def load(cls):
        try:
            with open("Configuration/user.conf", "r") as f:
                data = f.read().split()
            return User(data[0], data[1], data[2])
        except FileNotFoundError:
            return None

    def set_csrf_token(self, resp):
        soup = bs(resp.text, "html.parser")
        token = [n['value'] for n in soup.find_all('input')
                 if n['name'] == 'csrf_token']
        # print(token[0])
        self.csrf_token = token[0]

    def get_private_key(self):
        self.private_key = PRIVATE_KEY.get()

    def get_certificate(self):
        csr = PRIVATE_KEY.createCSR(self.username)
        payload = {
            'csr': str(csr, 'utf-8')
        }
        resp = CONN.post('/certificate/'+self.username, data=payload)
        if resp.status_code == 200:
            self.certificate = json.loads(resp.text)['certificate']
            print (self.certificate)
            return True
        print(resp)

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
        if response_post.status_code == 200:
            self.save()
            return True
        print(response_post)

    def login(self):
        resource = '/login'
        resp = CONN.get(resource)
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
        print(response_post)

    def logout(self):
        resource = '/logout'
        resp = CONN.get(resource)
        if resp.status_code == 200:
            self.csrf_token = None
            return True
        print(resp.text)
