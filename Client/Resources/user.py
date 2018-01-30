from connection import CONN, HEADERS
import json
import requests
from bs4 import BeautifulSoup as bs
from connection import SERVER_HOST, SERVER_PORT


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

    def set_csrf(self, resource):
        CONN.request("GET", resource)
        rsp = CONN.getresponse()
        # print(rsp.status, rsp.reason)
        data_received = rsp.read()
        HEADERS.update({"Cookie": rsp.getheader("Set-Cookie")})
        #print(data_received)
        data = str(data_received, 'utf-8').split()
        for i in range(0,len(data)):
            if not data[i].find("id=\"csrf_token\"") == -1:
                self.csrf_token = data[i+3].split("\"")[1]
                #print (self.csrf_token)
                return

    # def register(self):
    #     self.set_csrf("/register")
    #     body = json.dumps({"csrf_token": self.csrf_token, "email": self.email, "username": self.username, "password": self.password, "password_confirm": self.password, "remember": "y"})
    #     #print(body)
    #     CONN.request("POST", "/register", body, HEADERS)
    #     rsp = CONN.getresponse()
    #     if rsp.status == 200:
    #         HEADERS.update({"Cookie": rsp.getheader("Set-Cookie")})
    #         self.save()
    #         return True
    #     data_received = rsp.read()
    #     print(data_received)


    def set_csrf_token(self, resp):
        soup = bs(resp.text, "html.parser")
        token = [n['value'] for n in soup.find_all('input')
                 if n['name'] == 'csrf_token']
        # print(token[0])
        self.csrf_token = token[0]

    def register(self):
        resource = '/register'
        with requests.session() as s:
            resp = s.get('http://'+SERVER_HOST+':'+SERVER_PORT+resource)
            self.set_csrf_token(resp)
            payload = {
                'email': self.email,
                'username': self.username,
                'password': self.password,
                'password_confirm': self.password,
                'remember': 'y',
                'csrf_token': self.csrf_token,
                }
            response_post = s.post('http://'+SERVER_HOST+':'+SERVER_PORT+resource, data=payload)
            if response_post.status_code == 200:
                self.save()
                return True
            print(response_post)


    def login(self):
        self.set_csrf("/login")
        body = json.dumps({"csrf_token": self.csrf_token, "email": self.email, "username": self.username, "password": self.password, "remember": "y"})
        CONN.request("POST", "/login", body, HEADERS)
        rsp = CONN.getresponse()
        if rsp.status == 200:
            HEADERS.update({"Cookie": rsp.getheader("Set-Cookie")})
            return True
        data_received = rsp.read()
        print(data_received)

    def logout(self):
        CONN.request("GET", "/logout", headers=HEADERS)
        if CONN.getresponse().status == 200:
            return True
