from connection import CONN, HEADERS
import json


class User(object):
    username = None
    email = None
    password = None
    csrf_token = None
    private_key = None
    certificate = None

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    def __repr__(self):
        return self.username

    @classmethod
    def load(cls):
        pass

    def set_csrf(self):
        CONN.request("GET", "/register")
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

    def register(self):
        self.set_csrf()
        body = json.dumps({"csrf_token": self.csrf_token, "email": self.email, "username": self.username, "password": self.password, "password_confirm": self.password, "remember": "y"})
        #print(body)
        CONN.request("POST", "/register", body, HEADERS)
        rsp = CONN.getresponse()
        if not rsp.status == 400:
            HEADERS.update({"Cookie": rsp.getheader("Set-Cookie")})
        data_received = rsp.read()
        print(data_received)

    def login(self):
        pass

    def logout(self):
        pass
