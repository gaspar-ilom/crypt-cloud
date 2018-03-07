import json, os
from bs4 import BeautifulSoup as bs
from connection import CONN
from Key_handler.private_key import PrivateKey
import easygui as gui

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
            if not user.login():
                return None
            user.set_private_key()
            return user
        except FileNotFoundError:
            if gui.ynbox("Do you want to enter your credentials for an existing account? Otherwise you will be asked to register an account.", 'Existing Account?', ('Existing Account', 'Register new Account')):
                username, email, password = gui.multpasswordbox("Enter account information:",'Account', ['Username', 'Email', 'Password'])
                if username and email and password:
                    user = User(username, email, password)
                    if user.login():
                        user.save()
                        user.set_private_key()
                        return user
            return None

    def set_csrf_token(self, resp):
        soup = bs(resp.text, "html.parser")
        token = [n['value'] for n in soup.find_all('input')
                 if n['name'] == 'csrf_token']
        self.csrf_token = token[0]

    def set_private_key(self):
        self.private_key = PrivateKey()
        if not self.private_key.key:
            if not self.retrieve_private_key():
                if not gui.ynbox("Do you want to generate a new Private Key? Without a Private Key the application will not work.", 'Generate Private Key', ('Generate Key', 'Quit')):
                    if self.logout():
                        print("Logged out.")
                    CONN.close()
                    quit()
                key = self.private_key.generate_key()
                print("Uploading encrypted key to server.")
                resp = CONN.post('/private_key/'+self.username ,data={"key": str(key, 'utf-8')})
                if not resp.status_code == 200:
                    print(resp.json())
        if not self.private_key.certificate:
            self.get_certificate()

    def retrieve_private_key(self):
        resp = CONN.get('/private_key/'+self.username)
        if resp.status_code == 200:
            key = resp.json()['private_key']
            if key:
                print('Retrieved key from server.')
                self.private_key.set_key(bytes(key, 'utf-8'))
                if self.private_key.key:
                    return True
        return False

    def get_certificate(self, confirm=True):
        if not self.private_key or not self.private_key.key:
            if gui.ynbox("Do you want to generate a new Private Key?", 'No Private Key Found', ('Yes', 'No')):
                self.set_private_key()
            else:
                return False
        elif confirm and not gui.ynbox("Do you want to request a new certificate for your private key? (This should not be done if it has been compromised and not been deleted and regenerated since!)", 'New Certificate Signing Request', ('Yes', 'No')):
            return False
        csr = self.private_key.createCSR(self.username)
        payload = {
            'csr': str(csr, 'utf-8')
        }
        resp = CONN.post('/certificate/'+self.username, data=payload)
        if resp.status_code == 200:
            cert = resp.json()['certificate']
            self.private_key.set_certificate(bytes(cert, 'utf-8'))
            print("Succefully requested a new Certificate.")
            return True
        print(resp)

    #maybe in production use revocation_certificates or let only those in possession of the private key revoke it
    def revoke_certificate(self, private_key=None):
        data = None
        if private_key:
            data = json.dumps({"cert_serial":str(private_key.certificate.serial_number, 'utf-8')})
        resp = CONN.delete('/certificate/'+self.username, data=data)
        if not private_key:
            private_key = self.private_key
        if resp.status_code == 200 and resp.json()['revocation_list']:
            rev_list = bytes(resp.json()['revocation_list'], 'utf-8')
            private_key.revoke(rev_list)
            return True
        if resp.json()['message']:
            if resp.json()['message'] == 'No valid certificate for user found.':
                print("Certificate has already been revoked.")
                return True
        return False

    def delete_private_key(self):
        self.revoke_certificate()
        resp = CONN.delete('/private_key/'+self.username)
        try:
            os.remove("Configuration/myPrivateKey.pem")
        except FileNotFoundError:
            pass
        if not self.private_key:
            print("Private Key is already deleted.")
        else:
            self.private_key.delete_passphrase()
            if not resp.status_code == 200:
                print(resp.json())
            self.private_key = None
            print("Private Key was succesfully deleted.")
        print("Generate a new private Key.")
        self.set_private_key()

    def register(self):
        resource = '/register'
        try:
            resp = CONN.get(resource)
        except:
            gui.msgbox("Connection was refused. Make sure the specified server is reachable.")
            quit()
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

    def login(self):
        resource = '/login'
        try:
            resp = CONN.get(resource)
        except:
            gui.msgbox("Connection was refused. Make sure the specified server is reachable.")
            quit()
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

USER = User.load()
while not USER:
    username, email, password = gui.multpasswordbox("Register a new Account.",'Registration', ['Username', 'Email', 'Password'])
    if len(password) < 6:
        gui.msgbox("Password must have at least 6 characters.", 'Error')
        continue
    USER = User(username, email, password)
    if USER.register():
        USER.set_private_key()
    else:
        gui.msgbox("Username or email is already taken, is too short or not valid. Please choose another username and/or email.", 'Error')
        USER = None
if USER.login():
    print("Logged in as {}.\n".format(USER.username))
