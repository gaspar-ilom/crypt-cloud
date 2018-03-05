from Configuration.user import USER
from cryptography.fernet import Fernet
import easygui as gui
from connection import CONN
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from Key_handler.certificate import Certificate
import base64

class File(object):
    name = None
    path = None
    owner = USER.username
    data = None
    key = None
    encrypted_name = None

    def __init__(self, username=None, key=None):
        if username:
            self.owner = username
        self.set_key(key)
        if self.key:
            print(self.key)
            self.fernet = Fernet(self.key)

    def initiate(self):
        self.get_path()
        self.encrypt_name()
        self.load()
        self.upload()

    def encrypt_key(self, certificate_list):
        crypt = b''
        for c in certificate_list:
            crypt += bytes(c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, 'utf-8') + b':KEY:' + c.public_key().encrypt(self.key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)) + b':END:'
        return crypt.strip(b':END:')

    def upload(self, username_list=None):
        c_list = [USER.private_key.certificate]
        files = {'key': self.encrypt_key(c_list), 'data': self.encrypt_data()}
        r = CONN.post('/data/{}/{}'.format(self.owner, self.encrypted_name), files=files)
        if r.status_code == 200 and username_list:
            map(lambda x: self.share(x), username_list)
        self.check()
        if not r.status_code == 200:
            print(r.text)

    def check(self):
        keys, data, shares, complete_keys = self.parse_data_from_server()
        self.decrypt_name()
        self.decrypt(data)
        print("Success")

    @classmethod
    def retrieve(cls, owner, encrypted_name):
        f = File()
        f.encrypted_name = encrypted_name
        f.owner = owner
        keys, data, shares, complete_keys = f.parse_data_from_server()
        assert(bytes(USER.username, 'utf-8') in shares or USER.username==owner)
        if not f.get_key(keys):
            gui.msgbox("Could not retrieve a valid key at this URL.")
            return None
        f.decrypt_name()
        f.data = f.decrypt(data)
        f.set_path()
        f.update_data()
        return f

    def get_key(self, keys_list):
        i = 0
        while i < len(keys_list):
            if keys_list[i] == bytes(USER.username, 'utf-8'):
                self.key = USER.private_key.key.decrypt(keys_list[i+1], padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
                self.fernet = Fernet(self.key)
                print(self.key)
                return True
            i+=2


    def parse_data_from_server(self, r=None):
        if not r:
            r = CONN.get('/data/{}/{}'.format(self.owner, self.encrypted_name)).content
        complete_keys = r.split(b'_END_KEY_')[0]
        keys = complete_keys.split(b':END:')
        data = r.split(b'_END_KEY_')[0].split(b'_END_DATA_')[0]
        shares = r.split(b'_END_DATA_')[0].split(b'_')
        user_key_list = []
        for k in keys:
            user_key_list += k.split(b':KEY:')
        return user_key_list, data, shares, complete_keys

    def share(self, username):
        keys, data, shares, complete_keys = self.parse_data_from_server()
        if username in keys:
            assert(username in shares)
            return
        data={'shares':username}
        cert = Certificate.get_certificate_list([username])
        if len(cert)<1:
            print("No share possible. Missing certificate for {}".format(username))
            return
        complete_keys += b':END:' + self.encrypt_key(cert)
        r = CONN.post('/data/{}/{}'.format(self.owner, self.encrypted_name), data=data, files={'key': complete_keys})
        if not r.status_code == 200:
            print(r.text)

    def set_path(self):
        self.path = gui.diropenbox()+'/'+self.name

    def get_path(self, name=None):
        self.path = gui.fileopenbox()
        self.name = self.path.split('/')[-1]

    def load(self):
        with open(self.path, "rb") as f:
            self.data = f.read()

    def update_data(self):
        with open(self.path, "wb") as f:
            f.write(self.data)

    def set_key(self, key=None):
        if key:
            self.key = key
        else:
            self.key = Fernet.generate_key()

    def encrypt_data(self):
        return self.fernet.encrypt(self.data)

    def decrypt(self, data):
        self.data = self.fernet.decrypt(data)

    def encrypt_name(self):
        self.encrypted_name = str(base64.urlsafe_b64encode(self.fernet.encrypt(bytes(self.name, 'utf-8'))), 'utf-8')
        print(self.encrypted_name)

    def decrypt_name(self, name=None):
        if name:
            self.encrypted_name = name
        self.name = str(self.fernet.decrypt(base64.urlsafe_b64decode(bytes(self.encrypted_name, 'utf-8'))), 'utf-8')
