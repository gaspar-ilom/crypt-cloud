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
            self.fernet = Fernet(self.key)

    @classmethod
    def parse_file_url(cls, url):
        owner = url.split('/')[2]
        name = url.split('/')[3]
        return owner, name

    @classmethod
    def get_name(cls, owner, encrypted_name):
        f = File()
        f.encrypted_name = encrypted_name
        f.owner = owner
        keys, data, shares, complete_keys = f.parse_data_from_server()
        if not data:
            gui.msgbox("Could not retrieve data at this URL: /data/{}/{}".format(owner, encrypted_name))
            f.delete()
            return None
        # if not data:
        #     print('data')
        # if not bytes(USER.username, 'utf-8') in shares:
        #     print('no share')
        #     print(shares)
        # if not USER.username==owner:
        #     print('not owner')
        # if not f.get_key(keys):
        #     print('no key')
        if not bytes(USER.username, 'utf-8') in shares and not USER.username==owner:
            print(USER.username)
            print(owner)
            print('shares:')
            print(shares)
            f.delete()
            gui.msgbox("User has no access to this URL.")
            return None
        if not f.get_key(keys):
            f.delete()
            gui.msgbox("Could not retrieve a valid key at this URL.")
            return None
        f.decrypt_name()
        return f

    def options(self):
        #gui.msgbox("Implement file handling!")
        choice = gui.buttonbox("What do you want to do with the file '{}/{}'?".format(self.owner, self.name), 'File Options', ('Delete file', 'Add user to share', 'Remove user from share', 'Update file on server', 'Download', 'Cancel'))
        if not choice or choice == 'Cancel':
            return
        if choice == 'Delete file':
            self.delete()
        elif choice == 'Add user to share':
            self.share()
        elif choice == 'Remove user from share':
            self.remove_share()
        elif choice == 'Update file on server':
            self.update_online()
        elif choice == 'Download':
            self.store_locally()

    def initiate(self, username_list=None):
        self.get_path()
        if not self.name:
            return
        self.encrypt_name()
        self.load()
        self.upload(username_list)

    def delete(self, share=None):
        r = CONN.delete('/data/{}/{}'.format(self.owner, self.encrypted_name), data=share)
        if not r.status_code == 200:
            print(r.json())
        if share:
            print('Succesfully revoked share with user {} from {}'.format(share['shares'], self.name))
        else:
            print('Succesfully deleted {}'.format(self.name))

    def remove_share(self, username=None):
        if not username:
            username = gui.enterbox('Enter username of the user to remove from share of {}.'.format(self.name), 'Remove from share')
        if not username:
            return
        if self.owner == username:
            gui.msgbox("Cannot remove owner from a file share!")
            return
        keys, data, shares, complete_keys = self.parse_data_from_server()
        if data:
            new_key = b''
            beginning = complete_keys.split(bytes(username, 'utf-8')+b':KEY:')[0]
            rest = complete_keys.split(bytes(username, 'utf-8')+b':KEY:')[1]
            if len(rest.split(b':END:')) == 1:
                new_key = beginning.strip(b':END:')
            else:
                start = rest.find(b':END:')+len(b':END:')
                new_key = beginning+rest[start:]
            r = CONN.post('/data/{}/{}'.format(self.owner, self.encrypted_name), files={'key': new_key})
            if not r.status_code == 200:
                print(r.json())
        share = {'shares':username}
        self.delete(share)

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
        # self.check(r.content)
        if not r.status_code == 200:
            print(r.text)
        print('Succesfully uploaded {}'.format(self.name))

    def update_online(self):
        if not self.path:
            self.get_path()
        if not self.name:
            gui.msgbox("No file name specified. No file update possible.")
            return
        if not self.encrypted_name:
            self.encrypt_name()
        self.load()
        files = {'data': self.encrypt_data()}
        r = CONN.post('/data/{}/{}'.format(self.owner, self.encrypted_name), files=files)
        if not r.status_code == 200:
            print(r.text)
        print('Succesfully updated {}'.format(self.name))

    def check(self, r=None):
        keys, data, shares, complete_keys = self.parse_data_from_server(r)
        self.decrypt_name()
        # print('retrieved_data')
        # print(data)
        self.decrypt(data)
        print("Check Success")

    @classmethod
    def retrieve(cls, owner, encrypted_name):
        f = cls.get_name(owner, encrypted_name)
        f.store_locally()
        return f

    def store_locally(self):
        keys, data, shares, complete_keys = self.parse_data_from_server()
        if not data:
            print("Abort Download.")
            return
        self.decrypt(data)
        self.set_path()
        self.update_data()
        print('Succesfully saved {}'.format(self.path))

    def get_key(self, keys_list):
        i = 0
        while i < len(keys_list):
            if keys_list[i] == bytes(USER.username, 'utf-8'):
                self.key = USER.private_key.key.decrypt(keys_list[i+1], padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
                self.fernet = Fernet(self.key)
                return True
            i+=2

    def parse_data_from_server(self, r=None):
        if not r:
            r = CONN.get('/data/{}/{}'.format(self.owner, self.encrypted_name)).content
        try:
            complete_keys = r.split(b'_END_KEY_')[0]
            keys = complete_keys.split(b':END:')
            data = r.split(b'_END_KEY_')[1].split(b'_END_DATA_')[0]
            shares = r.split(b'_END_DATA_')[1].split(b'_')
            user_key_list = []
            for k in keys:
                user_key_list += k.split(b':KEY:')
            return user_key_list, data, shares, complete_keys
        except IndexError as e:
            print('Could not parse data from server.')
            return None, None, None, None

    def share(self, username=None):
        if not self.encrypted_name or not self.owner:
            return
        if not username:
            username = gui.enterbox('Enter username of the user to share {} with.'.format(self.name), 'Share')
        if not username:
            return
        if username == USER.username:
            gui.msgbox("Cannot share data with yourself!", 'ERROR')
            return
        keys, data, shares, complete_keys = self.parse_data_from_server()
        if not data:
            gui.msgbox("Data from server could not be parsed. So sharing is not possible.")
        if username in keys:
            assert(username in shares)
            return
        data={'shares':username}
        cert = Certificate.get_certificate_list([username])
        if len(cert)<1:
            gui.msgbox("No share possible. Missing certificate for {}".format(username))
            return
        complete_keys += b':END:' + self.encrypt_key(cert)
        r = CONN.post('/data/{}/{}'.format(self.owner, self.encrypted_name), data=data, files={'key': complete_keys})
        if not r.status_code == 200:
            print(r.text)

    def set_path(self):
        self.path = gui.diropenbox()+'/'+self.name

    def get_path(self, name=None):
        self.path = gui.fileopenbox()
        if not self.path:
            return
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

    def decrypt_name(self, name=None):
        if name:
            self.encrypted_name = name
        self.name = str(self.fernet.decrypt(base64.urlsafe_b64decode(bytes(self.encrypted_name, 'utf-8'))), 'utf-8')
