from Configuration.user import USER
from cryptography.fernet. import Fernet

class File(object):
    name = None
    metadata = None
    shared = []
    key = None

    def __init__(self, key=None, iv=None):
        self.set_key(key)
        self.fernet = Fernet(self.key)

    def set_key(self, key=None):
        if key:
            self.key = key
        else:
            self.key = Fernet.generate_key()

    def load(self):
        pass

    def encrypt(self, data):
        return self.fernet.encrypt(data)

    def decrypt(self, data):
        self.fernet.decrypt(data)

    def encrypt_metadata(self):
        return self.fernet.encrypt(bytes(self.name, 'utf-8'))

    def decrypt_metadata(self, data):
        self.name = self.fernet.decrypt(self.name)

    def share(self):
        pass
