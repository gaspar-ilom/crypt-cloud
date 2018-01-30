import requests
from Configuration.settings import SERVER_HOST, SERVER_PORT

class Connection(object):
    server = 'http://'+SERVER_HOST+':'+SERVER_PORT
    session = requests.session()

    def __init__(self, server_host=SERVER_HOST, server_port=SERVER_PORT):
        self.server = 'http://'+server_host+':'+server_port
        self.session = requests.session()

    def close(self):
        self.session.close()

    def get(self, resource, data=None):
        resp = self.session.get(self.server+resource)
        if resp.status_code == 200:
            return resp
        print(resp.status_code)
        print(resp.text)

    def post(self, resource, data=None):
        resp = self.session.post(self.server+resource, data=data)
        if resp.status_code == 200:
            return resp
        print(resp.status_code)
        print(resp.text)

    def delete(self, resource, data=None):
        resp = self.session.delete(self.server+resource, data=data)
        if resp.status_code == 200:
            return resp
        print(resp.status_code)
        print(resp.text)

#Use for Singleton Session
CONN = Connection()
