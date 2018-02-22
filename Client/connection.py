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
        resp = self.session.get(self.server+resource, data=data)
        return resp

    def post(self, resource, data=None):
        resp = self.session.post(self.server+resource, data=data)
        return resp

    def delete(self, resource, data=None):
        resp = self.session.delete(self.server+resource, data=data)
        return resp

#Use for Singleton Session
# Session() makes sure cookies persist, while multiple TCP Connections are opened, increasing performance in case of multiple requests
CONN = Connection()
