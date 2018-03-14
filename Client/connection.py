import requests
from Configuration.settings import SERVER_HOST, SERVER_PORT, CA_KEY

class Connection(object):
    server = 'https://'+SERVER_HOST+':'+SERVER_PORT
    session = requests.session()

    def __init__(self, server_host=SERVER_HOST, server_port=SERVER_PORT):
        self.server = 'https://'+server_host+':'+server_port
        self.session = requests.session()
        self.session.verify = 'Configuration/tls_server_certificate.pem'

    def close(self):
        self.session.close()

    def get(self, resource, data=None, files=None, headers=None):
        resp = self.session.get(self.server+resource, data=data, files=files, headers=headers)
        return resp

    def post(self, resource, data=None, files=None, headers=None):
        resp = self.session.post(self.server+resource, data=data, files=files, headers=headers)
        return resp

    def delete(self, resource, data=None, files=None, headers=None):
        resp = self.session.delete(self.server+resource, data=data, files=files, headers=headers)
        return resp

#Use for Singleton Session
# Session() makes sure cookies persist, while multiple TCP Connections are opened, increasing performance in case of multiple requests
CONN = Connection()
if not CA_KEY:
    CONN.get('/login')
    print("Terminating application due to missing root certificate!")
    quit()
