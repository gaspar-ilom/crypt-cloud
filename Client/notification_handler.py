from connection import CONN
from Key_handler.certificate import Certificate
import time, threading, json

class Notifications(object):
    list = []
    check = False
    threads = []

    def __init__(self, username):
        self.username = username
        self.threads.append(threading.Thread(target=self.loop, daemon=True))

    def start(self):
        if not self.threads[0].is_alive():
            self.threads[0].start()

    def retrieve(self):
        resource = '/notification/'+self.username
        try:
            resp = CONN.get(resource)
        except:
            print("Connection was refused. Make sure the specified server is reachable.")
            return
        if not resp.status_code == 200:
            return False
        data = resp.json()
        assert(data['username'] == self.username)
        data.pop('username')
        for key, value in data.items():
            self.list.append(value['data'])
        return True

    def handle(self):
        for n in self.list:
            if n.startswith('/smp/'):
                print("SMP request retrieved: {}".format(n))
                user = n.split('/')[2].split('_')[0]
                #catch errors?!
                c = Certificate.get(user).verify(smp=n)
            elif n.startswith('/data/'):
                #TODO implement handle new data shared by someone
                print("New Data shared. Retrieve by requesting: {}".format(n))
            else:
                print("Unknown Notification. Handle Manually: {}".format(n))
            self.delete(n)

    def delete(self, notification):
        data = {"data": notification}
        CONN.delete('/notification/'+self.username, data=data)
        self.list.remove(notification)

    def loop(self):
        self.check = True
        while self.check:
            self.retrieve()
            self.handle()
            time.sleep(3)

    def stop(self):
        self.check = False
        time.sleep(0.1)