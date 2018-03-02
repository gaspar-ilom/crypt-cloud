from connection import CONN
from Key_handler.certificate import Certificate
import time, threading, json
import easygui as gui

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
            gui.msgbox("Connection was refused. Make sure the specified server is reachable.", 'ERROR in Notification Handler Thread')
            #print("Connection was refused. Make sure the specified server is reachable.")
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
                #print("SMP request retrieved: {}".format(n))
                user = n.split('/')[2].split('_')[0]
                verify = gui.ynbox("Retrieved SMP verification request from user {}. Accept and start verification now? (Y/n)".format(user), '[NOTIFICATION]', ('Yes', 'No'))
                #catch errors?!
                if verify:
                    c = Certificate.get(user)
                    if c:
                        c.verify(smp=2)
            elif n.startswith('/data/'):
                #TODO implement handle new data shared by someone
                gui.msgbox("New Data shared. Retrieve by requesting: {}".format(n), '[NOTIFICATION]')
            else:
                gui.msgbox("Unknown Notification. Handle Manually: {}".format(n), '[NOTIFICATION]')
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
