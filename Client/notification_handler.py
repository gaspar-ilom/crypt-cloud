from connection import CONN
from Key_handler.certificate import Certificate
from Data.encryption import File
import time, threading
import easygui as gui

class Notifications(object):
    list = []
    check = False
    threads = []
    list_lock = threading.Lock() # makes the list thread-safe -> necessary because of easygui limitations regarding threads

    def __init__(self, USER):
        self.user = USER
        self.username = USER.username
        self.threads.append(threading.Thread(target=self.loop, daemon=True))

    def start(self):
        if not self.threads[0].is_alive():
            self.threads[0].start()

    def retrieve(self):
        resource = '/notification/'+self.username
        try:
            resp = CONN.get(resource)
        except:
            # gui.msgbox("Connection was refused. Make sure the specified server is reachable.", 'ERROR in Notification Handler Thread')
            print("Connection was refused. Make sure the specified server is reachable.")
            return
        if not resp.status_code == 200:
            return False
        data = resp.json()
        assert(data['username'] == self.username)
        data.pop('username')
        self.list_lock.acquire()
        for key, value in data.items():
            if not value['data'] in self.list:
                self.list.append(value['data'])
                print("[NOTIFICATION] {}".format(value['data']))
        self.list_lock.release()
        return True

    def handle(self):
        #parallel notification ahndling is not possible because easygui cannot handle threads
        if len(self.list) < 1:
            print("No new notifications found.")
            return
        self.list_lock.acquire()
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
                owner, enc_name = File.parse_file_url(n)
                f = File.get_name(owner, enc_name)
                if f and f.name:
                    access = gui.ynbox("New Data shared with you: {}/{}".format(owner, f.name), '[NOTIFICATION]', ('Access now', 'Cancel'))
                    if access:
                        f.options()
            else:
                print("[NOTIFICATION] Unknown Notification. Handle Manually: {}".format(n))
            self.delete(n)
        self.list_lock.release()

    def delete(self, notification):
        data = {"data": notification}
        CONN.delete('/notification/'+self.username, data=data)
        self.list.remove(notification)

    def loop(self):
        self.check = True
        while self.check:
            self.retrieve()
            time.sleep(3)

    def stop(self):
        self.check = False
        time.sleep(0.1)
