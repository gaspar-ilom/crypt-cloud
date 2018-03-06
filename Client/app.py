import easygui as gui
from connection import CONN
from Configuration.user import USER
from main_handler import menu
# import time

if __name__ == '__main__':

    notify_activated = False

    while 1:
        #handle all the options in menu!
        if menu():
            break

    # f = File()
    # f.initiate()
    # f.share('hallo')
    # f.share('admin')
    # # f.share('tester')
    # retrieve_file_list()
        if not notify_activated:
            notify_activated = True
            from notification_handler import Notifications
            handler = Notifications(USER.username)
            handler.start()

    handler.stop()
    if USER.logout():
        print("Logged out.")
    else:
        print("Closing client without successful logout!")
    CONN.close()
