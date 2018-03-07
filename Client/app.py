import easygui as gui
from connection import CONN
from Configuration.user import USER
from main_handler import menu




if __name__ == '__main__':

    while 1:
        #handle all the options in menu!
        if menu():
            break

    if USER.logout():
        print("Logged out.")
    else:
        print("Closing client without successful logout!")
    CONN.close()
