import easygui as gui
from Data.overview import retrieve_file_list
from Data.encryption import File
from Key_handler.certificate import Certificate
from Configuration.user import USER
from notification_handler import Notifications

HANDLER = Notifications(USER)
HANDLER.start()

def menu():
    HANDLER.handle()
    choice = gui.buttonbox("What do you want to do?", 'Main Menu - {}'.format(USER.username), ('Notifications', 'Access my Files', 'Upload File', 'Verify Certificate', 'Revoke my Certificate', 'Request Certificate', 'Regenerate my Private Key (includes revocation)', 'Display Secret Passphrase', 'Quit'))
    if not choice:
        return False
    if choice == 'Quit':
        HANDLER.stop()
        return True
    if choice == 'Access my Files':
        retrieve_file_list()
    elif choice == 'Notifications':
        return False
    elif choice == 'Upload File':
        f = File()
        f.initiate()
        if f:
            f.options()
    elif choice == 'Verify Certificate':
        username = gui.enterbox("Please enter the username for certificate you want to verify.", 'Certificate Verification')
        if username:
            c = Certificate.get(username)
            if c:
                c.verify()
    elif choice == 'Revoke my Certificate':
        USER.revoke_certificate()
    elif choice == 'Request Certificate':
        USER.get_certificate(confirm=False)
    elif choice == 'Regenerate my Private Key (includes revocation)':
        USER.delete_private_key()
    elif choice == 'Display Secret Passphrase':
        USER.display_passphrase()
    return False
