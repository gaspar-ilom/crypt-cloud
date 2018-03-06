import easygui as gui
from Data.overview import retrieve_file_list
from Data.encryption import File
from Key_handler.certificate import Certificate
from Configuration.user import USER

def menu():
    pass
    choice = gui.buttonbox("What do you want to do?", 'Main Menu', ('Access my Files (Share/Download/Delete etc.)', 'Upload new File', 'Verify User Certificate', 'Revoke my Certificate', 'Delete Private Key (includes revocation)', 'Quit'))
    if not choice:
        return False
    if choice == 'Quit':
        return True
    if choice == 'Access my Files (Share/Download/Delete etc.)':
        retrieve_file_list()
    elif choice == 'Upload new File':
        f = File()
        f.initiate()
        f.options()
    elif choice == 'Verify User Certificate':
        username = gui.enterbox("Please enter the username for certificate you want to verify.", 'Certificate Verification')
        if username:
            c = Certificate.get(username)
            c.verify()
    elif choice == 'Revoke my Certificate':
        USER.revoke_certificate()
    elif choice == 'Delete Private Key (includes revocation)':
        USER.delete_private_key()
    return False
