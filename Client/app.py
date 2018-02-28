from Configuration.user import User
from getpass import getpass
from connection import CONN
from Key_handler import certificate, private_key

print("Starting client...")
USER = User.load()
while not USER:
    username = input('Register new Account\nUsername: ')
    email = input('Email: ')
    password = getpass()
    password_confirm = getpass('Retype Password: ')
    if len(password) < 6:
        print("Password must have at least 6 characters.")
        continue
    if not password == password_confirm:
        print("Passwords do not match.")
        continue
    USER = User(username, email, password)
    if USER.register():
        USER.set_private_key()
    else:
        print("\nUsername or email is already taken. Please choose another username and/or email.")
        USER = None
if USER.login():
    print("Logged in as {}.\n".format(USER.username))

if __name__ == '__main__':
    while 1:
        cmd = input('Input command (ex. help): ')
        cmd = cmd.split()

        if cmd[0] in ['q', 'quit', 'quit()', 'exit']: #tipe quit to end it
            break
        elif cmd[0] == 'help':
            print("")
            print(" --- Command Overview --- ")
            print ("help - display this help text")
            print("quit - close client")
            print("GET - request http resource. Use: GET URI\n")
        elif cmd[0] == 'revoke':
            USER.revoke_certificate()
        elif len(cmd) > 1 and cmd[0] in ['GET', 'POST', 'DELETE']:
            #request command to server
            if cmd[0] == 'GET':
                print(CONN.get(cmd[1]).json())
            elif cmd[0] == 'POST':
                print(CONN.post(cmd[1]).json())
            elif cmd[0] == 'DELETE':
                print(CONN.delete(cmd[1]).json())
        else:
            print("Invalid command. Type 'help' for a list of commands.\n")

    # c = certificate.Certificate.get('admin')
    # from Verifier.QRCode_verifier import QRCode_verifier as QR
    # QR(c.certificate, USER.private_key.certificate).display_qrcode()
    # QR(c.certificate, USER.private_key.certificate).verify_qrcode()

    USER.revoke_certificate()

    if USER.logout():
        print("Logged out.")
    else:
        print("Closing client without successful logout!")
    CONN.close()
