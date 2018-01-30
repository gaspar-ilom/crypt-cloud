from Resources.user import User
from getpass import getpass
from connection import CONN

# generate_certificate()
# revoke_certificate()
# get_certificate(username)
# get_revocation_list(username)


if __name__ == '__main__':
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
            print("Username or email is already taken. Please choose another username and/or email.")
            USER = None
    if USER.login():
        print("Logged in as {}.".format(USER.username))

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

        elif cmd[0] == 'GET':
            #request command to server
            CONN.get(cmd[1])
        else:
            print("Invalid command. Type 'help' for a list of commands.")

    USER.get_certificate()
    if USER.logout():
        print("Logged out.")
    else:
        print("Closing client without successful logout!")
    CONN.close()
