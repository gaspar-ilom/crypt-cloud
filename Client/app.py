from Resources.user import User
from getpass import getpass

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
        if not password == password_confirm:
            print("Passwords do not match.")
            continue
        USER = User(username, email, password)
        if not USER.register():
            print("Username or email is already taken. Please choose another username and/or email.")
            USER = None
    if USER.login():
        print("Logged in as '{}'".format(USER.username))

    while 1:
        cmd = input('input command (ex. help): ')
        cmd = cmd.split()

        if cmd[0] in ['q', 'quit', 'quit()', 'exit']: #tipe quit to end it
            break
        if cmd[0] == 'help':
            print(" --- Command Overview --- ")
            print ("help - display this help text")
            print("quit - close client")
            print("GET - request http resource. Use: GET URI")
            #print("response - retrieve response from server")

        if cmd[0] == 'GET':
            #request command to server
            USER.get(cmd[1])
        # if cmd[0] in ['r', 'resp', 'response']:
        #     #get response from server
        #     rsp = CONN.getresponse()
        #     #print server response and data
        #     print(rsp.status, rsp.reason)
        #     data_received = rsp.read()
        #     print(data_received)

    USER.get('/certificate/admin')
    if USER.logout():
        print("Logged out.")
    print("Client closed.")
