from Resources.user import User
from getpass import getpass

# generate_certificate()
# revoke_certificate()
# get_certificate(username)
# get_revocation_list(username)


if __name__ == '__main__':
    print("Starting client...")
    from connection import CONN
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

        if cmd[0] == 'q' or cmd[0] == 'quit': #tipe quit to end it
            break
        if cmd[0] == 'help':
            print(" --- Command Overview --- ")
            print ("help - display this help text")
            print("quit - close client")
            print("request - request http resource. Use: request HTTP_METHOD URI")
            print("response - retrieve response from server")

        if cmd[0] == 'request':
            #request command to server
            CONN.request(cmd[1], cmd[2])
        if cmd[0] == 'response':
            #get response from server
            rsp = CONN.getresponse()
            #print server response and data
            print(rsp.status, rsp.reason)
            data_received = rsp.read()
            print(data_received)

    if USER.logout():
        print("Logged out.")
    CONN.close()
    print("Client closed.")
