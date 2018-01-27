from Resources.user import User

USER = User.load()

# generate_certificate()
# revoke_certificate()
# get_certificate(username)
# get_revocation_list(username)


if __name__ == '__main__':
    print("Starting client...")
    from connection import CONN
    if not USER:
        USER = User("bl2a","bl2asdasda@wurst.de","test123")
        USER.register()

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

    CONN.close()
    print("Closing client...")
