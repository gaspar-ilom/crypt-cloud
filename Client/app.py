from connection import CONN
from Configuration.user import USER
from notification_handler import Notifications
import easygui as gui

if __name__ == '__main__':
    handler = Notifications(USER.username)
    handler.start()
    while 1:
        break
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


    # fin = b'halloashd\x00\xff\xdcbabdshallo'
    # fin2 = b'\x00\xff\xdcbabdshallo'
    # files = {'key': fin, 'data': fin2}
    #
    #
    # r = CONN.post('/data/tester/name', data={'shares':'tester'}, files=files)#, headers={'content-type': 'application/octet-stream'})
    #r = CONN.get('/data/tester/name')#, data={'shares':'abcd'}, files=files)
    # print(r.status_code)
    # print(r.content)
    # print(r.content.split(b'_END_KEY_'))
    # print(r.json())

    from Data.encryption import File
    f = File()
    f.initiate()
    f.share('admin')
    f.share('admin')
    fr = File.retrieve('tester', 'Z0FBQUFBQmFubG5rZkJiaEJNdUlEdHpmMW1DMzBtQ2xRaFhlWmVFZVlBZmxyNFhiTi1YemZrd2Y4VG9FNkt6SFpiYVVIX1dMbTdBemd1NVZ0UXhROC1IcFc1SlVDa2FxYlE9PQ==')

    handler.stop()
    if USER.logout():
        print("Logged out.")
    else:
        print("Closing client without successful logout!")
    CONN.close()
