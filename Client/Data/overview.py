from Configuration.user import USER
from connection import CONN
import easygui as gui
from Data.encryption import File

list_location = '/data/{}'.format(USER.username)

def retrieve_file_list():
    resp = CONN.get(list_location)
    if not resp.status_code == 200:
        print(resp.json())
        return None
    owner = resp.json()['owner']
    shared = resp.json()['shared']
    owner_list = []
    shared_list = []
    no_access_list = []
    files = {}
    if owner:
        for key, value in owner.items():
            own, enc_name = File.parse_file_url(value)
            f = File.get_name(own, enc_name)
            if not f:
                continue
            if not f.name:
                files.update({'Lost access due to private key change. Select to delete: ' + f.encrypted_name:f})
                no_access_list += ['Lost access due to private key change. Select to delete: ' + f.encrypted_name]
            else:
                files.update({'Your file: ' + f.name:f})
                owner_list += ['Your file: ' + f.name]
    if shared:
        for key, value in shared.items():
            own, enc_name = File.parse_file_url(value)
            f = File.get_name(own, enc_name)
            if not f:
                continue
            if not f.name:
                files.update({"Lost access due to private key change. Select to delete: {}/{}".format(own, f.encrypted_name):f})
                no_access_list += ["Lost access due to private key change. Select to delete: {}/{}".format(own, f.encrypted_name)]
            else:
                files.update({"Shared with you: {}/{}".format(own, f.name):f})
                shared_list += ["Shared with you: {}/{}".format(own, f.name)]
    if not len(owner_list) > 0 and not len(shared_list) > 0 and not len(no_access_list) > 0:
        gui.msgbox("No Files available!")
        return
    choice = gui.choicebox("Which File do you want to access?", 'Access files', owner_list+shared_list+no_access_list)
    if choice:
        if choice == 'Add more choices':
            return
        f = files[choice]
        if choice.startswith("Lost access"):
            f.delete()
        else:
            f.options()
