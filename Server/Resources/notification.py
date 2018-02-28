from flask_restful import Resource, reqparse
from flask_security import login_required
from flask import session
from Models.user import User
from Models.notification import Notification as NotifModel
from Models.revocation_list import RevocationList

class Notification(Resource):

    parser = reqparse.RequestParser()
    parser.add_argument('data',
        type=str,
        required=False,
        help="Notification url to delete."
    )

    @login_required
    def get(self, username):
        if not username==User.get_username_by_id(session["user_id"]):
            return {'message': "You may not access another user's notifications."}, 400
        notif = NotifModel.get_all_by_user(session["user_id"])
        if not notif or len(notif)<1:
            return {'message': "No notifications for this user."}, 404
        result = {'username': username}
        i = 0
        for n in notif:
            result.update(n.json(i))
            i+=1
        return result


    @login_required
    def delete(self, username):
        if not username==User.get_username_by_id(session["user_id"]):
            return {'message': "You may not access another user's notifications."}, 400
        data = self.parser.parse_args()
        if not data['data']:
            NotifModel.delete(user_id=session["user_id"])
        else:
            NotifModel.delete(user_id=session["user_id"], data=data['data'])
        return {'message': "Deleted notifications for user {}".format(username)}
