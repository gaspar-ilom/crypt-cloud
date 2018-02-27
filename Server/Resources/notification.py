from flask_restful import Resource, reqparse
from flask_security import login_required
from flask import session
from Models.user import User
from Models.notification import Notification as NotifModel
from Models.revocation_list import RevocationList

class Notification(Resource):

    @login_required
    def get(self, username):
        if not username==User.get_username_by_id(session["user_id"]):
            return {'message': "You may not access another user's notifications."}, 400

        notif = NotifModel.get_all_by_user(session["user_id"])
        if not notif or len(notif)<1:
            return {'message': "No notifications for this user."}, 404
        return notif
