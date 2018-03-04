from flask_restful import Resource, reqparse
from flask_security import login_required
from flask import session
from Models.user import User
from Models.data import Data
from Models.joins import Data_Access

class Data_List(Resource):

    @login_required
    def get(self, username):
        if not username==User.get_username_by_id(session["user_id"]):
            return {'message': "You may not access another user's data."}, 400
        owner = {}
        d = Data.get_all_by_user(user_id=session["user_id"])
        if d:
            for item in d:
                owner.update({str(item.id): "/data/{}/{}".format(username, item.name)})
        shared = {}
        d = Data_Access.get(user_id=session["user_id"])
        if d:
            for item in d:
                shared.update({str(item.data.id): "/data/{}/{}".format(item.data.user.username, item.data.name)})
        return {'owner': owner, 'shared': shared}
