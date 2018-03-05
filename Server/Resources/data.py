from flask_restful import Resource, reqparse
from flask_security import login_required
from flask import session
from Models.user import User
from Models.data import Data as DModel
import werkzeug
# from flask import Response, request

class Data(Resource):

    parser = reqparse.RequestParser()
    parser.add_argument('shares',
        type=str,
        help="User to be shared with"
    )
    parser.add_argument('data',
        location='files',
        type=werkzeug.datastructures.FileStorage,
        required=False,
        help="File in Binary"
    )
    parser.add_argument('key',
        location='files',
        type=werkzeug.datastructures.FileStorage,
        required=False,
        help="Key in Binary"
    )

    @login_required
    def get(self, username, name):
        user = User.find_by_name(username)
        res = DModel.get_by_name_and_user(name, user=user)
        if not user:
            return {'message': "Username '{}' does not exist.".format(username)}, 404
        if not res:
            return {'message': "File '{}' does not exist at that location.".format(name)}, 404
        if not username==User.get_username_by_id(session["user_id"]):
            print(res.get_shares(session["user_id"]))
            if not User.get_username_by_id(session["user_id"]) in res.get_shares(session["user_id"]):
                return {'message': "You may not access another user's storage."}, 400
        return res.prepare_answer()

    @login_required
    def post(self, username, name):
        user = User.find_by_name(username)
        res = DModel.get_by_name_and_user(name, user=user)
        if not username==User.get_username_by_id(session["user_id"]):
            if not res:
                return {'message': "You may not upload data to another user's storage."}, 400
            if not User.get_username_by_id(session["user_id"]) in res.get_shares(session["user_id"]):
                return {'message': "You may not upload data to another user's storage."}, 400
        data = self.parser.parse_args()
        if data['data']:
            d = data['data'].read()
        else:
            d = None
        if data['key']:
            key = data['key'].read()
        else:
            key = None
        shares = data['shares']
        if shares:
            u = User.find_by_name(shares)
            if u:
                shares = u.id
            else:
                shares = None
        if res:
            res.update(name, user.id, key, d, shares)
            return res.prepare_answer()
        resp = DModel(name, user.id, key, d, shares).save_to_db()
        return resp.prepare_answer()

    @login_required
    def delete(self, username, name):
        user = User.find_by_name(username)
        res = DModel.get_by_name_and_user(name, user=user)
        if not user:
            return {'message': "Username '{}' does not exist.".format(username)}, 404
        if not res:
            return {'message': "File '{}' does not exist at that location.".format(name)}, 404
        if not username==User.get_username_by_id(session["user_id"]):
            if not User.get_username_by_id(session["user_id"]) in res.get_shares(session["user_id"]):
                return {'message': "You may not access another user's storage."}, 400
        data = self.parser.parse_args()
        if data['shares']:
                u = User.find_by_name(data['shares'])
                if u:
                    res.remove_share(u.id)
                    return {'message': "Revoked share for {}".format(data['shares'])}
                else:
                    return {'message': "User could not be found to revoke share."}, 404
        res.delete_from_db()
        return {'message': "Deleted file succesfully."}
