from flask_restful import Resource, reqparse
from flask_security import login_required
from flask import session
from Models.user import User

class Private_Key(Resource):

    parser = reqparse.RequestParser()
    parser.add_argument('key',
        type=str,
        required=True,
        help="Private Key in PEM Encoding!"
    )

    @login_required
    def get(self, username):
        user = User.find_by_name(username)
        if not user:
            return {'message': "Username '{}' does not exist.".format(username)}, 404
        if not username==User.get_username_by_id(session["user_id"]):
            return {'message': "You may not access another user's private_key."}, 400
        return user.get_private_key()

    @login_required
    def post(self, username):
        user = User.find_by_name(username)
        if not user:
            return {'message': "Username '{}' does not exist.".format(username)}, 404
        if not username==User.get_username_by_id(session["user_id"]):
            return {'message': "You may not access another user's private_key."}, 400
        data = self.parser.parse_args()
        if not data['key']:
            return {'message': "No key in Body."}, 400
        user.set_private_key(data['key'])
        return user.get_private_key()

    @login_required
    def delete(self, username):
        user = User.find_by_name(username)
        if not user:
            return {'message': "Username '{}' does not exist.".format(username)}, 404
        if not username==User.get_username_by_id(session["user_id"]):
            return {'message': "You may not access another user's private_key."}, 400
        user.delete_private_key()
        return {'message': "Private Key succesfully deleted."}
