from flask_restful import Resource, reqparse
from flask_security import login_required
from flask import session
from Models.user import User
from Models.certificate import Certificate as CertModel

class Certificate(Resource):

    parser = reqparse.RequestParser()
    parser.add_argument('csr',
        type=str,
        required=False,
        help="Certificate Request Data in PEM Encoding!"
    )

    @login_required
    def get(self, username):
        user = User.find_by_name(username)
        if not user:
            return {'message': "Username '{}' does not exist.".format(username)}, 404
        cert = CertModel.get_by_user(user=user)
        if not cert:
            return {'message': "No valid certificate for this user."}, 404
        return cert.json()

    @login_required
    def post(self, username):
        if not username==User.get_username_by_id(session["user_id"]):
            return {'message': "You may not update another user's certificate."}, 400
        data = self.parser.parse_args()
        if not data['csr']:
            return {'message': "No certificate Signing Request in Body."}, 400
        cert = CertModel.create(data['csr'], User.find_by_name(username).id)
        if not cert:
            return {'message': "Signature in CSR could not be verified or invalid CSR data!"}, 400
        cert.save_to_db()
        return cert.json()


    @login_required
    def put(self, username):
        pass

    @login_required
    def delete(self, username):
        pass
