from flask_restful import Resource
from flask_security import login_required
from Models.user import User
from Models.revocation_list import RevocationList as RevList
from Models.certificate import Certificate as CertModel

class RevocationList(Resource):

    @login_required
    def get(self, username):
        user = User.find_by_name(username)
        if not user:
            return {'message': "Username '{}' does not exist.".format(username)}, 404
        # revocation list is always freshly created, when requested by client
        certs = CertModel.get_all_invalid_by_user(user=user)
        if not certs:
            return {'message': "No revoked certificate for this user."}, 404
        certs = list(certs)
        return RevList(username, certs).json()
