from flask_restful import Resource
from flask_security import login_required
from Models.user import User
from Models.revocation_list import RevocationList as RevList
from Models.certificate import Certificate as CertModel

class SMP(Resource):

    @login_required
    def get(self, initiator, replier, step):
        init = User.find_by_name(initiator)
        rep  = User.find_by_name(replier)
        if not init:
            return {'message': "Username '{}' does not exist.".format(initiator)}, 404
        if not rep:
            return {'message': "Username '{}' does not exist.".format(replier)}, 404
        if not User.get_username_by_id(session["user_id"]) in [initiator, replier]:
            return {'message': "You may not access other users' SMP data."}, 400
        if not init.active:
            return {'message': "User '{}' is not logged in.".format(initiator)}, 404
        if not rep.active:
            return {'message': "User '{}' is not logged in.".format(replier)}, 404

        #TODO actual stuff

    @login_required
    def delete(self, initiator, replier, step):
        return ''

    def validate_request(self, initiator, replier, step):
        pass
