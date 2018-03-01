from flask_restful import Resource, reqparse
from flask_security import login_required
from flask import session
from Models.user import User
from Models.smp import SMP as SMPModel
from Models.notification import Notification

class SMP(Resource):
    steps = ['question','step1', 'step2','step3','step4']
    parser = reqparse.RequestParser()
    parser.add_argument('question',
        type=str,
        required=False,
        help="Question for SMP initiation."
    )
    parser.add_argument('data',
        type=str,
        required=False,
        help="Base64 encoded data for SMP, depending on the SMP step."
    )

    @login_required
    def get(self, initiator, replier, step):
        valid = self.validate_request(initiator, replier, step, 'get')
        if not valid[0] == True:
            return  valid
        init = valid[1]
        rep = valid[2]
        answer = SMPModel.get_by_users(init, rep)
        if not answer:
            return {'message': "The SMP has not yet been initiated. Resource not available."}, 404
        if step == 'question':
            return answer.json()
        for i in range(5):
            if step == self.steps[i]:
                data = answer.get_data_as_json(i)
                answer = answer.json()
                answer.update(data)
                return answer

    @login_required
    def post(self, initiator, replier, step):
        valid = self.validate_request(initiator, replier, step, 'post')
        if not valid[0] == True:
            return  valid
        init = valid[1]
        rep = valid[2]
        smp_object = SMPModel.get_by_users(init, rep)
        data = self.parser.parse_args()
        if not smp_object:
            if step == 'question' and data['question']:
                Notification.add("/smp/{}_{}/question".format(initiator, replier), rep.id)
                return SMPModel(init.id, rep.id, data['question']).save_to_db().json()
            return {'message': "You have to start the SMP by posting a question to /smp/{}_{}/question".format(initiator, replier)}, 400
        if not data['data']:
            return {'message': "You have to post data to the resource!"}, 400
        data = data['data']
        if step == 'question':
            return {'message': "The SMP has already been initiated. Continue with the next steps."}, 400
        for i in range(5):
            if step == self.steps[i]:
                answer = smp_object.update(i, data)
                if not answer:
                    return {'message': "The requested step resource does not exist in SMP or is not allowed to be modified at this phase of the protocol."}, 404
                return answer
        return {'message': "Illegal request."}, 404

    @login_required
    def delete(self, initiator, replier, step):
        valid = self.validate_request(initiator, replier, step, 'delete')
        if not valid[0] == True:
            return  valid
        init = valid[1]
        rep = valid[2]
        del_smp = SMPModel.get_by_users(init, rep)
        if del_smp:
            del_smp.delete_from_db()
        Notification.delete(user=rep, data="/smp/{}_{}/question".format(initiator, replier))
        return {'message': "Succesfully deleted remaining SMP data for {} and {}".format(initiator, replier)}

    def validate_request(self, initiator, replier, step, method):
        if not step in self.steps:
            return {'message': "Resource '{}' does not exist.".format(step)}, 404
        init = User.find_by_name(initiator)
        rep  = User.find_by_name(replier)
        if not init:
            return {'message': "Username '{}' does not exist.".format(initiator)}, 404
        if not rep:
            return {'message': "Username '{}' does not exist.".format(replier)}, 404
        username = User.get_username_by_id(session["user_id"])
        if not username in [initiator, replier]:
            return {'message': "You may not access other users' SMP data."}, 400
        if username == initiator and step not in ['question', 'step2', 'step4'] and not method == 'get':
            return {'message': "You may not access someone else's SMP data."}, 400
        if username == replier and step not in ['step1', 'step3'] and not method == 'get':
            return {'message': "You may not access someone else's SMP data."}, 400
        if not init.active:
            return {'message': "User '{}' is not logged in.".format(initiator)}, 404
        if not rep.active:
            return {'message': "User '{}' is not logged in.".format(replier)}, 404
        return True, init, rep
