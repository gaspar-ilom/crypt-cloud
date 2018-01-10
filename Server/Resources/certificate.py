from flask_restful import Resource, reqparse
from flask_security import login_required
from Models.user import User

class Certificate(Resource):

    parser = reqparse.RequestParser()
    parser.add_argument('username',
        type=str,
        required=True,
        help="The most recent certificate of the user!"
    )
    parser.add_argument('username',
        type=str,
        required=False,
        help="The most recent certificate of the user!"
    )

    @login_required
    def get(self, username):
        user = User.find_by_name(username)
        if not user:
            return {'message': "Username '{}' does not exist.".format(username)}, 400



    # def retrieveCert(username):
    #     cert = None
    #     if not userExists(username):
    #         return cert
    #
    #     stmt = ("SELECT cert_data, expiry FROM certificates WHERE username=%s AND revoked=0 AND expiry>=%s ORDER BY expiry DESC")
    #     cnx = mysql.connector.connect(user=DB_USER, password=DB_PASSWORD, host=DB_HOST, database=DB_NAME)
    #     cur = cnx.cursor()
    #     cur.execute(stmt, [username, str(datetime.datetime.utcnow().date())])
    #     try:
    #         cert = cur.fetchone()[0]
    #     except TypeError:
    #         cnx.close()
    #         return cert
    #     cnx.close()
    #     return cert

    @login_required
    def post(self, username):
        pass

    @login_required
    def put(self, username):
        pass

    @login_required
    def delete(self, username):
        pass
