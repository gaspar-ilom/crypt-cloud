from flask import Flask, session, escape
from flask_restful import Api
from security import user_datastore, getSecurity
from Resources.certificate import Certificate
from Resources.revocation_list import RevocationList
from Resources.smp import SMP
from Resources.notification import Notification
from Resources.data_list import Data_List
from Resources.data import Data
from Resources.private_key import Private_Key
from Models.certificate import Certificate as cm
from Models.revocation import Revocation as rm
from Models.notification import Notification as nm
from Models.data import Data as dm
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('tls_server_certificate.pem', 'tls_private_key.pem')


app = Flask(__name__)
app.config['SECRET_KEY'] = '!ThisShouldBeRandom_123456$%)(#X^'
app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha512'
app.config['SECURITY_PASSWORD_SALT'] = '!ThisShouldBeRandom_123456$%)(#X^'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://flask-server:test123@localhost/flaskserver'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False
app.config['SECURITY_USER_IDENTITY_ATTRIBUTES'] = ('username', 'email')

security = getSecurity(app)
api = Api(app)

@app.before_first_request
def create_tables():
    db.create_all()
    db.session.commit()

@app.route('/')
def index():
    # just testing login...
    try:
        return escape("Logged in as {}.".format(user_datastore.get_user(session["user_id"]).get_security_payload()['username']))
    except:
        return "Not logged in.", 401

#Api Resources
api.add_resource(Certificate, '/certificate/<string:username>')
api.add_resource(RevocationList, '/revocation_list/<string:username>')
api.add_resource(Notification, '/notification/<string:username>')
api.add_resource(SMP, '/smp/<string:initiator>_<string:replier>/<string:step>')
api.add_resource(Data_List, '/data/<string:username>')
api.add_resource(Data, '/data/<string:username>/<string:name>')
api.add_resource(Private_Key, '/private_key/<string:username>')

@api.representation('application/octet-stream')
def binary(data, code, headers=None):
    resp = api.make_response(data.data, code)
    resp.headers.extend(headers or {})
    return resp

if __name__ == '__main__':
    from db import db
    db.init_app(app)
    app.run(debug=True, ssl_context=context)
