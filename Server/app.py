from flask import Flask, session, escape, redirect, url_for#, request, jsonify, make_response
from flask_restful import Api
from flask_security import login_required
from security import user_datastore, getSecurity
from Resources.certificate import Certificate
from Resources.revocation_list import RevocationList
from Models.certificate import Certificate as cm
from Models.revocation import Revocation as rm

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

@app.route('/redir-test')
def hello():
    return redirect(url_for('foo'))

@app.route('/foo')
def foo():
    return 'Hello Foo!'

#Api Resources
api.add_resource(Certificate, '/certificate/<string:username>')
api.add_resource(RevocationList, '/revocation_list/<string:username>')

if __name__ == '__main__':
    from db import db
    db.init_app(app)
    app.run(debug=True)
