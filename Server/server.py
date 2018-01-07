from flask import Flask, session#, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required
from flask_security.forms import RegisterForm, LoginForm
from wtforms import StringField, validators

app = Flask(__name__)

app.config['SECRET_KEY'] = '!ThisShouldBeRandom_123456$%)(#X^'
app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha512'
app.config['SECURITY_PASSWORD_SALT'] = '!ThisShouldBeRandom_123456$%)(#X^'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://flask-server:test123@localhost/flaskserver'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_USER_IDENTITY_ATTRIBUTES'] = ('username', 'email')
app.debug = True

db = SQLAlchemy(app)
db.init_app(app)

# Define models
roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    username = db.Column(db.String(255), unique=True, index=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

    def get_security_payload(self):
        return {
            'username': self.username,
            'email' : self.email,
            'id' : self.id
        }

class ExtendedRegisterForm(RegisterForm):
    username = StringField('Username', [validators.Required()])
class ExtendedLoginForm(LoginForm):
    email = StringField('Username or Email', [validators.Required()])


db.create_all()
db.session.commit()

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore, register_form=ExtendedRegisterForm, login_form=ExtendedLoginForm)

@app.route('/')
#@login_required
def index():
    try:
        return user_datastore.get_user(session["user_id"]).get_security_payload()['username']
    except:
        return "something did not work. logged in?"


if __name__ == '__main__':
    app.run()
