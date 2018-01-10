from flask_security import Security, SQLAlchemyUserDatastore
from Models.role import Role
from Models.user import User
from flask_security.forms import RegisterForm, LoginForm
from wtforms import StringField, validators
from db import db

class ExtendedRegisterForm(RegisterForm):
    username = StringField('Username', [validators.Required()])
class ExtendedLoginForm(LoginForm):
    email = StringField('Username or Email', [validators.Required()])


# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
_security = None
def getSecurity(app):
    global _security
    if not _security:
        _security = Security(app, user_datastore, register_form=ExtendedRegisterForm, login_form=ExtendedLoginForm)
    return _security
