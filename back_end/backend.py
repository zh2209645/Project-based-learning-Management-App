import os
import re
import json
import database as db
from datetime import datetime

from flask import Flask, g, jsonify, make_response, request
from flask_cors import CORS
from flask_httpauth import HTTPBasicAuth
# from flask_sqlalchemy import SQLAlchemy
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature, SignatureExpired
from passlib.apps import custom_app_context

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

CORS(app, resources=r'/*')
app.config['SECRET_KEY'] = 'hard to guess string'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_RECORD_QUERIES'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'data.sqlite')

auth = HTTPBasicAuth()
CSRF_ENABLED = True
app.debug = True


# -------------------------- start classes ---------------------
# --------------------------- user model -----------------------
class user:
    user_id = None
    __password = None
    name = None
    email = None
    photo = None

    def __init__(self, user_profile=None):
        if user_profile is not None:
            self.load_from_dict(user_profile)

    def load_from_dict(self, user_profile):
        self.user_id = user_profile["user_id"]
        self.__password = self.hash_password(
            user_profile.get("passwd", "None"))
        self.name = user_profile.get("name", self.user_id)
        self.email = user_profile.get("email", "None")
        self.photo = user_profile.get("photo", "None")

    def hash_password(self, password):
        self.password = custom_app_context.encrypt(password)

    def verify_password(self, password):
        return custom_app_context.verify(password, self.password)

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        if data["user_type"] != "admin":
            admin = admin_user(db.get_admin_user(data['id'])[0])
            return admin
        elif data["user_type"] != "student":
            student = student_user(db.get_student_user(data['id'])[0])
            return student


class admin_user(user):
    user_type = None

    def __init__(self, user_profile=None):
        user.__init__(self, user_profile)
        self.set_admin_type(user_profile.get("type", 0))

    def set_admin_type(self, user_type):
        self.user_type = user_type

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.user_id, 'user_type': "admin", 'type': self.user_type})


class student_user(user):
    mark = None

    def __init__(self, user_profile=None):
        user.__init__(self, user_profile)
        self.set_student_mark(user_profile.get("mark", "None"))

    def set_student_mark(self, mark):
        self.mark = mark

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.user_id, 'user_type': "student"})

# TODO
@auth.verify_password
def verify_password(name_or_token, password):
    if not name_or_token:
        return False
    name_or_token = re.sub(r'^"|"$', '', name_or_token)
    temp_user = user.verify_auth_token(name_or_token)
    if not temp_user:
        admin = admin_user(db.get_admin_user(name_or_token)[0])
        # if not admin or not admin.verify_password(password):
        #     return False
    g.user = admin
    return True


@app.route('/api/test', methods=['GET'])
def test():
    user_id = request.args.get("id")
    result = db.get_admin_user(user_id)
    test1 = admin_user(result[0])
    token1 = test1.generate_auth_token()
    print(token1)
    # print(admin_user.verify_auth_token('test2'))
    return jsonify(result[0])


@app.route('/api/test2', methods=['GET'])
@auth.login_required
def test2():
    return "Ture"


if __name__ == '__main__':
    app.run(host='0.0.0.0')
