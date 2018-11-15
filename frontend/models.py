from frontend import db, login_manager
from flask_login import UserMixin
from flask import current_app


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    name = db.Column(db.String(127))
    email = db.Column(db.String(127))
    gt_id = db.Column(db.Integer)
    auth_token = db.Column(db.String(127))

    def __init__(self, id, name, email, gt_id, auth_token):
        self.user_id = id
        self.name = name
        self.email = email
        self.gt_id = gt_id
        self.auth_token = auth_token
