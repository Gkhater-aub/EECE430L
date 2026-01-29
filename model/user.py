from extensions import db, ma, bcrypt
from marshmallow import fields

class User(db.Model):
    __tablename__ = "user"

    def __init__(self, user_name, password):
        super(User, self).__init__(user_name=user_name)
        self.hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(30), unique=True)
    hashed_password = db.Column(db.String(128))


class UserSchema(ma.Schema):
    id = fields.Int()
    user_name = fields.Str()

user_schema = UserSchema()
