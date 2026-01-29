from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_marshmallow import Marshmallow
from marshmallow import fields 
from flask_bcrypt import Bcrypt
from flask import abort
import jwt
import os
import datetime 

load_dotenv()

DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
SECRET_KEY = os.getenv("SECRET_KEY")
print("SECRET_KEY set?", bool(SECRET_KEY))

app = Flask(__name__)
ma = Marshmallow(app) 
bcrypt = Bcrypt(app) 

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

limiter = Limiter(app = app, key_func=get_remote_address)

class Transaction(db.Model):
    def __init__(self, usd_amount, lbp_amount, usd_to_lbp, user_id):
        super(Transaction, self).__init__(usd_amount=usd_amount, lbp_amount=lbp_amount, usd_to_lbp=usd_to_lbp, 
            user_id = user_id, added_date = datetime.datetime.now())
    __tablename__ = "transactions"
    id = db.Column(db.Integer, primary_key=True)
    usd_amount = db.Column(db.Float, nullable=False)
    lbp_amount = db.Column(db.Float, nullable=False)
    usd_to_lbp = db.Column(db.Boolean, nullable=False)
    added_date = db.Column(db.DateTime, nullable  =False) 
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable = True)

class TransactionSchema(ma.Schema):
    id = fields.Int()
    usd_amount = fields.Float()
    lbp_amount = fields.Float()
    usd_to_lbp = fields.Bool()
    user_id = fields.Int(allow_none=True)
    added_date = fields.DateTime()

transaction_schema = TransactionSchema()
transaction_list_schema = TransactionSchema(many=True)

class User(db.Model):
    def __init__(self, user_name, password): 
        super(User, self).__init__(user_name = user_name) 
        self.hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(30), unique=True)
    hashed_password = db.Column(db.String(128))

class UserSchema(ma.Schema):
    id = fields.Int()
    user_name = fields.Str()

user_schema = UserSchema() 

def extract_auth_token(authenticated_request):
    auth_header = authenticated_request.headers.get('Authorization')
    if auth_header:
        token = auth_header.split(" ")[1]
        return token.strip()
    else:
        return None

def decode_token(token):
    payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    print("decoded payload: ", payload)
    return int(payload['sub'])

@app.route("/transaction", methods=["POST"])
@limiter.limit("10 per minute")
def add_transaction():

    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    try:
        usd_amount = float(data.get("usd_amount"))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid usd_amount"}), 400
    if usd_amount <= 0:
        return jsonify({"error": "Invalid amount"}), 400

    try:
        lbp_amount = float(data.get("lbp_amount"))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid lbp_amount"}), 400
    if lbp_amount <= 0:
        return jsonify({"error": "Invalid amount"}), 400

    usd_to_lbp = data.get("usd_to_lbp")
    if type(usd_to_lbp) is not bool:
        return jsonify({"error": "Invalid usd_to_lbp"}), 400
    token = extract_auth_token(request)
    if token is None: 
        tx = Transaction(usd_amount=usd_amount, lbp_amount=lbp_amount, usd_to_lbp=usd_to_lbp, user_id=None)
    else: 
        try: 
            user_id = decode_token(token) 
            
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            abort(403) 
        tx = Transaction(usd_amount=usd_amount, lbp_amount=lbp_amount, usd_to_lbp=usd_to_lbp, user_id=user_id)

    db.session.add(tx)
    db.session.commit()

    return jsonify(transaction_schema.dump(tx)), 201

@app.route("/transaction", methods=["GET"])
@limiter.limit("10 per minute")
def get_transactions():
    token = extract_auth_token(request)
    print("extracted token:", token)
    if token is None:
        abort(403)

    try:
        user_id = decode_token(token)
        print("decoded user id:", user_id)
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        abort(403)

    txs = Transaction.query.filter_by(user_id=user_id).all()
    return jsonify(transaction_list_schema.dump(txs)), 200

@app.route("/user", methods=["POST"])
@limiter.limit("10 per minute")
def add_user():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    user_name = data.get("user_name")
    password = data.get("password")

    if not isinstance(user_name, str) or not user_name.strip():
        return jsonify({"error": "Invalid user_name"}), 400

    if not isinstance(password, str) or not password:
        return jsonify({"error": "Invalid password"}), 400

    user = User(user_name=user_name.strip(), password=password)
    db.session.add(user)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "User already exists"}), 409

    return jsonify(user_schema.dump(user)), 201

def create_token(user_id):
    payload = {
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=4),
        "iat": datetime.datetime.utcnow(),
        "sub": str(user_id)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

@app.route("/authentication", methods=["POST"])
@limiter.limit("10 per minute")
def authenticate():
    data = request.get_json()
    if not data:
        abort(400)

    user_name = data.get("user_name")
    password = data.get("password")

    if user_name is None or password is None:
        abort(400)

    user = User.query.filter_by(user_name=user_name).first()
    if user is None:
        abort(403)

    if not bcrypt.check_password_hash(user.hashed_password, password):
        abort(403)
    
    token = create_token(user.id) 
    return jsonify({"token": token}), 200

@app.route("/exchangeRate", methods=["GET"])
def exchange_rate():
    end_date = datetime.datetime.now()
    start_date = end_date - datetime.timedelta(hours=72)

    usd_to_lbp_txs = (
        Transaction.query
        .filter(
            Transaction.added_date.between(start_date, end_date),
            Transaction.usd_to_lbp == True
        )
        .all()
    )

    lbp_to_usd_txs = (
        Transaction.query
        .filter(
            Transaction.added_date.between(start_date, end_date),
            Transaction.usd_to_lbp == False
        )
        .all()
    )

    usd_to_lbp_rates = [
        tx.lbp_amount / tx.usd_amount
        for tx in usd_to_lbp_txs
        if tx.usd_amount != 0
    ]

    lbp_to_usd_rates = [
        tx.usd_amount / tx.lbp_amount
        for tx in lbp_to_usd_txs
        if tx.lbp_amount != 0
    ]

    avg_usd_to_lbp = (sum(usd_to_lbp_rates) / len(usd_to_lbp_rates)) if usd_to_lbp_rates else None
    avg_lbp_to_usd = (sum(lbp_to_usd_rates) / len(lbp_to_usd_rates)) if lbp_to_usd_rates else None

    return jsonify({
        "usd_to_lbp": avg_usd_to_lbp,
        "lbp_to_usd": avg_lbp_to_usd
    })

if __name__ == "__main__":
    with app.app_context(): 
        db.create_all()
    app.run(debug=False)
