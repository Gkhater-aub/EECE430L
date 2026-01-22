from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

load_dotenv()

DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
SECRET_KEY = os.getenv("SECRET_KEY")

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

limiter = Limiter(app, key_func=get_remote_address)

class Transaction(db.Model):
    __tablename__ = "transactions"
    id = db.Column(db.Integer, primary_key=True)
    usd_amount = db.Column(db.Float, nullable=False)
    lbp_amount = db.Column(db.Float, nullable=False)
    usd_to_lbp = db.Column(db.Boolean, nullable=False)

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

    tx = Transaction(usd_amount=usd_amount, lbp_amount=lbp_amount, usd_to_lbp=usd_to_lbp)
    db.session.add(tx)
    db.session.commit()

    return jsonify({"message": "Transaction created", "id": tx.id}), 201

@app.route("/exchangeRate", methods=["GET"])
def exchange_rate():
    usd_to_lbp_txs = Transaction.query.filter_by(usd_to_lbp=True).all()
    lbp_to_usd_txs = Transaction.query.filter_by(usd_to_lbp=False).all()

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

    if len(usd_to_lbp_rates) > 0:
        avg_usd_to_lbp = sum(usd_to_lbp_rates) / len(usd_to_lbp_rates)
    else:
        avg_usd_to_lbp = None

    if len(lbp_to_usd_rates) > 0:
        avg_lbp_to_usd = sum(lbp_to_usd_rates) / len(lbp_to_usd_rates)
    else:
        avg_lbp_to_usd = None

    return jsonify({
        "usd_to_lbp": avg_usd_to_lbp,
        "lbp_to_usd": avg_lbp_to_usd
    })

if __name__ == "__main__":
    app.run(debug=False)
