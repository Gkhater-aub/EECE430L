from extensions import db, ma
from marshmallow import fields
import datetime

class Transaction(db.Model):
    __tablename__ = "transactions"

    def __init__(self, usd_amount, lbp_amount, usd_to_lbp, user_id):
        super(Transaction, self).__init__(
            usd_amount=usd_amount,
            lbp_amount=lbp_amount,
            usd_to_lbp=usd_to_lbp,
            user_id=user_id,
            added_date=datetime.datetime.now(),
        )

    id = db.Column(db.Integer, primary_key=True)
    usd_amount = db.Column(db.Float, nullable=False)
    lbp_amount = db.Column(db.Float, nullable=False)
    usd_to_lbp = db.Column(db.Boolean, nullable=False)
    added_date = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)


class TransactionSchema(ma.Schema):
    id = fields.Int()
    usd_amount = fields.Float()
    lbp_amount = fields.Float()
    usd_to_lbp = fields.Bool()
    user_id = fields.Int(allow_none=True)
    added_date = fields.DateTime()

transaction_schema = TransactionSchema()
transaction_list_schema = TransactionSchema(many=True)
