from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt

# Shared Flask extensions instantiated without an app to avoid circular imports.
db = SQLAlchemy()
ma = Marshmallow()
bcrypt = Bcrypt()
