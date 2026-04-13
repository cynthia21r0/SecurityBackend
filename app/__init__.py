from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_cors import CORS
from .config import Config

db    = SQLAlchemy()
bcrypt = Bcrypt()
jwt   = JWTManager()
mail  = Mail()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app, origins=["http://localhost:4200"], supports_credentials=True)

    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)

    from .routes.auth  import auth_bp
    from .routes.users import users_bp
    app.register_blueprint(auth_bp,  url_prefix="/api/auth")
    app.register_blueprint(users_bp, url_prefix="/api/users")

    with app.app_context():
        db.create_all()

    return app