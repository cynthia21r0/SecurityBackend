import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY          = os.getenv("SECRET_KEY", "dev-secret")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY      = os.getenv("JWT_SECRET_KEY", "jwt-secret")
    JWT_ACCESS_TOKEN_EXPIRES  = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    MAIL_SERVER    = os.getenv("MAIL_SERVER")
    MAIL_PORT      = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS   = True
    MAIL_USERNAME  = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD  = os.getenv("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER")
    FRONTEND_URL   = os.getenv("FRONTEND_URL", "http://localhost:4200")