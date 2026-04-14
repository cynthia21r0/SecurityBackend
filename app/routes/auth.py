from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                 jwt_required, get_jwt_identity)
from app import db, bcrypt
from app.models.user import User, Role, AuditLog
import secrets, re
from datetime import datetime, timedelta
from app.utils.email import send_reset_email

auth_bp = Blueprint("auth", __name__)

def log_action(user_id, action, resource=None, details=None):
    log = AuditLog(user_id=user_id, action=action, resource=resource,
                   ip_address=request.remote_addr, details=details)
    db.session.add(log)
    db.session.commit()

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    print("DATA RECIBIDA:", data)
    required = ["username", "email", "password"]
    if not all(k in data for k in required):
        return jsonify({"error": "Campos requeridos: username, email, password"}), 400

    # Validar email
    if not re.match(r"[^@]+@[^@]+\.[^@]+", data["email"]):
        return jsonify({"error": "Email inválido"}), 400

    # Validar contraseña (mín 8 chars, 1 mayús, 1 número)
    pwd = data["password"]
    if len(pwd) < 8 or not re.search(r"[A-Z]", pwd) or not re.search(r"\d", pwd):
        return jsonify({"error": "Contraseña débil: mínimo 8 caracteres, 1 mayúscula, 1 número"}), 400

    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email ya registrado"}), 409
    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "Username ya en uso"}), 409

    hashed = bcrypt.generate_password_hash(pwd).decode("utf-8")
    user   = User(username=data["username"], email=data["email"], password_hash=hashed)

    # Asignar rol "user" por defecto
    default_role = Role.query.filter_by(name="user").first()
    if default_role:
        user.roles.append(default_role)

    db.session.add(user)
    db.session.commit()
    log_action(user.id, "REGISTER", "users", f"Nuevo usuario: {user.username}")

    return jsonify({"message": "Usuario registrado correctamente", "user": user.to_dict()}), 201

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or not data.get("email") or not data.get("password"):
        return jsonify({"error": "Email y contraseña requeridos"}), 400

    user = User.query.filter_by(email=data["email"]).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, data["password"]):
        return jsonify({"error": "Credenciales inválidas"}), 401
    if not user.is_active:
        return jsonify({"error": "Cuenta desactivada"}), 403

    access_token  = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    
    log_action(user.id, "LOGIN", "auth", "Inicio de sesión exitoso")

    return jsonify({
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "user":          user.to_dict()
    }), 200

@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity     = get_jwt_identity()
    access_token = create_access_token(identity=str(identity))
    return jsonify({"access_token": access_token}), 200

@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    data  = request.get_json()
    email = data.get("email", "").strip().lower()

    if not email:
        return jsonify({"error": "Email requerido"}), 400

    user = User.query.filter_by(email=email).first()

    if user:
        # Generar token seguro
        token   = secrets.token_urlsafe(32)
        expires = datetime.utcnow() + timedelta(hours=1)

        user.reset_token         = token
        user.reset_token_expires = expires
        db.session.commit()

        reset_url = f"{current_app.config['FRONTEND_URL']}/reset-password?token={token}"

        # Enviar correo real
        sent = send_reset_email(
            to_email=user.email,
            username=user.username,
            reset_url=reset_url
        )

        log_action(user.id, "PASSWORD_RESET_REQUEST", "auth",
                   f"Correo {'enviado' if sent else 'FALLO'} a {user.email}")

        if not sent:
            return jsonify({
                "error": "No se pudo enviar el correo. Verifica la configuración SMTP."
            }), 500

    # Siempre responder igual para no revelar si el email existe
    return jsonify({
        "message": "Si el email está registrado, recibirás un enlace en tu correo."
    }), 200

@auth_bp.route("/reset-password", methods=["POST"])
def reset_password():
    data  = request.get_json()
    token = data.get("token")
    pwd   = data.get("new_password")

    user = User.query.filter_by(reset_token=token).first()
    if not user or not user.reset_token_expires or \
       user.reset_token_expires < datetime.utcnow():
        return jsonify({"error": "Token inválido o expirado"}), 400

    if len(pwd) < 8 or not re.search(r"[A-Z]", pwd) or not re.search(r"\d", pwd):
        return jsonify({"error": "Contraseña débil"}), 400

    user.password_hash       = bcrypt.generate_password_hash(pwd).decode("utf-8")
    user.reset_token         = None
    user.reset_token_expires = None
    db.session.commit()
    log_action(user.id, "PASSWORD_RESET", "auth")

    return jsonify({"message": "Contraseña actualizada correctamente"}), 200

@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    user_id = int(get_jwt_identity())
    user    = User.query.get_or_404(user_id)
    return jsonify(user.to_dict()), 200