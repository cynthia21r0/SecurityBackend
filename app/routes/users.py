from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db, bcrypt
from app.models.user import User, Role, AuditLog
from app.utils.decorators import role_required

users_bp = Blueprint("users", __name__)

@users_bp.route("/", methods=["GET"])
@jwt_required()
@role_required("admin", "manager")
def list_users():
    users = User.query.all()
    return jsonify([u.to_dict() for u in users]), 200

@users_bp.route("/<int:user_id>", methods=["GET"])
@jwt_required()
@role_required("admin", "manager")
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict()), 200

@users_bp.route("/<int:user_id>/role", methods=["PUT"])
@jwt_required()
@role_required("admin")
def assign_role(user_id):
    user      = User.query.get_or_404(user_id)
    data      = request.get_json()
    role_name = data.get("role")
    role      = Role.query.filter_by(name=role_name).first()
    if not role:
        return jsonify({"error": f"Rol '{role_name}' no existe"}), 404

    caller_id = get_jwt_identity()
    if role not in user.roles:
        user.roles.append(role)
        db.session.commit()
        log = AuditLog(user_id=caller_id, action="ASSIGN_ROLE",
                       resource="users", details=f"Rol {role_name} → user {user_id}",
                       ip_address=request.remote_addr)
        db.session.add(log)
        db.session.commit()

    return jsonify(user.to_dict()), 200

@users_bp.route("/<int:user_id>/deactivate", methods=["PUT"])
@jwt_required()
@role_required("admin")
def deactivate_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = False
    db.session.commit()
    return jsonify({"message": "Usuario desactivado"}), 200

@users_bp.route("/<int:user_id>/activate", methods=["PUT"])
@jwt_required()
@role_required("admin")
def activate_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = True
    db.session.commit()
    return jsonify({"message": "Usuario activado"}), 200

@users_bp.route("/audit-logs", methods=["GET"])
@jwt_required()
@role_required("admin")
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
    return jsonify([{
        "id":         l.id,
        "user_id":    l.user_id,
        "action":     l.action,
        "resource":   l.resource,
        "ip_address": l.ip_address,
        "details":    l.details,
        "created_at": l.created_at.isoformat()
    } for l in logs]), 200