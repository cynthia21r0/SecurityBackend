from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import re
from app import db, bcrypt
from app.models.user import User, Role, AuditLog
from app.utils.decorators import role_required
import csv
import io
from flask import Response

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

# ─── Perfil propio ────────────────────────────────────────────

@users_bp.route("/me", methods=["GET"])
@jwt_required()
def get_my_profile():
    user_id = int(get_jwt_identity())
    user    = User.query.get_or_404(user_id)
    return jsonify(user.to_dict()), 200


@users_bp.route("/me", methods=["PUT"])
@jwt_required()
def update_my_profile():
    user_id = int(get_jwt_identity())
    user    = User.query.get_or_404(user_id)
    data    = request.get_json()

    new_username = data.get("username", "").strip()
    new_email    = data.get("email", "").strip().lower()

    if not new_username or not new_email:
        return jsonify({"error": "Username y email son requeridos"}), 400

    if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
        return jsonify({"error": "Email inválido"}), 400

    # Verificar duplicados excluyendo al usuario actual
    if new_username != user.username:
        if User.query.filter_by(username=new_username).first():
            return jsonify({"error": "Username ya en uso"}), 409

    if new_email != user.email:
        if User.query.filter_by(email=new_email).first():
            return jsonify({"error": "Email ya registrado"}), 409

    user.username = new_username
    user.email    = new_email
    db.session.commit()

    log = AuditLog(user_id=user_id, action="UPDATE_PROFILE",
                   resource="users", details="Perfil actualizado",
                   ip_address=request.remote_addr)
    db.session.add(log)
    db.session.commit()

    return jsonify(user.to_dict()), 200


@users_bp.route("/me/password", methods=["PUT"])
@jwt_required()
def change_my_password():
    user_id = int(get_jwt_identity())
    user    = User.query.get_or_404(user_id)
    data    = request.get_json()

    current  = data.get("current_password", "")
    new_pwd  = data.get("new_password", "")
    confirm  = data.get("confirm_password", "")

    if not bcrypt.check_password_hash(user.password_hash, current):
        return jsonify({"error": "Contraseña actual incorrecta"}), 400

    if new_pwd != confirm:
        return jsonify({"error": "Las contraseñas no coinciden"}), 400

    if len(new_pwd) < 8 or not re.search(r"[A-Z]", new_pwd) or not re.search(r"\d", new_pwd):
        return jsonify({"error": "Contraseña débil: mínimo 8 caracteres, 1 mayúscula, 1 número"}), 400

    user.password_hash = bcrypt.generate_password_hash(new_pwd).decode("utf-8")
    db.session.commit()

    log = AuditLog(user_id=user_id, action="PASSWORD_CHANGE",
                   resource="users", details="Contraseña cambiada",
                   ip_address=request.remote_addr)
    db.session.add(log)
    db.session.commit()

    return jsonify({"message": "Contraseña actualizada correctamente"}), 200


@users_bp.route("/me/activity", methods=["GET"])
@jwt_required()
def my_activity():
    user_id = int(get_jwt_identity())
    logs    = AuditLog.query.filter_by(user_id=user_id)\
                            .order_by(AuditLog.created_at.desc())\
                            .limit(50).all()
    return jsonify([{
        "id":         l.id,
        "action":     l.action,
        "resource":   l.resource,
        "ip_address": l.ip_address,
        "details":    l.details,
        "created_at": l.created_at.isoformat()
    } for l in logs]), 200

# ─── Estadísticas para manager ───────────────────────────────

@users_bp.route("/stats", methods=["GET"])
@jwt_required()
@role_required("admin", "manager")
def get_stats():
    from sqlalchemy import func
    from datetime import datetime, timedelta

    total    = User.query.count()
    active   = User.query.filter_by(is_active=True).count()
    inactive = total - active

    # Usuarios nuevos últimos 7 días
    week_ago  = datetime.utcnow() - timedelta(days=7)
    new_users = User.query.filter(User.created_at >= week_ago).count()

    # Acciones más frecuentes (últimos 100 logs)
    top_actions = db.session.query(
        AuditLog.action,
        func.count(AuditLog.action).label("count")
    ).group_by(AuditLog.action)\
     .order_by(func.count(AuditLog.action).desc())\
     .limit(5).all()

    return jsonify({
        "total":      total,
        "active":     active,
        "inactive":   inactive,
        "new_users":  new_users,
        "top_actions": [{"action": a, "count": c} for a, c in top_actions]
    }), 200


# ─── Logs filtrados para manager ─────────────────────────────

@users_bp.route("/audit-logs/filter", methods=["GET"])
@jwt_required()
@role_required("admin", "manager")
def filter_audit_logs():
    action     = request.args.get("action", "").upper()
    resource   = request.args.get("resource", "")
    date_from  = request.args.get("date_from", "")
    date_to    = request.args.get("date_to", "")
    limit      = int(request.args.get("limit", 100))

    query = AuditLog.query

    if action:
        query = query.filter(AuditLog.action == action)
    if resource:
        query = query.filter(AuditLog.resource.ilike(f"%{resource}%"))
    if date_from:
        try:
            query = query.filter(
                AuditLog.created_at >= datetime.fromisoformat(date_from)
            )
        except ValueError:
            pass
    if date_to:
        try:
            query = query.filter(
                AuditLog.created_at <= datetime.fromisoformat(date_to)
            )
        except ValueError:
            pass

    logs = query.order_by(AuditLog.created_at.desc()).limit(limit).all()

    return jsonify([{
        "id":         l.id,
        "user_id":    l.user_id,
        "action":     l.action,
        "resource":   l.resource,
        "ip_address": l.ip_address,
        "details":    l.details,
        "created_at": l.created_at.isoformat()
    } for l in logs]), 200


# ─── Exportar usuarios CSV ────────────────────────────────────

@users_bp.route("/export/csv", methods=["GET"])
@jwt_required()
@role_required("admin", "manager")
def export_users_csv():
    users  = User.query.all()
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["ID", "Username", "Email", "Activo", "Roles", "Creado"])
    for u in users:
        writer.writerow([
            u.id,
            u.username,
            u.email,
            "Sí" if u.is_active else "No",
            ", ".join(r.name for r in u.roles),
            u.created_at.strftime("%d/%m/%Y %H:%M")
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=usuarios.csv"}
    )


# ─── Exportar logs CSV ────────────────────────────────────────

@users_bp.route("/export/logs-csv", methods=["GET"])
@jwt_required()
@role_required("admin", "manager")
def export_logs_csv():
    from datetime import datetime
    logs   = AuditLog.query.order_by(AuditLog.created_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["ID", "Usuario ID", "Acción", "Recurso", "IP", "Detalles", "Fecha"])
    for l in logs:
        writer.writerow([
            l.id,
            l.user_id  or "—",
            l.action,
            l.resource or "—",
            l.ip_address or "—",
            l.details  or "—",
            l.created_at.strftime("%d/%m/%Y %H:%M")
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=logs.csv"}
    )