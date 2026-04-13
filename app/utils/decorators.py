from functools import wraps
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from flask import jsonify
from app.models.user import User

def role_required(*roles):
    """Decorador que verifica que el usuario tenga al menos uno de los roles."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user    = User.query.get(user_id)
            if not user or not user.is_active:
                return jsonify({"error": "Usuario no encontrado o inactivo"}), 403
            user_role_names = [r.name for r in user.roles]
            if not any(r in user_role_names for r in roles):
                return jsonify({"error": "Permisos insuficientes"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator