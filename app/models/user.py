from app import db
from datetime import datetime

# Tabla de asociación N:M
user_roles = db.Table("user_roles",
    db.Column("user_id", db.Integer, db.ForeignKey("users.id"),  primary_key=True),
    db.Column("role_id", db.Integer, db.ForeignKey("roles.id"),  primary_key=True),
    db.Column("assigned_at", db.DateTime, default=datetime.utcnow)
)

class Role(db.Model):
    __tablename__ = "roles"
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {"id": self.id, "name": self.name, "description": self.description}

class User(db.Model):
    __tablename__ = "users"
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    is_active     = db.Column(db.Boolean, default=True)
    reset_token   = db.Column(db.String(255))
    reset_token_expires = db.Column(db.DateTime)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at    = db.Column(db.DateTime, default=datetime.utcnow,
                              onupdate=datetime.utcnow)
    roles = db.relationship("Role", secondary=user_roles,
                            backref=db.backref("users", lazy="dynamic"))

    def to_dict(self):
        return {
            "id":         self.id,
            "username":   self.username,
            "email":      self.email,
            "is_active":  self.is_active,
            "roles":      [r.to_dict() for r in self.roles],
            "created_at": self.created_at.isoformat()
        }

class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"))
    action     = db.Column(db.String(100), nullable=False)
    resource   = db.Column(db.String(100))
    ip_address = db.Column(db.String(45))
    details    = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)