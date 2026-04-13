from flask_mail import Message
from flask import current_app
from app import mail

def send_reset_email(to_email: str, username: str, reset_url: str):
    """Envía el correo de recuperación de contraseña."""
    subject = "SecureGate — Recuperación de contraseña"

    # Cuerpo en texto plano (fallback)
    body_text = f"""
Hola {username},

Recibimos una solicitud para restablecer la contraseña de tu cuenta en SecureGate.

Haz clic en el siguiente enlace para crear una nueva contraseña:
{reset_url}

Este enlace expira en 1 hora.

Si no solicitaste este cambio, ignora este correo. Tu contraseña no será modificada.

— Equipo SecureGate
"""

    # Cuerpo en HTML
    body_html = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body {{ font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 0; }}
    .container {{ max-width: 520px; margin: 40px auto; background: #ffffff;
                  border-radius: 8px; overflow: hidden;
                  box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
    .header {{ background: #1D9E75; padding: 32px; text-align: center; }}
    .header h1 {{ color: #ffffff; margin: 0; font-size: 24px; letter-spacing: 1px; }}
    .body {{ padding: 32px; color: #333333; }}
    .body p {{ line-height: 1.7; margin: 0 0 16px; }}
    .btn {{ display: inline-block; background: #1D9E75; color: #ffffff;
            text-decoration: none; padding: 14px 32px; border-radius: 6px;
            font-size: 15px; font-weight: bold; margin: 8px 0 24px; }}
    .warning {{ font-size: 13px; color: #888888; border-top: 1px solid #eeeeee;
                margin-top: 24px; padding-top: 16px; }}
    .footer {{ background: #f4f4f4; padding: 16px; text-align: center;
               font-size: 12px; color: #aaaaaa; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>SecureGate</h1>
    </div>
    <div class="body">
      <p>Hola <strong>{username}</strong>,</p>
      <p>Recibimos una solicitud para restablecer la contraseña de tu cuenta.</p>
      <p>Haz clic en el botón para crear una nueva contraseña:</p>
      <a href="{reset_url}" class="btn">Restablecer contraseña</a>
      <p>O copia este enlace en tu navegador:</p>
      <p style="word-break:break-all; font-size:13px; color:#555;">{reset_url}</p>
      <div class="warning">
        <p>⏱ Este enlace expira en <strong>1 hora</strong>.</p>
        <p>Si no solicitaste este cambio, puedes ignorar este correo con seguridad.</p>
      </div>
    </div>
    <div class="footer">
      Universidad Tecnológica del Norte de Guanajuato &mdash; SecureGate
    </div>
  </div>
</body>
</html>
"""

    msg = Message(
        subject=subject,
        recipients=[to_email],
        body=body_text,
        html=body_html
    )

    try:
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Error enviando correo a {to_email}: {e}")
        return False