from .models import AuditLog, db
from flask import request

class AuditLogger:
    @staticmethod
    def log_action(user_id, action, resource_type, resource_id=None):
        """Log user actions"""
        log = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
