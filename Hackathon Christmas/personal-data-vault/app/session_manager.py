from datetime import datetime, timedelta
from .models import Session, db
import jwt

class SessionManager:
    def __init__(self, app):
        self.app = app
        self.session_duration = timedelta(hours=1)
    
    def create_session(self, user_id, device_info=None):
        """Create new session"""
        expires_at = datetime.utcnow() + self.session_duration
        token = jwt.encode(
            {'user_id': user_id, 'exp': expires_at},
            self.app.config['JWT_SECRET_KEY']
        )
        
        session = Session(
            user_id=user_id,
            token=token,
            expires_at=expires_at,
            device_info=device_info
        )
        db.session.add(session)
        db.session.commit()
        return token
    
    def validate_session(self, token):
        """Validate session token"""
        session = Session.query.filter_by(token=token, is_active=True).first()
        if not session or session.expires_at < datetime.utcnow():
            return False
        return True
    
    def invalidate_session(self, token):
        """Invalidate session"""
        session = Session.query.filter_by(token=token).first()
        if session:
            session.is_active = False
            db.session.commit()
