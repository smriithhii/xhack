from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_cors import CORS

db = SQLAlchemy()
jwt = JWTManager()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)
    CORS(app, resources={
        r"/*": {
        "origins": "http://localhost:3000",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
    })

    # Disable CSRF globally for the API
    app.config['WTF_CSRF_ENABLED'] = False

    Talisman(app, 
        force_https=False,
        strict_transport_security=True,
        session_cookie_secure=False,
        content_security_policy={
            'default-src': "'self'",
            'script-src': "'self' 'unsafe-inline'",
            'style-src': "'self' 'unsafe-inline'",
            'connect-src': "'self' http://localhost:5000"
        },
    )
    app.config.from_object('config.Config')
    
    db.init_app(app)
    jwt.init_app(app)
    
    with app.app_context():
        from . import routes
        app.register_blueprint(routes.bp)
        db.create_all()
    
    return app
