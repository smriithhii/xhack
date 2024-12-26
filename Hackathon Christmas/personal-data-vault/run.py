from app import create_app, db
from app.models import User, SensitiveFile, Password, AuditLog, FileVersion, MFAToken, Session
import logging

app = create_app()

# Create tables before running the app
with app.app_context():
    db.drop_all()
    db.create_all()
    print("Database tables created!")

logging.basicConfig(level=logging.DEBUG)

if __name__ == "__main__":
    app.run(debug=True)
    