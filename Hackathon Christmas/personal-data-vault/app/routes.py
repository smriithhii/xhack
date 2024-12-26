from flask import Flask, Blueprint, request, jsonify, render_template, send_file, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from .models import db, User, SensitiveFile, Password, MFAToken
from .encryption_utils import encrypt_data, decrypt_data
from .auth import authenticate_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from .security import SecurityManager
from .session_manager import SessionManager
from .audit_logger import AuditLogger
from .breach_detection import BreachDetector
from werkzeug.utils import secure_filename

# Initialize the Flask app
app = Flask(__name__)

# Configure app (e.g., secret key, database URI, etc.)
app.config['SECRET_KEY'] = '6ef65243ea6f1b2999b99c7afcc6eb55f8c4584e0f76d3184d5a93810dd42444'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault.db'

# Initialize the db
db.init_app(app)

# Initialize the Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["200 per day", "50 per hour"]
)

security_manager = SecurityManager()
breach_detector = BreachDetector()

# Create the Blueprint
bp = Blueprint('api', __name__)

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@bp.route('/')
def index():
    return jsonify({"message": "Personal Data Vault API is running"})

@bp.route('/')
def serve_frontend():
    return render_template('index.html')

@bp.route('/register', methods=['POST'])
@limiter.limit("3 per minute")
def register():
    try:
        data = request.json
        app.logger.debug(f"Received registration data: {data}")

        if not data:
            return jsonify({"message": "No input data provided"}), 400
            
        if not data.get('username') or not data.get('password'):
            return jsonify({"message": "Username and password are required"}), 400
        
        # Check if user already exists
        existing_user = User.query.filter_by(username=data['username']).first()
        if existing_user:
            return jsonify({"message": "Username already exists"}), 400
            
        # Validate password complexity
        if not security_manager.validate_password(data['password']):
            return jsonify({
                "message": "Password must be at least 8 characters and contain letters, numbers, and special characters"
            }), 400
        
        # Check for breached password
        if breach_detector.check_password(data['password']):
            return jsonify({
                "message": "API issue while checking for breaches."
            }), 400
            
        hashed_password = generate_password_hash(data['password'])
        user = User(username=data['username'], password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        
        
        # Generate MFA secret
        mfa_token = MFAToken(
            user_id=user.id,
            secret_key=security_manager.generate_mfa_secret()
        )
        db.session.add(mfa_token)
        db.session.commit()
        
        # Convert QR code bytes to base64 string
        import base64
        qr_code = security_manager.generate_mfa_qr(user.username, mfa_token.secret_key)
        qr_code_b64 = base64.b64encode(qr_code).decode('utf-8')

        return jsonify({
            "message": "User registered successfully!",
            "mfa_qr": qr_code_b64
        }), 201
        
    except Exception as e:
        app.logger.error(f"Registration error: {str(e)}")
        print(f"Registration error: {str(e)}")  # For debugging
        db.session.rollback()
        return jsonify({"message": f"Registration failed: {str(e)}"}), 500
    
@bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.json
        user = authenticate_user(data['username'], data['password'])
        
        if not user:
            return jsonify({"message": "Invalid credentials"}), 401
            
        # Verify MFA token if enabled
        mfa_token = MFAToken.query.filter_by(user_id=user.id).first()
        if mfa_token and mfa_token.is_enabled:
            if 'mfa_code' not in data:
                return jsonify({"message": "MFA code required"}), 401
                
            if not security_manager.verify_mfa_token(mfa_token.secret_key, data['mfa_code']):
                return jsonify({"message": "Invalid MFA code"}), 401
        
        # Create session
        session_manager = SessionManager(current_app)
        token = session_manager.create_session(
            user.id,
            device_info={
                "user_agent": request.headers.get('User-Agent'),
                "ip": request.remote_addr
            }
        )
        
        # Log login
        AuditLogger.log_action(user.id, "login", "session")
        
        return jsonify({"token": token}), 200
        
    except Exception as e:
        return jsonify({"message": f"Login failed: {str(e)}"}), 500

@bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        token = request.headers.get('Authorization').split()[1]
        session_manager = SessionManager(current_app)
        session_manager.invalidate_session(token)
        
        user_id = get_jwt_identity()
        AuditLogger.log_action(user_id, "logout", "session")
        
        return jsonify({"message": "Logged out successfully"}), 200
    except Exception as e:
        return jsonify({"message": f"Logout failed: {str(e)}"}), 500
    
@bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400
    
    file = request.files['file']
    category = request.form.get('category', 'uncategorized')
    
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
        
    if file and allowed_file(file.filename):
        user_id = get_jwt_identity()
        filename = secure_filename(file.filename)
        
        # Create user-specific directory
        user_directory = os.path.join(UPLOAD_FOLDER, str(user_id))
        if not os.path.exists(user_directory):
            os.makedirs(user_directory)
            
        file_path = os.path.join(user_directory, filename)
        file.save(file_path)
        
        # Encrypt file content
        with open(file_path, 'rb') as f:
            file_content = f.read()
        encrypted_data = encrypt_data(file_content)
        
        # Save file info to database
        new_file = SensitiveFile(
            user_id=user_id,
            file_name=filename,
            category=category,
            encrypted_data=encrypted_data
        )
        db.session.add(new_file)
        db.session.commit()
        
        # Remove the temporary file
        os.remove(file_path)
        
        return jsonify({
            'message': 'File uploaded successfully',
            'id': new_file.id,
            'filename': filename,
            'category': category
        }), 201
    
    return jsonify({'message': 'File type not allowed'}), 400

@bp.route('/download/<int:file_id>', methods=['GET'])
@jwt_required()
def download_file(file_id):
    user_id = get_jwt_identity()
    file = SensitiveFile.query.filter_by(id=file_id, user_id=user_id).first()
    
    if not file:
        return jsonify({'message': 'File not found'}), 404
    
    # Decrypt file content
    decrypted_data = decrypt_data(file.encrypted_data)
    
    # Create temporary file
    temp_path = os.path.join(UPLOAD_FOLDER, secure_filename(file.file_name))
    with open(temp_path, 'wb') as f:
        f.write(decrypted_data)
    
    try:
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=file.file_name
        )
    finally:
        # Clean up temporary file
        os.remove(temp_path)

@bp.route('/files/<int:file_id>', methods=['DELETE'])
@jwt_required()
def delete_file(file_id):
    user_id = get_jwt_identity()
    file = SensitiveFile.query.filter_by(id=file_id, user_id=user_id).first()
    
    if not file:
        return jsonify({'message': 'File not found'}), 404
        
    db.session.delete(file)
    db.session.commit()
    
    return jsonify({'message': 'File deleted successfully'})

@bp.route('/files', methods=['GET'])
@jwt_required()
def list_files():
    user_id = get_jwt_identity()
    files = SensitiveFile.query.filter_by(user_id=user_id).all()
    return jsonify([{
        "id": file.id,
        "file_name": file.file_name,
        "category": file.category,
        "uploaded_at": file.uploaded_at
    } for file in files])

@bp.route('/files/<int:file_id>', methods=['GET'])
@jwt_required()
def get_file(file_id):
    user_id = get_jwt_identity()
    file = SensitiveFile.query.filter_by(user_id=user_id, id=file_id).first_or_404()
    decrypted_data = decrypt_data(file.encrypted_data)
    return jsonify({"file_name": file.file_name, "data": decrypted_data.decode('utf-8')})

@bp.route('/share', methods=['POST'])
@jwt_required()
def share_file():
    data = request.json
    user_id = get_jwt_identity()
    file_id = data['file_id']
    share_with = data['username']
    
    user = User.query.filter_by(username=share_with).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    file = SensitiveFile.query.filter_by(user_id=user_id, id=file_id).first_or_404()
    file.shared_with = f"{file.shared_with},{user.username}" if file.shared_with else user.username
    db.session.commit()
    return jsonify({"message": "File shared successfully!"})

@bp.route('/passwords', methods=['POST'])
@jwt_required()
def add_password():
    user_id = get_jwt_identity()
    data = request.json
    site = data['site']
    username = data['username']
    password = encrypt_data(data['password'].encode())
    sensitive_file = SensitiveFile(user_id=user_id, file_name=f"Password for {site}", 
                                   category="passwords", encrypted_data=password)
    db.session.add(sensitive_file)
    db.session.commit()
    return jsonify({"message": "Password stored successfully!"}), 201

@bp.route('/passwords', methods=['GET'])
@jwt_required()
def get_passwords():
    user_id = get_jwt_identity()
    passwords = SensitiveFile.query.filter_by(user_id=user_id, category="passwords").all()
    return jsonify([{
        "site": file.file_name.replace("Password for ", ""),
        "username": file.file_name,
        "password": decrypt_data(file.encrypted_data).decode('utf-8')
    } for file in passwords])

# Register Blueprint
app.register_blueprint(bp)

# Run the app (if this is the main script)
if __name__ == '__main__':
    app.run(debug=True)
