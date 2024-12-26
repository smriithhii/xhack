import re
from datetime import datetime, timedelta
import pyotp
import qrcode
import io

class SecurityManager:
    def __init__(self):
        self.password_pattern = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$')
        
    def validate_password(self, password):
        """Validate password meets complexity requirements"""
        return bool(self.password_pattern.match(password))
    
    def generate_mfa_secret(self):
        """Generate MFA secret key"""
        return pyotp.random_base32()
    
    def generate_mfa_qr(self, username, secret):
        """Generate QR code for MFA setup"""
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(username, issuer_name="Personal Data Vault")
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img_buffer = io.BytesIO()
        qr.make_image().save(img_buffer, format='PNG')
        return img_buffer.getvalue()
    
    def verify_mfa_token(self, secret, token):
        """Verify MFA token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token)
