"""
Multi-Factor Authentication System for NetBanking
Handles TOTP, SMS, and email-based MFA
"""

import pyotp
import qrcode
import io
import base64
import secrets
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import streamlit as st
from database import DatabaseManager

class MFAManager:
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.issuer_name = "SecureBank"
        self.token_validity = 300  # 5 minutes
    
    def generate_totp_secret(self):
        """Generate TOTP secret for user"""
        # PSEUDOCODE:
        # 1. Generate random 32-character secret
        # 2. Return base32 encoded secret
        
        return pyotp.random_base32()
    
    def generate_qr_code(self, user_email, secret):
        """Generate QR code for TOTP setup"""
        # PSEUDOCODE:
        # 1. Create TOTP URI
        # 2. Generate QR code image
        # 3. Convert to base64 for display
        # 4. Return base64 encoded image
        
        # Create provisioning URI
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name=self.issuer_name
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return img_base64
    
    def verify_totp_token(self, secret, token):
        """Verify TOTP token"""
        # PSEUDOCODE:
        # 1. Create TOTP object with secret
        # 2. Verify token with time window
        # 3. Return True if valid, False otherwise
        
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=1)
        except Exception:
            return False
    
    def setup_totp_for_user(self, user_id, user_email):
        """Setup TOTP for user"""
        # PSEUDOCODE:
        # 1. Generate secret
        # 2. Store secret in database
        # 3. Generate QR code
        # 4. Return secret and QR code
        
        try:
            secret = self.generate_totp_secret()
            
            # Store secret in database
            with self.db_manager.get_connection() as conn:
                conn.execute(
                    "UPDATE users SET mfa_secret = ?, mfa_enabled = TRUE WHERE user_id = ?",
                    (secret, user_id)
                )
            
            # Generate QR code
            qr_code = self.generate_qr_code(user_email, secret)
            
            return {
                'success': True,
                'secret': secret,
                'qr_code': qr_code,
                'backup_codes': self.generate_backup_codes(user_id)
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Error setting up TOTP: {str(e)}'}
    
    def generate_backup_codes(self, user_id):
        """Generate backup codes for MFA"""
        # PSEUDOCODE:
        # 1. Generate 10 random backup codes
        # 2. Store hashed codes in database
        # 3. Return plain text codes for user
        
        backup_codes = []
        for _ in range(10):
            code = secrets.token_hex(4).upper()
            backup_codes.append(code)
            
            # Store hashed code in database
            hashed_code = self.hash_backup_code(code)
            self.db_manager.create_mfa_token(
                user_id=user_id,
                token=hashed_code,
                token_type='backup',
                expires_at=datetime.now() + timedelta(days=365)
            )
        
        return backup_codes
    
    def hash_backup_code(self, code):
        """Hash backup code for storage"""
        # PSEUDOCODE:
        # 1. Use secure hash function
        # 2. Return hashed code
        
        import hashlib
        return hashlib.sha256(code.encode()).hexdigest()
    
    def verify_backup_code(self, user_id, code):
        """Verify backup code"""
        # PSEUDOCODE:
        # 1. Hash provided code
        # 2. Check if hashed code exists and is unused
        # 3. Mark code as used if valid
        # 4. Return verification result
        
        hashed_code = self.hash_backup_code(code)
        
        token = self.db_manager.get_mfa_token(user_id, hashed_code)
        
        if token and token['token_type'] == 'backup':
            # Mark token as used
            self.db_manager.mark_mfa_token_used(token['token_id'])
            return True
        
        return False
    
    def generate_sms_token(self, user_id):
        """Generate SMS token for MFA"""
        # PSEUDOCODE:
        # 1. Generate 6-digit numeric token
        # 2. Store token in database with expiration
        # 3. Send SMS to user's phone
        # 4. Return success status
        
        token = str(secrets.randbelow(1000000)).zfill(6)
        expires_at = datetime.now() + timedelta(seconds=self.token_validity)
        
        # Store token in database
        self.db_manager.create_mfa_token(
            user_id=user_id,
            token=token,
            token_type='sms',
            expires_at=expires_at
        )
        
        # Get user phone number
        user = self.db_manager.get_user_by_id(user_id)
        if not user:
            return {'success': False, 'message': 'User not found'}
        
        # Send SMS (placeholder - integrate with SMS service)
        sms_sent = self.send_sms(user['phone'], token)
        
        return {
            'success': sms_sent,
            'message': 'SMS sent successfully' if sms_sent else 'Failed to send SMS',
            'expires_in': self.token_validity
        }
    
    def send_sms(self, phone_number, token):
        """Send SMS with MFA token"""
        # PSEUDOCODE:
        # 1. Format SMS message
        # 2. Use SMS service API (Twilio, etc.)
        # 3. Return success status
        
        message = f"Your SecureBank verification code is: {token}. Valid for 5 minutes."
        
        # Placeholder for SMS service integration
        # In production, integrate with Twilio, AWS SNS, etc.
        print(f"SMS to {phone_number}: {message}")
        
        # Simulate SMS sending
        return True
    
    def verify_sms_token(self, user_id, token):
        """Verify SMS token"""
        # PSEUDOCODE:
        # 1. Get token from database
        # 2. Check if token is valid and not expired
        # 3. Mark token as used
        # 4. Return verification result
        
        stored_token = self.db_manager.get_mfa_token(user_id, token)
        
        if stored_token and stored_token['token_type'] == 'sms':
            # Check if token is expired
            if datetime.now() > datetime.fromisoformat(stored_token['expires_at']):
                return {'success': False, 'message': 'Token expired'}
            
            # Mark token as used
            self.db_manager.mark_mfa_token_used(stored_token['token_id'])
            return {'success': True, 'message': 'Token verified successfully'}
        
        return {'success': False, 'message': 'Invalid token'}
    
    def generate_email_token(self, user_id):
        """Generate email token for MFA"""
        # PSEUDOCODE:
        # 1. Generate 8-character alphanumeric token
        # 2. Store token in database with expiration
        # 3. Send email to user
        # 4. Return success status
        
        token = secrets.token_urlsafe(6)
        expires_at = datetime.now() + timedelta(seconds=self.token_validity)
        
        # Store token in database
        self.db_manager.create_mfa_token(
            user_id=user_id,
            token=token,
            token_type='email',
            expires_at=expires_at
        )
        
        # Get user email
        user = self.db_manager.get_user_by_id(user_id)
        if not user:
            return {'success': False, 'message': 'User not found'}
        
        # Send email
        email_sent = self.send_email(user['email'], token)
        
        return {
            'success': email_sent,
            'message': 'Email sent successfully' if email_sent else 'Failed to send email',
            'expires_in': self.token_validity
        }
    
    def send_email(self, email_address, token):
        """Send email with MFA token"""
        # PSEUDOCODE:
        # 1. Format email message
        # 2. Use SMTP to send email
        # 3. Return success status
        
        subject = "SecureBank - Verification Code"
        body = f"""
        Your SecureBank verification code is: {token}
        
        This code is valid for 5 minutes.
        
        If you didn't request this code, please contact customer service immediately.
        
        Best regards,
        SecureBank Security Team"""