import hashlib
import secrets
import pyotp
import qrcode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import random
import string
import re
from datetime import datetime, timedelta
import sqlite3
import os
from typing import Optional, Dict, Tuple, List
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityManager:
    """
    Comprehensive security manager for banking application
    Handles encryption, authentication, MFA, and secure account generation
    """
    
    def __init__(self, db_path: str = "banking_security.db"):
        self.db_path = db_path
        self.failed_attempts = {}  # Track failed login attempts
        self.max_attempts = 5
        self.lockout_duration = 300  # 5 minutes in seconds
        self._init_database()
        
    def _init_database(self):
        """Initialize security database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create security tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_security (
                user_id TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                mfa_secret TEXT,
                mfa_enabled BOOLEAN DEFAULT 0,
                account_locked BOOLEAN DEFAULT 0,
                lock_until TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS encryption_keys (
                key_id TEXT PRIMARY KEY,
                encrypted_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS account_numbers (
                account_number TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                account_type TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES user_security (user_id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS session_tokens (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES user_security (user_id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    # PASSWORD SECURITY
    def generate_salt(self) -> str:
        """Generate a random salt for password hashing"""
        return secrets.token_hex(32)
    
    def hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt using PBKDF2"""
        # Convert salt to bytes
        salt_bytes = salt.encode('utf-8')
        
        # Use PBKDF2 with SHA256
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
        )
        
        # Hash the password
        key = kdf.derive(password.encode('utf-8'))
        return base64.b64encode(key).decode('utf-8')
    
    def verify_password(self, password: str, stored_hash: str, salt: str) -> bool:
        """Verify password against stored hash"""
        return self.hash_password(password, salt) == stored_hash
    
    def validate_password_strength(self, password: str) -> Dict[str, bool]:
        """Validate password meets security requirements"""
        requirements = {
            'length': len(password) >= 8,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'digit': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'no_common': password.lower() not in ['password', '123456', 'qwerty', 'abc123']
        }
        
        requirements['valid'] = all(requirements.values())
        return requirements
    
    # MULTI-FACTOR AUTHENTICATION
    def generate_mfa_secret(self, user_id: str) -> str:
        """Generate MFA secret for user"""
        secret = pyotp.random_base32()
        
        # Store encrypted secret in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        encrypted_secret = self.encrypt_data(secret)
        cursor.execute("""
            UPDATE user_security 
            SET mfa_secret = ?, mfa_enabled = 1 
            WHERE user_id = ?
        """, (encrypted_secret, user_id))
        
        conn.commit()
        conn.close()
        
        return secret
    
    def generate_mfa_qr_code(self, user_id: str, secret: str, issuer: str = "SecureBank") -> str:
        """Generate QR code for MFA setup"""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_id,
            issuer_name=issuer
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        # Save QR code temporarily
        qr_path = f"mfa_qr_{user_id}.png"
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(qr_path)
        
        return qr_path
    
    def verify_mfa_token(self, user_id: str, token: str) -> bool:
        """Verify MFA token"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT mfa_secret FROM user_security WHERE user_id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result or not result[0]:
            return False
        
        # Decrypt the secret
        encrypted_secret = result[0]
        secret = self.decrypt_data(encrypted_secret)
        
        # Verify token
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
    
    # DATA ENCRYPTION
    def generate_encryption_key(self) -> bytes:
        """Generate encryption key"""
        return Fernet.generate_key()
    
    def get_or_create_master_key(self) -> Fernet:
        """Get or create master encryption key"""
        key_file = "master.key"
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                key = f.read()
        else:
            key = self.generate_encryption_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            # Secure the key file
            os.chmod(key_file, 0o600)
        
        return Fernet(key)
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        fernet = self.get_or_create_master_key()
        encrypted_data = fernet.encrypt(data.encode())
        return base64.b64encode(encrypted_data).decode()
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        fernet = self.get_or_create_master_key()
        encrypted_bytes = base64.b64decode(encrypted_data.encode())
        decrypted_data = fernet.decrypt(encrypted_bytes)
        return decrypted_data.decode()
    
    # ACCOUNT NUMBER GENERATION
    def generate_account_number(self, user_id: str, account_type: str) -> str:
        """Generate secure randomized account number based on type"""
        # Account type prefixes
        type_prefixes = {
            'checking': '1001',
            'savings': '2001', 
            'cd_investment': '3001'
        }
        
        prefix = type_prefixes.get(account_type.lower(), '9001')
        
        # Generate random 8-digit number
        random_part = ''.join([str(random.randint(0, 9)) for _ in range(8)])
        
        # Create account number
        account_number = f"{prefix}{random_part}"
        
        # Ensure uniqueness
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if account number already exists
        cursor.execute("SELECT account_number FROM account_numbers WHERE account_number = ?", 
                      (account_number,))
        
        while cursor.fetchone():
            random_part = ''.join([str(random.randint(0, 9)) for _ in range(8)])
            account_number = f"{prefix}{random_part}"
            cursor.execute("SELECT account_number FROM account_numbers WHERE account_number = ?", 
                          (account_number,))
        
        # Store account number
        cursor.execute("""
            INSERT INTO account_numbers (account_number, user_id, account_type)
            VALUES (?, ?, ?)
        """, (account_number, user_id, account_type))
        
        conn.commit()
        conn.close()
        
        return account_number
    
    def get_user_accounts(self, user_id: str) -> List[Dict]:
        """Get all account numbers for a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT account_number, account_type, created_at 
            FROM account_numbers 
            WHERE user_id = ?
        """, (user_id,))
        
        accounts = []
        for row in cursor.fetchall():
            accounts.append({
                'account_number': row[0],
                'account_type': row[1],
                'created_at': row[2]
            })
        
        conn.close()
        return accounts
    
    # SESSION MANAGEMENT
    def create_session_token(self, user_id: str) -> str:
        """Create secure session token"""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=2)  # 2-hour session
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO session_tokens (token, user_id, expires_at)
            VALUES (?, ?, ?)
        """, (token, user_id, expires_at))
        
        conn.commit()
        conn.close()
        
        return token
    
    def validate_session_token(self, token: str) -> Optional[str]:
        """Validate session token and return user_id if valid"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT user_id, expires_at FROM session_tokens 
            WHERE token = ?
        """, (token,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return None
        
        user_id, expires_at = result
        expires_at = datetime.fromisoformat(expires_at)
        
        if datetime.now() > expires_at:
            self.revoke_session_token(token)
            return None
        
        return user_id
    
    def revoke_session_token(self, token: str):
        """Revoke session token"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM session_tokens WHERE token = ?", (token,))
        
        conn.commit()
        conn.close()
    
    # ACCOUNT LOCKOUT PROTECTION
    def record_failed_login(self, user_id: str):
        """Record failed login attempt"""
        if user_id not in self.failed_attempts:
            self.failed_attempts[user_id] = []
        
        self.failed_attempts[user_id].append(datetime.now())
        
        # Remove old attempts (older than lockout duration)
        cutoff_time = datetime.now() - timedelta(seconds=self.lockout_duration)
        self.failed_attempts[user_id] = [
            attempt for attempt in self.failed_attempts[user_id] 
            if attempt > cutoff_time
        ]
        
        # Lock account if too many attempts
        if len(self.failed_attempts[user_id]) >= self.max_attempts:
            self.lock_account(user_id)
    
    def lock_account(self, user_id: str):
        """Lock user account"""
        lock_until = datetime.now() + timedelta(seconds=self.lockout_duration)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE user_security 
            SET account_locked = 1, lock_until = ?
            WHERE user_id = ?
        """, (lock_until, user_id))
        
        conn.commit()
        conn.close()
        
        logger.warning(f"Account locked for user: {user_id}")
    
    def is_account_locked(self, user_id: str) -> bool:
        """Check if account is locked"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT account_locked, lock_until FROM user_security 
            WHERE user_id = ?
        """, (user_id,))
        
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return False
        
        locked, lock_until = result
        
        if not locked:
            conn.close()
            return False
        
        if lock_until:
            lock_until = datetime.fromisoformat(lock_until)
            if datetime.now() > lock_until:
                # Unlock account
                cursor.execute("""
                    UPDATE user_security 
                    SET account_locked = 0, lock_until = NULL
                    WHERE user_id = ?
                """, (user_id,))
                conn.commit()
                conn.close()
                return False
        
        conn.close()
        return True
    
    # USER MANAGEMENT
    def create_user_security(self, user_id: str, password: str) -> bool:
        """Create security record for new user"""
        # Validate password strength
        password_check = self.validate_password_strength(password)
        if not password_check['valid']:
            return False
        
        salt = self.generate_salt()
        password_hash = self.hash_password(password, salt)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO user_security (user_id, password_hash, salt)
                VALUES (?, ?, ?)
            """, (user_id, password_hash, salt))
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            conn.close()
            return False
    
    def authenticate_user(self, user_id: str, password: str) -> Dict[str, any]:
        """Authenticate user with password"""
        result = {
            'authenticated': False,
            'requires_mfa': False,
            'account_locked': False,
            'message': ''
        }
        
        # Check if account is locked
        if self.is_account_locked(user_id):
            result['account_locked'] = True
            result['message'] = 'Account is temporarily locked due to too many failed attempts'
            return result
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT password_hash, salt, mfa_enabled 
            FROM user_security 
            WHERE user_id = ?
        """, (user_id,))
        
        user_data = cursor.fetchone()
        conn.close()
        
        if not user_data:
            result['message'] = 'Invalid credentials'
            return result
        
        password_hash, salt, mfa_enabled = user_data
        
        # Verify password
        if self.verify_password(password, password_hash, salt):
            result['authenticated'] = True
            result['requires_mfa'] = bool(mfa_enabled)
            result['message'] = 'Authentication successful'
            
            # Clear failed attempts
            if user_id in self.failed_attempts:
                del self.failed_attempts[user_id]
        else:
            result['message'] = 'Invalid credentials'
            self.record_failed_login(user_id)
        
        return result
    
    def cleanup_expired_sessions(self):
        """Clean up expired session tokens"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM session_tokens 
            WHERE expires_at < ?
        """, (datetime.now(),))
        
        conn.commit()
        conn.close()


# Utility functions for Streamlit integration
def get_security_manager() -> SecurityManager:
    """Get singleton security manager instance"""
    if 'security_manager' not in globals():
        globals()['security_manager'] = SecurityManager()
    return globals()['security_manager']

def validate_input_security(data: str, input_type: str = "general") -> bool:
    """Validate user input for security threats"""
    # Basic SQL injection protection
    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER']
    if any(keyword in data.upper() for keyword in sql_keywords):
        return False
    
    # XSS protection
    if '<script>' in data.lower() or 'javascript:' in data.lower():
        return False
    
    # Additional validation based on input type
    if input_type == "username":
        return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', data))
    elif input_type == "email":
        return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', data))
    
    return True

# Example usage and testing
if __name__ == "__main__":
    # Initialize security manager
    security_mgr = SecurityManager()
    
    # Test user creation
    user_id = "test_user_001"
    password = "SecurePass123!"
    
    if security_mgr.create_user_security(user_id, password):
        print(f"User {user_id} created successfully")
        
        # Test authentication
        auth_result = security_mgr.authenticate_user(user_id, password)
        print(f"Authentication result: {auth_result}")
        
        # Generate account numbers
        checking_account = security_mgr.generate_account_number(user_id, "checking")
        savings_account = security_mgr.generate_account_number(user_id, "savings")
        cd_account = security_mgr.generate_account_number(user_id, "cd_investment")
        
        print(f"Checking Account: {checking_account}")
        print(f"Savings Account: {savings_account}")
        print(f"CD Investment Account: {cd_account}")
        
        # Test MFA setup
        mfa_secret = security_mgr.generate_mfa_secret(user_id)
        print(f"MFA Secret: {mfa_secret}")
        
        # Test session management
        session_token = security_mgr.create_session_token(user_id)
        print(f"Session Token: {session_token}")
        
        # Validate session
        validated_user = security_mgr.validate_session_token(session_token)
        print(f"Session validation result: {validated_user}")
    
    else:
        print("Failed to create user")