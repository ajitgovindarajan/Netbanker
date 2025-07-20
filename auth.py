"""
Authentication Manager for NetBanking System
Handles user login, registration, and session management
"""

import bcrypt
import hashlib
import secrets
from datetime import datetime, timedelta
from database import DatabaseManager

class AuthenticationManager:
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.max_login_attempts = 5
        self.lockout_duration = 30  # minutes
    
    def hash_password(self, password):
        """Hash password using bcrypt"""
        # PSEUDOCODE:
        # 1. Generate salt
        # 2. Hash password with salt using bcrypt
        # 3. Return hashed password
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password, hashed_password):
        """Verify password against hash"""
        # PSEUDOCODE:
        # 1. Convert password to bytes
        # 2. Use bcrypt to check password against hash
        # 3. Return True if match, False otherwise
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    
    def create_user(self, user_data):
        """Create new user account"""
        # PSEUDOCODE:
        # 1. Check if username already exists
        # 2. Validate user data
        # 3. Hash password
        # 4. Encrypt sensitive data (SSN, etc.)
        # 5. Insert user into database
        # 6. Create initial account records
        # 7. Return success/failure
        
        try:
            # Check if username exists
            if self.db_manager.user_exists(user_data['username']):
                return False
            
            # Hash password
            hashed_password = self.hash_password(user_data['password'])
            
            # Encrypt sensitive data
            encrypted_ssn = self.encrypt_sensitive_data(user_data['ssn_last4'])
            
            # Prepare user record
            user_record = {
                'username': user_data['username'],
                'password_hash': hashed_password,
                'first_name': user_data['first_name'],
                'last_name': user_data['last_name'],
                'email': user_data['email'],
                'phone': user_data['phone'],
                'address': user_data['address'],
                'city': user_data['city'],
                'state': user_data['state'],
                'zip_code': user_data['zip_code'],
                'age': user_data['age'],
                'ssn_last4': encrypted_ssn,
                'employment': user_data['employment'],
                'income': user_data['income'],
                'created_at': datetime.now(),
                'is_active': True,
                'login_attempts': 0
            }
            
            # Insert user
            user_id = self.db_manager.create_user(user_record)
            
            if user_id:
                # Create default checking account
                self.create_initial_account(user_id)
                return True
            
            return False
            
        except Exception as e:
            print(f"Error creating user: {e}")
            return False
    
    def validate_login(self, username, password):
        """Validate user login credentials"""
        # PSEUDOCODE:
        # 1. Check if account is locked
        # 2. Get user record from database
        # 3. Verify password
        # 4. Update login attempts
        # 5. Lock account if too many failed attempts
        # 6. Return success/failure
        
        try:
            # Get user record
            user = self.db_manager.get_user_by_username(username)
            
            if not user:
                return False
            
            # Check if account is locked
            if self.is_account_locked(user):
                return False
            
            # Verify password
            if self.verify_password(password, user['password_hash']):
                # Reset login attempts on successful login
                self.db_manager.reset_login_attempts(user['user_id'])
                return True
            else:
                # Increment login attempts
                self.db_manager.increment_login_attempts(user['user_id'])
                return False
                
        except Exception as e:
            print(f"Error validating login: {e}")
            return False
    
    def is_account_locked(self, user):
        """Check if account is locked due to failed login attempts"""
        # PSEUDOCODE:
        # 1. Check login attempts count
        # 2. Check last failed login time
        # 3. Calculate if lockout period has expired
        # 4. Return True if locked, False otherwise
        
        if user['login_attempts'] >= self.max_login_attempts:
            # Check if lockout period has expired
            lockout_time = user['last_failed_login'] + timedelta(minutes=self.lockout_duration)
            if datetime.now() < lockout_time:
                return True
            else:
                # Reset attempts if lockout period expired
                self.db_manager.reset_login_attempts(user['user_id'])
                return False
        
        return False
    
    def get_user_id(self, username):
        """Get user ID by username"""
        # PSEUDOCODE:
        # 1. Query database for user
        # 2. Return user_id if found
        # 3. Return None if not found
        
        user = self.db_manager.get_user_by_username(username)
        return user['user_id'] if user else None
    
    def encrypt_sensitive_data(self, data):
        """Encrypt sensitive data like SSN"""
        # PSEUDOCODE:
        # 1. Use AES encryption with key from environment
        # 2. Return encrypted data
        # 3. Store encryption key securely
        
        # Placeholder - implement proper encryption
        return hashlib.sha256(data.encode()).hexdigest()
    
    def create_initial_account(self, user_id):
        """Create initial checking account for new user"""
        # PSEUDOCODE:
        # 1. Generate unique account number
        # 2. Create checking account record
        # 3. Set initial balance to 0
        # 4. Insert into accounts table
        
        from accounts import AccountManager
        account_manager = AccountManager()
        account_manager.create_account(user_id, 'checking', 0.00)
    
    def generate_session_token(self, user_id):
        """Generate secure session token"""
        # PSEUDOCODE:
        # 1. Generate random token
        # 2. Store token with expiration in database
        # 3. Return token
        
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=24)
        
        self.db_manager.create_session(user_id, token, expires_at)
        return token
    
    def validate_session_token(self, token):
        """Validate session token"""
        # PSEUDOCODE:
        # 1. Check if token exists in database
        # 2. Check if token is expired
        # 3. Return user_id if valid, None otherwise
        
        session = self.db_manager.get_session(token)
        
        if session and session['expires_at'] > datetime.now():
            return session['user_id']
        
        return None
    
    def logout_user(self, token):
        """Logout user and invalidate session"""
        # PSEUDOCODE:
        # 1. Remove session token from database
        # 2. Clear any cached user data
        
        self.db_manager.delete_session(token)