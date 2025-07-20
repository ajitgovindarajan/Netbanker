"""
Database Manager for NetBanking System
Handles all database operations and schema management
"""

import sqlite3
import os
from datetime import datetime
from contextlib import contextmanager

class DatabaseManager:
    def __init__(self, db_path="netbanking.db"):
        self.db_path = db_path
        self.initialize_database()
    
    def initialize_database(self):
        """Initialize database with required tables"""
        # PSEUDOCODE:
        # 1. Create database connection
        # 2. Create all required tables
        # 3. Set up indexes for performance
        # 4. Create initial admin user if needed
        
        with self.get_connection() as conn:
            self.create_tables(conn)
            self.create_indexes(conn)
    
    @contextmanager
    def get_connection(self):
        """Get database connection with automatic cleanup"""
        # PSEUDOCODE:
        # 1. Create connection
        # 2. Yield connection
        # 3. Commit transaction
        # 4. Close connection on exit
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable dict-like access
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def create_tables(self, conn):
        """Create all database tables"""
        # PSEUDOCODE:
        # 1. Create users table
        # 2. Create accounts table
        # 3. Create transactions table
        # 4. Create sessions table
        # 5. Create mfa_tokens table
        
        # Users table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT NOT NULL,
                address TEXT NOT NULL,
                city TEXT NOT NULL,
                state TEXT NOT NULL,
                zip_code TEXT NOT NULL,
                age INTEGER NOT NULL,
                ssn_last4 TEXT NOT NULL,
                employment TEXT NOT NULL,
                income REAL NOT NULL,
                created_at DATETIME NOT NULL,
                updated_at DATETIME,
                is_active BOOLEAN DEFAULT TRUE,
                login_attempts INTEGER DEFAULT 0,
                last_failed_login DATETIME,
                mfa_enabled BOOLEAN DEFAULT FALSE,
                mfa_secret TEXT
            )
        ''')
        
        # Accounts table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                account_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                account_number TEXT UNIQUE NOT NULL,
                account_type TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 0.00,
                interest_rate REAL DEFAULT 0.00,
                created_at DATETIME NOT NULL,
                updated_at DATETIME,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # Transactions table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL,
                transaction_type TEXT NOT NULL,
                amount REAL NOT NULL,
                description TEXT,
                recipient_account TEXT,
                created_at DATETIME NOT NULL,
                status TEXT DEFAULT 'completed',
                FOREIGN KEY (account_id) REFERENCES accounts (account_id)
            )
        ''')
        
        # Sessions table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at DATETIME NOT NULL,
                expires_at DATETIME NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # MFA tokens table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS mfa_tokens (
                token_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL,
                token_type TEXT NOT NULL,
                created_at DATETIME NOT NULL,
                expires_at DATETIME NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
    
    def create_indexes(self, conn):
        """Create database indexes for performance"""
        # PSEUDOCODE:
        # 1. Create indexes on frequently queried columns
        # 2. Create composite indexes for complex queries
        
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            "CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_accounts_number ON accounts(account_number)",
            "CREATE INDEX IF NOT EXISTS idx_transactions_account_id ON transactions(account_id)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)",
            "CREATE INDEX IF NOT EXISTS idx_mfa_tokens_user_id ON mfa_tokens(user_id)"
        ]
        
        for index in indexes:
            conn.execute(index)
    
    # User Management Methods
    def create_user(self, user_data):
        """Create new user in database"""
        # PSEUDOCODE:
        # 1. Insert user data into users table
        # 2. Return user_id if successful
        # 3. Handle any constraint violations
        
        try:
            with self.get_connection() as conn:
                cursor = conn.execute('''
                    INSERT INTO users (
                        username, password_hash, first_name, last_name, email, phone,
                        address, city, state, zip_code, age, ssn_last4, employment,
                        income, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_data['username'], user_data['password_hash'],
                    user_data['first_name'], user_data['last_name'],
                    user_data['email'], user_data['phone'],
                    user_data['address'], user_data['city'],
                    user_data['state'], user_data['zip_code'],
                    user_data['age'], user_data['ssn_last4'],
                    user_data['employment'], user_data['income'],
                    user_data['created_at']
                ))
                return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None
    
    def get_user_by_username(self, username):
        """Get user by username"""
        # PSEUDOCODE:
        # 1. Query users table by username
        # 2. Return user record if found
        # 3. Return None if not found
        
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_user_by_id(self, user_id):
        """Get user by user ID"""
        # PSEUDOCODE:
        # 1. Query users table by user_id
        # 2. Return user record if found
        # 3. Return None if not found
        
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM users WHERE user_id = ?", (user_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def user_exists(self, username):
        """Check if username exists"""
        # PSEUDOCODE:
        # 1. Query users table for username
        # 2. Return True if exists, False otherwise
        
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            )
            return cursor.fetchone() is not None
    
    def update_login_attempts(self, user_id, attempts, last_failed=None):
        """Update login attempts for user"""
        # PSEUDOCODE:
        # 1. Update login_attempts and last_failed_login
        # 2. Handle None values appropriately
        
        with self.get_connection() as conn:
            if last_failed:
                conn.execute(
                    "UPDATE users SET login_attempts = ?, last_failed_login = ? WHERE user_id = ?",
                    (attempts, last_failed, user_id)
                )
            else:
                conn.execute(
                    "UPDATE users SET login_attempts = ? WHERE user_id = ?",
                    (attempts, user_id)
                )
    
    def increment_login_attempts(self, user_id):
        """Increment login attempts for user"""
        # PSEUDOCODE:
        # 1. Get current attempts
        # 2. Increment by 1
        # 3. Update with current timestamp
        
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE users SET login_attempts = login_attempts + 1, last_failed_login = ? WHERE user_id = ?",
                (datetime.now(), user_id)
            )
    
    def reset_login_attempts(self, user_id):
        """Reset login attempts for user"""
        # PSEUDOCODE:
        # 1. Set login_attempts to 0
        # 2. Clear last_failed_login
        
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE users SET login_attempts = 0, last_failed_login = NULL WHERE user_id = ?",
                (user_id,)
            )
    
    # Account Management Methods
    def create_account(self, user_id, account_type, initial_balance=0.00):
        """Create new account for user"""
        # PSEUDOCODE:
        # 1. Generate unique account number
        # 2. Insert account record
        # 3. Return account_id
        
        from accounts import AccountManager
        account_manager = AccountManager()
        account_number = account_manager.generate_account_number(account_type)
        
        try:
            with self.get_connection() as conn:
                cursor = conn.execute('''
                    INSERT INTO accounts (user_id, account_number, account_type, balance, created_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, account_number, account_type, initial_balance, datetime.now()))
                return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None
    
    def get_user_accounts(self, user_id):
        """Get all accounts for user"""
        # PSEUDOCODE:
        # 1. Query accounts table by user_id
        # 2. Return list of account records
        
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM accounts WHERE user_id = ? AND is_active = TRUE",
                (user_id,)
            )
            return [dict(row) for row in cursor.fetchall()]
    
    def get_account_by_number(self, account_number):
        """Get account by account number"""
        # PSEUDOCODE:
        # 1. Query accounts table by account_number
        # 2. Return account record if found
        
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM accounts WHERE account_number = ?", (account_number,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_account_balance(self, account_id, new_balance):
        """Update account balance"""
        # PSEUDOCODE:
        # 1. Update balance in accounts table
        # 2. Update timestamp
        
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE accounts SET balance = ?, updated_at = ? WHERE account_id = ?",
                (new_balance, datetime.now(), account_id)
            )
    
    # Transaction Management Methods
    def create_transaction(self, transaction_data):
        """Create new transaction record"""
        # PSEUDOCODE:
        # 1. Insert transaction into transactions table
        # 2. Return transaction_id
        
        try:
            with self.get_connection() as conn:
                cursor = conn.execute('''
                    INSERT INTO transactions (
                        account_id, transaction_type, amount, description, 
                        recipient_account, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    transaction_data['account_id'],
                    transaction_data['transaction_type'],
                    transaction_data['amount'],
                    transaction_data['description'],
                    transaction_data.get('recipient_account'),
                    datetime.now()
                ))
                return cursor.lastrowid
        except Exception:
            return None
    
    def get_account_transactions(self, account_id, limit=50):
        """Get transactions for account"""
        # PSEUDOCODE:
        # 1. Query transactions table by account_id
        # 2. Order by created_at DESC
        # 3. Limit results
        
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM transactions WHERE account_id = ? ORDER BY created_at DESC LIMIT ?",
                (account_id, limit)
            )
            return [dict(row) for row in cursor.fetchall()]
    
    # Session Management Methods
    def create_session(self, user_id, token, expires_at):
        """Create session token"""
        # PSEUDOCODE:
        # 1. Insert session record
        # 2. Clean up expired sessions
        
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO sessions (user_id, token, created_at, expires_at)
                VALUES (?, ?, ?, ?)
            ''', (user_id, token, datetime.now(), expires_at))
            
            # Clean up expired sessions
            conn.execute(
                "DELETE FROM sessions WHERE expires_at < ?", (datetime.now(),)
            )
    
    def get_session(self, token):
        """Get session by token"""
        # PSEUDOCODE:
        # 1. Query sessions table by token
        # 2. Return session if found and not expired
        
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM sessions WHERE token = ?", (token,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def delete_session(self, token):
        """Delete session token"""
        # PSEUDOCODE:
        # 1. Delete session from sessions table
        
        with self.get_connection() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    
    # MFA Management Methods
    def create_mfa_token(self, user_id, token, token_type, expires_at):
        """Create MFA token"""
        # PSEUDOCODE:
        # 1. Insert MFA token record
        # 2. Clean up expired tokens
        
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO mfa_tokens (user_id, token, token_type, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, token, token_type, datetime.now(), expires_at))
    
    def get_mfa_token(self, user_id, token):
        """Get MFA token"""
        # PSEUDOCODE:
        # 1. Query mfa_tokens table
        # 2. Return token if found and not expired
        
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM mfa_tokens WHERE user_id = ? AND token = ? AND used = FALSE",
                (user_id, token)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def mark_mfa_token_used(self, token_id):
        """Mark MFA token as used"""
        # PSEUDOCODE:
        # 1. Update used flag to TRUE
        
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE mfa_tokens SET used = TRUE WHERE token_id = ?", (token_id,)
            )