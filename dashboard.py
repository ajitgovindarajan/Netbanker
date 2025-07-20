import streamlit as st
import sqlite3
import hashlib
import secrets
import random
import string
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from cryptography.fernet import Fernet
import re
import time
import smtplib
from email.mime.text import MIMEText

# Page configuration
st.set_page_config(
    page_title="SecureBank - Online Banking",
    page_icon="🏦",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional banking interface
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .account-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        border-left: 4px solid #2a5298;
        margin-bottom: 1rem;
    }
    .balance-text {
        font-size: 2rem;
        font-weight: bold;
        color: #2a5298;
    }
    .transaction-row {
        padding: 0.5rem;
        border-bottom: 1px solid #eee;
    }
    .sidebar .element-container {
        margin-bottom: 1rem;
    }
    .success-message {
        background-color: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 5px;
        border: 1px solid #c3e6cb;
    }
    .error-message {
        background-color: #f8d7da;
        color: #721c24;
        padding: 1rem;
        border-radius: 5px;
        border: 1px solid #f5c6cb;
    }
</style>
""", unsafe_allow_html=True)

class BankingSystem:
    def __init__(self):
        self.db_name = "banking_system.db"
        self.init_database()
        self.encryption_key = self.get_or_create_encryption_key()
        
    def get_or_create_encryption_key(self):
        """Generate or retrieve encryption key"""
        try:
            with open("encryption_key.key", "rb") as key_file:
                return key_file.read()
        except FileNotFoundError:
            key = Fernet.generate_key()
            with open("encryption_key.key", "wb") as key_file:
                key_file.write(key)
            return key
    
    def encrypt_data(self, data):
        """Encrypt sensitive data"""
        f = Fernet(self.encryption_key)
        return f.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data):
        """Decrypt sensitive data"""
        f = Fernet(self.encryption_key)
        return f.decrypt(encrypted_data.encode()).decode()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT NOT NULL,
                full_name TEXT NOT NULL,
                address TEXT NOT NULL,
                ssn_encrypted TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                failed_attempts INTEGER DEFAULT 0,
                last_login TIMESTAMP,
                mfa_secret TEXT,
                mfa_enabled BOOLEAN DEFAULT FALSE
            )
        ''')
        
        # Accounts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                account_number TEXT UNIQUE NOT NULL,
                account_type TEXT NOT NULL,
                balance DECIMAL(15,2) DEFAULT 0.00,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Transactions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL,
                transaction_type TEXT NOT NULL,
                amount DECIMAL(15,2) NOT NULL,
                description TEXT,
                recipient_account TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (account_id) REFERENCES accounts (id)
            )
        ''')
        
        # MFA tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mfa_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password):
        """Hash password with salt"""
        salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return salt + password_hash.hex()
    
    def verify_password(self, password, stored_hash):
        """Verify password against stored hash"""
        salt = stored_hash[:64]
        stored_password_hash = stored_hash[64:]
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return password_hash.hex() == stored_password_hash
    
    def generate_account_number(self, account_type):
        """Generate randomized account numbers based on account type"""
        type_prefixes = {
            'Checking': '1001',
            'Savings': '2001',
            'CD Investment': '3001'
        }
        
        prefix = type_prefixes.get(account_type, '1001')
        random_suffix = ''.join(random.choices(string.digits, k=8))
        return f"{prefix}{random_suffix}"
    
    def generate_mfa_token(self):
        """Generate 6-digit MFA token"""
        return ''.join(random.choices(string.digits, k=6))
    
    def send_mfa_token(self, email, token):
        """Send MFA token via email (simulation)"""
        # In a real application, you would integrate with an email service
        # For demo purposes, we'll just store it in session state
        st.session_state['mfa_token'] = token
        st.session_state['mfa_sent_time'] = datetime.now()
        return True
    
    def validate_email(self, email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def validate_phone(self, phone):
        """Validate phone number"""
        pattern = r'^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$'
        return re.match(pattern, phone) is not None
    
    def validate_ssn(self, ssn):
        """Validate SSN format"""
        pattern = r'^\d{3}-?\d{2}-?\d{4}$'
        return re.match(pattern, ssn) is not None
    
    def register_user(self, username, password, email, phone, full_name, address, ssn):
        """Register new user"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            # Check if username already exists
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                return False, "Username already exists"
            
            # Validate inputs
            if not self.validate_email(email):
                return False, "Invalid email format"
            
            if not self.validate_phone(phone):
                return False, "Invalid phone number format"
            
            if not self.validate_ssn(ssn):
                return False, "Invalid SSN format"
            
            # Hash password and encrypt SSN
            password_hash = self.hash_password(password)
            ssn_encrypted = self.encrypt_data(ssn)
            
            # Insert user
            cursor.execute('''
                INSERT INTO users (username, password_hash, email, phone, full_name, address, ssn_encrypted)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, password_hash, email, phone, full_name, address, ssn_encrypted))
            
            user_id = cursor.lastrowid
            
            # Create default accounts
            for account_type in ['Checking', 'Savings']:
                account_number = self.generate_account_number(account_type)
                cursor.execute('''
                    INSERT INTO accounts (user_id, account_number, account_type, balance)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, account_number, account_type, 0.00))
            
            conn.commit()
            return True, "Registration successful"
            
        except Exception as e:
            conn.rollback()
            return False, f"Registration failed: {str(e)}"
        finally:
            conn.close()
    
    def authenticate_user(self, username, password):
        """Authenticate user credentials"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT id, password_hash, is_active, failed_attempts, email
                FROM users WHERE username = ?
            ''', (username,))
            
            result = cursor.fetchone()
            if not result:
                return False, "Invalid username or password"
            
            user_id, stored_hash, is_active, failed_attempts, email = result
            
            if not is_active:
                return False, "Account is deactivated"
            
            if failed_attempts >= 5:
                return False, "Account locked due to too many failed attempts"
            
            if self.verify_password(password, stored_hash):
                # Reset failed attempts on successful login
                cursor.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user_id,))
                conn.commit()
                return True, {"user_id": user_id, "email": email}
            else:
                # Increment failed attempts
                cursor.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?", (user_id,))
                conn.commit()
                return False, "Invalid username or password"
                
        except Exception as e:
            return False, f"Authentication failed: {str(e)}"
        finally:
            conn.close()
    
    def get_user_accounts(self, user_id):
        """Get user's accounts"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, account_number, account_type, balance
            FROM accounts WHERE user_id = ? AND is_active = TRUE
        ''', (user_id,))
        
        accounts = cursor.fetchall()
        conn.close()
        
        return [{"id": acc[0], "number": acc[1], "type": acc[2], "balance": acc[3]} for acc in accounts]
    
    def get_account_transactions(self, account_id, limit=10):
        """Get account transactions"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT transaction_type, amount, description, recipient_account, created_at
            FROM transactions WHERE account_id = ?
            ORDER BY created_at DESC LIMIT ?
        ''', (account_id, limit))
        
        transactions = cursor.fetchall()
        conn.close()
        
        return transactions
    
    def transfer_money(self, from_account_id, to_account_number, amount, description):
        """Transfer money between accounts"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            # Check if source account has sufficient balance
            cursor.execute("SELECT balance FROM accounts WHERE id = ?", (from_account_id,))
            result = cursor.fetchone()
            if not result or result[0] < amount:
                return False, "Insufficient funds"
            
            # Check if destination account exists
            cursor.execute("SELECT id FROM accounts WHERE account_number = ? AND is_active = TRUE", (to_account_number,))
            to_account = cursor.fetchone()
            if not to_account:
                return False, "Destination account not found"
            
            to_account_id = to_account[0]
            
            # Perform transfer
            cursor.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, from_account_id))
            cursor.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, to_account_id))
            
            # Record transactions
            cursor.execute('''
                INSERT INTO transactions (account_id, transaction_type, amount, description, recipient_account)
                VALUES (?, ?, ?, ?, ?)
            ''', (from_account_id, 'Transfer Out', -amount, description, to_account_number))
            
            cursor.execute('''
                INSERT INTO transactions (account_id, transaction_type, amount, description, recipient_account)
                VALUES (?, ?, ?, ?, ?)
            ''', (to_account_id, 'Transfer In', amount, description, to_account_number))
            
            conn.commit()
            return True, "Transfer successful"
            
        except Exception as e:
            conn.rollback()
            return False, f"Transfer failed: {str(e)}"
        finally:
            conn.close()

# Initialize banking system
banking_system = BankingSystem()

def show_login_page():
    """Display login page"""
    st.markdown('<div class="main-header"><h1>🏦 SecureBank</h1><p>Secure Online Banking</p></div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("### Login to Your Account")
        
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            
            col_a, col_b = st.columns(2)
            with col_a:
                login_button = st.form_submit_button("Login", use_container_width=True)
            with col_b:
                signup_button = st.form_submit_button("Sign Up", use_container_width=True)
            
            if login_button:
                if username and password:
                    success, result = banking_system.authenticate_user(username, password)
                    if success:
                        st.session_state['auth_step'] = 'mfa'
                        st.session_state['user_data'] = result
                        st.session_state['username'] = username
                        st.rerun()
                    else:
                        st.error(result)
                else:
                    st.error("Please enter both username and password")
            
            if signup_button:
                st.session_state['show_signup'] = True
                st.rerun()

def show_mfa_page():
    """Display MFA verification page"""
    st.markdown('<div class="main-header"><h1>🔐 Multi-Factor Authentication</h1></div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("### Verify Your Identity")
        st.info("A 6-digit verification code has been sent to your registered email address.")
        
        # Generate and "send" MFA token
        if 'mfa_token' not in st.session_state:
            token = banking_system.generate_mfa_token()
            banking_system.send_mfa_token(st.session_state['user_data']['email'], token)
            st.success(f"Verification code sent! (Demo code: {token})")
        
        with st.form("mfa_form"):
            mfa_code = st.text_input("Enter 6-digit verification code", max_chars=6)
            
            col_a, col_b = st.columns(2)
            with col_a:
                verify_button = st.form_submit_button("Verify", use_container_width=True)
            with col_b:
                resend_button = st.form_submit_button("Resend Code", use_container_width=True)
            
            if verify_button:
                if mfa_code == st.session_state.get('mfa_token', ''):
                    st.session_state['authenticated'] = True
                    st.session_state['user_id'] = st.session_state['user_data']['user_id']
                    st.success("Authentication successful! Redirecting to dashboard...")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("Invalid verification code")
            
            if resend_button:
                token = banking_system.generate_mfa_token()
                banking_system.send_mfa_token(st.session_state['user_data']['email'], token)
                st.success(f"New verification code sent! (Demo code: {token})")

def show_signup_page():
    """Display signup page"""
    st.markdown('<div class="main-header"><h1>📝 Create New Account</h1></div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("### Personal Information")
        
        with st.form("signup_form"):
            full_name = st.text_input("Full Name", placeholder="Enter your full name")
            username = st.text_input("Username", placeholder="Choose a username")
            email = st.text_input("Email Address", placeholder="Enter your email")
            phone = st.text_input("Phone Number", placeholder="Enter your phone number")
            
            st.markdown("### Address Information")
            address = st.text_area("Address", placeholder="Enter your full address")
            
            st.markdown("### Security Information")
            ssn = st.text_input("Social Security Number", placeholder="XXX-XX-XXXX")
            password = st.text_input("Password", type="password", placeholder="Choose a strong password")
            confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm your password")
            
            st.markdown("### Account Eligibility")
            age_check = st.checkbox("I am 18 years or older")
            citizen_check = st.checkbox("I am a US citizen or permanent resident")
            terms_check = st.checkbox("I agree to the Terms of Service and Privacy Policy")
            
            col_a, col_b = st.columns(2)
            with col_a:
                submit_button = st.form_submit_button("Create Account", use_container_width=True)
            with col_b:
                back_button = st.form_submit_button("Back to Login", use_container_width=True)
            
            if submit_button:
                # Validate form
                if not all([full_name, username, email, phone, address, ssn, password, confirm_password]):
                    st.error("Please fill in all required fields")
                elif password != confirm_password:
                    st.error("Passwords do not match")
                elif not all([age_check, citizen_check, terms_check]):
                    st.error("Please check all eligibility requirements")
                else:
                    success, message = banking_system.register_user(
                        username, password, email, phone, full_name, address, ssn
                    )
                    if success:
                        st.success(message)
                        st.info("You can now log in with your credentials")
                        st.session_state['show_signup'] = False
                        time.sleep(2)
                        st.rerun()
                    else:
                        st.error(message)
            
            if back_button:
                st.session_state['show_signup'] = False
                st.rerun()

def show_dashboard():
    """Display main dashboard"""
    st.markdown('<div class="main-header"><h1>🏦 SecureBank Dashboard</h1></div>', unsafe_allow_html=True)
    
    # Sidebar navigation
    with st.sidebar:
        st.markdown("### Navigation")
        page = st.selectbox(
            "Select Page",
            ["Dashboard", "Accounts", "Transfer Money", "Transactions", "Settings"],
            key="page_selector"
        )
        
        st.markdown("---")
        if st.button("Logout"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    
    # Get user accounts
    accounts = banking_system.get_user_accounts(st.session_state['user_id'])
    
    if page == "Dashboard":
        show_dashboard_overview(accounts)
    elif page == "Accounts":
        show_accounts_page(accounts)
    elif page == "Transfer Money":
        show_transfer_page(accounts)
    elif page == "Transactions":
        show_transactions_page(accounts)
    elif page == "Settings":
        show_settings_page()

def show_dashboard_overview(accounts):
    """Display dashboard overview"""
    st.markdown("### Account Overview")
    
    # Display account cards
    cols = st.columns(len(accounts))
    total_balance = 0
    
    for i, account in enumerate(accounts):
        with cols[i]:
            st.markdown(f'''
                <div class="account-card">
                    <h4>{account['type']} Account</h4>
                    <p>Account: {account['number']}</p>
                    <div class="balance-text">${account['balance']:,.2f}</div>
                </div>
            ''', unsafe_allow_html=True)
            total_balance += account['balance']
    
    st.markdown("---")
    
    # Total balance and quick stats
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Balance", f"${total_balance:,.2f}")
    
    with col2:
        st.metric("Active Accounts", len(accounts))
    
    with col3:
        st.metric("Account Status", "✅ Active")
    
    # Recent transactions chart
    st.markdown("### Recent Activity")
    
    if accounts:
        # Get recent transactions for chart
        all_transactions = []
        for account in accounts:
            transactions = banking_system.get_account_transactions(account['id'], 30)
            for trans in transactions:
                all_transactions.append({
                    'Date': trans[4][:10],
                    'Amount': abs(trans[1]),
                    'Type': trans[0]
                })
        
        if all_transactions:
            df = pd.DataFrame(all_transactions)
            df['Date'] = pd.to_datetime(df['Date'])
            
            fig = px.line(df, x='Date', y='Amount', title='Transaction History (Last 30 Days)')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No recent transactions to display")

def show_accounts_page(accounts):
    """Display detailed accounts page"""
    st.markdown("### Account Details")
    
    for account in accounts:
        with st.expander(f"{account['type']} Account - {account['number']}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown(f"**Account Number:** {account['number']}")
                st.markdown(f"**Account Type:** {account['type']}")
                st.markdown(f"**Current Balance:** ${account['balance']:,.2f}")
            
            with col2:
                st.markdown("**Account Actions:**")
                if st.button(f"View Statements", key=f"stmt_{account['id']}"):
                    st.info("Statement generation feature coming soon!")
                
                if account['type'] == 'CD Investment':
                    st.markdown("**CD Terms:** 12 months at 3.5% APY")
            
            # Recent transactions for this account
            st.markdown("**Recent Transactions:**")
            transactions = banking_system.get_account_transactions(account['id'], 5)
            
            if transactions:
                for trans in transactions:
                    st.markdown(f"- {trans[0]}: ${abs(trans[1]):,.2f} - {trans[2] or 'No description'} ({trans[4][:10]})")
            else:
                st.info("No recent transactions")

def show_transfer_page(accounts):
    """Display money transfer page"""
    st.markdown("### Transfer Money")
    
    if len(accounts) < 1:
        st.warning("You need at least one account to make transfers")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Transfer Details")
        
        with st.form("transfer_form"):
            from_account = st.selectbox(
                "From Account",
                options=[(acc['id'], f"{acc['type']} - {acc['number']} (${acc['balance']:,.2f})") for acc in accounts],
                format_func=lambda x: x[1]
            )
            
            to_account_number = st.text_input("To Account Number", placeholder="Enter recipient account number")
            amount = st.number_input("Amount", min_value=0.01, step=0.01, format="%.2f")
            description = st.text_input("Description (Optional)", placeholder="Enter transfer description")
            
            transfer_button = st.form_submit_button("Transfer Money", use_container_width=True)
            
            if transfer_button:
                if from_account and to_account_number and amount > 0:
                    success, message = banking_system.transfer_money(
                        from_account[0], to_account_number, amount, description
                    )
                    if success:
                        st.success(message)
                        st.balloons()
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(message)
                else:
                    st.error("Please fill in all required fields")
    
    with col2:
        st.markdown("#### Transfer Guidelines")
        st.info("""
        **Important Information:**
        - Transfers are processed immediately
        - Daily transfer limit: $10,000
        - Verify recipient account number carefully
        - Keep transaction records for your files
        """)
        
        st.markdown("#### Quick Transfer")
        st.markdown("Transfer between your own accounts:")
        
        if len(accounts) >= 2:
            for i, acc1 in enumerate(accounts):
                for acc2 in accounts[i+1:]:
                    if st.button(f"Transfer from {acc1['type']} to {acc2['type']}", key=f"quick_{acc1['id']}_{acc2['id']}"):
                        st.session_state['quick_transfer'] = {
                            'from': acc1['id'],
                            'to': acc2['number']
                        }

def show_transactions_page(accounts):
    """Display transactions history page"""
    st.markdown("### Transaction History")
    
    if not accounts:
        st.warning("No accounts found")
        return
    
    # Account selector
    selected_account = st.selectbox(
        "Select Account",
        options=[(acc['id'], f"{acc['type']} - {acc['number']}") for acc in accounts],
        format_func=lambda x: x[1]
    )
    
    # Get transactions for selected account
    transactions = banking_system.get_account_transactions(selected_account[0], 50)
    
    if transactions:
        # Create DataFrame for better display
        df = pd.DataFrame(transactions, columns=['Type', 'Amount', 'Description', 'Recipient', 'Date'])
        df['Date'] = pd.to_datetime(df['Date']).dt.strftime('%Y-%m-%d %H:%M')
        df['Amount'] = df['Amount'].apply(lambda x: f"${x:,.2f}")
        
        st.dataframe(df, use_container_width=True)
        
        # Transaction summary
        st.markdown("### Transaction Summary")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Transactions", len(transactions))
        
        with col2:
            credits = sum(t[1] for t in transactions if t[1] > 0)
            st.metric("Total Credits", f"${credits:,.2f}")
        
        with col3:
            debits = sum(abs(t[1]) for t in transactions if t[1] < 0)
            st.metric("Total Debits", f"${debits:,.2f}")
    else:
        st.info("No transactions found for this account")

def show_settings_page():
    """Display settings page"""
    st.markdown("### Account Settings")
    
    tab1, tab2, tab3 = st.tabs(["Profile", "Security", "Notifications"])
    
    with tab1:
        st.markdown("#### Profile Information")
        st.info("Profile update feature coming soon!")
        
        with st.form("profile_form"):
            st.text_input("Full Name", value="John Doe", disabled=True)
            st.text_input("Email", value="john@example.com", disabled=True)
            st.text_input("Phone", value="(555) 123-4567", disabled=True)
            st.form_submit_button("Update Profile", disabled=True)
    
    with tab2:
        st.markdown("#### Security Settings")
        
        with st.form("security_form"):
            st.text_input("Current Password", type="password")
            st.text_input("New Password", type="password")
            st.text_input("Confirm New Password", type="password")
            
            if st.form_submit_button("Change Password"):
                st.success("Password change feature coming soon!")
        
        st.markdown("#### Two-Factor Authentication")
        if st.checkbox("Enable 2FA", value=True):
            st.success("2FA is currently enabled")
        
        st.markdown("#### Login History")
        st.info("Login history feature coming soon!")
    
    with tab3:
        st.markdown("#### Notification Preferences")
        
        st.checkbox("Email notifications for transactions", value=True)
        st.checkbox("SMS notifications for large transactions", value=False)
        st.checkbox("Monthly account statements", value=True)
        st.checkbox("Security alerts", value=True)
        st.checkbox("Marketing communications", value=False)
        
        if st.button("Save Notification Settings"):
            st.success("Notification preferences updated!")

# Main application logic
def main():
    """Main application entry point"""
    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state['authenticated'] = False
    if 'auth_step' not in st.session_state:
        st.session_state['auth_step'] = 'login'
    if 'show_signup' not in st.session_state:
        st.session_state['show_signup'] = False
    
    # Route to appropriate page
    if not st.session_state['authenticated']:
        if st.session_state.get('show_signup', False):
            show_signup_page()
        elif st.session_state.get('auth_step') == 'mfa':
            show_mfa_page()
        else:
            show_login_page()
    else:
        show_dashboard()

if __name__ == "__main__":
    main()