"""
Main Streamlit Application for NetBanking System
"""

import streamlit as st
from auth import AuthenticationManager
from database import DatabaseManager
from dashboard import BankingDashboard
from security import SecurityManager
from accounts import AccountManager
from mfa import MFAManager

class NetBankingApp:
    def __init__(self):
        self.auth_manager = AuthenticationManager()
        self.db_manager = DatabaseManager()
        self.security_manager = SecurityManager()
        self.account_manager = AccountManager()
        self.mfa_manager = MFAManager()
        self.dashboard = BankingDashboard()
        
        # Initialize database on startup
        self.db_manager.initialize_database()
    
    def run(self):
        """Main application runner"""
        st.set_page_config(
            page_title="SecureBank",
            page_icon="🏦",
            layout="wide"
        )
        
        # Initialize session state
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
            st.session_state.user_id = None
            st.session_state.mfa_verified = False
        
        # Main application flow
        if not st.session_state.authenticated:
            self.show_login_page()
        elif not st.session_state.mfa_verified:
            self.show_mfa_page()
        else:
            self.show_dashboard()
    
    def show_login_page(self):
        """Display login/signup interface"""
        st.title("🏦 SecureBank Login")
        
        tab1, tab2 = st.tabs(["Login", "Sign Up"])
        
        with tab1:
            self.handle_login()
        
        with tab2:
            self.handle_signup()
    
    def handle_login(self):
        """Handle user login"""
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login")
            
            if submit:
                if self.auth_manager.validate_login(username, password):
                    st.session_state.authenticated = True
                    st.session_state.user_id = self.auth_manager.get_user_id(username)
                    st.rerun()
                else:
                    st.error("Invalid credentials")
    
    def handle_signup(self):
        """Handle new user registration"""
        with st.form("signup_form"):
            # Personal Information
            st.subheader("Personal Information")
            first_name = st.text_input("First Name")
            last_name = st.text_input("Last Name")
            email = st.text_input("Email")
            phone = st.text_input("Phone Number")
            
            # Address Information
            st.subheader("Address Information")
            address = st.text_area("Street Address")
            city = st.text_input("City")
            state = st.text_input("State")
            zip_code = st.text_input("ZIP Code")
            
            # Account Information
            st.subheader("Account Setup")
            username = st.text_input("Choose Username")
            password = st.text_input("Choose Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            
            # Eligibility Questions
            st.subheader("Eligibility Information")
            age = st.number_input("Age", min_value=18, max_value=120)
            ssn = st.text_input("Social Security Number (Last 4 digits)", max_chars=4)
            employment = st.selectbox("Employment Status", ["Employed", "Self-Employed", "Unemployed", "Student", "Retired"])
            income = st.number_input("Annual Income", min_value=0)
            
            submit = st.form_submit_button("Create Account")
            
            if submit:
                # Validate and create account
                user_data = {
                    'first_name': first_name,
                    'last_name': last_name,
                    'email': email,
                    'phone': phone,
                    'address': address,
                    'city': city,
                    'state': state,
                    'zip_code': zip_code,
                    'username': username,
                    'password': password,
                    'age': age,
                    'ssn_last4': ssn,
                    'employment': employment,
                    'income': income
                }
                
                if self.validate_signup_data(user_data, confirm_password):
                    if self.auth_manager.create_user(user_data):
                        st.success("Account created successfully! Please login.")
                    else:
                        st.error("Failed to create account. Username may already exist.")
    
    def validate_signup_data(self, user_data, confirm_password):
        """Validate signup form data"""
        if user_data['password'] != confirm_password:
            st.error("Passwords do not match")
            return False
        
        if len(user_data['password']) < 8:
            st.error("Password must be at least 8 characters long")
            return False
        
        if user_data['age'] < 18:
            st.error("Must be 18 or older to open an account")
            return False
        
        return True
    
    def show_mfa_page(self):
        """Display MFA verification"""
        st.title("Multi-Factor Authentication")
        
        if self.mfa_manager.handle_mfa_verification(st.session_state.user_id):
            st.session_state.mfa_verified = True
            st.rerun()
    
    def show_dashboard(self):
        """Display main banking dashboard"""
        self.dashboard.display_dashboard(st.session_state.user_id)

def main():
    app = NetBankingApp()
    app.run()

if __name__ == "__main__":
    main()