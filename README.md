# Netbanker

# NetBanking Application

A secure, modern netbanking application built with Streamlit, featuring comprehensive cybersecurity measures and multi-account management capabilities.

## 🌟 Features

### 🔐 Security & Authentication
- **Multi-Factor Authentication (MFA)** - Enhanced security with multiple verification layers
- **Encrypted Data Storage** - All personal information secured through advanced cryptography
- **Secure Session Management** - Protected user sessions with timeout capabilities
- **Password Security** - Strong password requirements and secure hashing

### 🏦 Banking Capabilities
- **Multiple Account Types**
  - Checking Accounts
  - Savings Accounts
  - CD Investment Accounts
- **Randomized Account Numbers** - Unique, secure account number generation
- **Account-Specific Features** - Different functionalities based on account type
- **Real-time Dashboard** - Comprehensive overview of all customer accounts

### 💻 User Experience
- **Intuitive Web Interface** - Clean, user-friendly design built with Streamlit
- **Responsive Navigation** - Easy-to-use menus and tabs
- **Account Management** - Complete control over account settings and preferences
- **Transaction History** - Detailed records of all banking activities

## 🏗️ Architecture

### Frontend (Streamlit)
- User authentication interface (login/signup)
- Multi-factor authentication flow
- Dashboard with account summaries
- Navigation between different banking functions
- Account management interfaces

### Backend Systems
- User authentication and session management
- Database layer for customer data
- Account number generation system
- Transaction processing
- Security and encryption layers

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- Streamlit
- Database system (PostgreSQL/MySQL recommended)
- Required Python packages (see `requirements.txt`)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd netbanking-app
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your database credentials and security keys
```

4. Initialize the database:
```bash
python setup_database.py
```

5. Run the application:
```bash
streamlit run app.py
```

## 📋 Account Eligibility & Signup

The signup process includes comprehensive eligibility verification:
- Personal information collection
- Identity verification
- Financial background assessment
- Account type selection
- Terms and conditions agreement

All information is encrypted and stored securely in the database.

## 🔒 Security Measures

- **Data Encryption**: All sensitive data encrypted at rest and in transit
- **Secure Account Numbers**: Randomized generation based on account type
- **MFA Integration**: Multiple authentication factors for enhanced security
- **Session Security**: Automatic timeout and secure session handling
- **Audit Logging**: Comprehensive logging of all user activities

## 🗄️ Database Schema

The application uses a secure database structure to store:
- User credentials (encrypted)
- Personal information (encrypted)
- Account details with type-specific configurations
- Transaction history
- Security logs

## 📊 Account Types

### Checking Account
- Daily transaction capabilities
- Debit card access
- Online bill pay
- Mobile check deposit

### Savings Account
- High-yield interest
- Transfer limitations
- Automatic savings plans
- Goal tracking

### CD Investment Account
- Fixed-term deposits
- Competitive interest rates
- Early withdrawal penalties
- Automatic renewal options

## 🛡️ Cybersecurity Features

- End-to-end encryption
- Secure password storage with salt hashing
- Protection against SQL injection
- Cross-site scripting (XSS) prevention
- CSRF token implementation
- Rate limiting for login attempts

## 📱 User Interface

The Streamlit-based interface provides:
- Clean, modern design
- Responsive layout
- Intuitive navigation
- Real-time updates
- Mobile-friendly experience

## 🔧 Configuration

Key configuration options:
- Database connection settings
- Security parameters
- MFA settings
- Session timeout values
- Encryption keys
  
## ⚠️ Security Notice

This application handles sensitive financial data. Ensure all security measures are properly implemented before deployment in a production environment.
