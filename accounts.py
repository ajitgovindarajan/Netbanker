"""
Account Management System for NetBanking
Handles account creation, transactions, and account number generation
"""

import random
import string
from datetime import datetime
from database import DatabaseManager

class AccountManager:
    def __init__(self):
        self.db_manager = DatabaseManager()
        
        # Account type configurations
        self.account_types = {
            'checking': {
                'prefix': '1001',
                'min_balance': 0.00,
                'interest_rate': 0.01,
                'maintenance_fee': 10.00
            },
            'savings': {
                'prefix': '2001',
                'min_balance': 100.00,
                'interest_rate': 0.02,
                'maintenance_fee': 5.00
            },
            'cd': {
                'prefix': '3001',
                'min_balance': 1000.00,
                'interest_rate': 0.05,
                'maintenance_fee': 0.00
            }
        }
    
    def generate_account_number(self, account_type):
        """Generate unique account number based on account type"""
        # PSEUDOCODE:
        # 1. Get prefix based on account type
        # 2. Generate random 8-digit number
        # 3. Combine prefix with random number
        # 4. Check if number already exists
        # 5. Regenerate if exists, return if unique
        
        if account_type not in self.account_types:
            raise ValueError(f"Invalid account type: {account_type}")
        
        prefix = self.account_types[account_type]['prefix']
        
        # Generate unique account number
        max_attempts = 100
        for _ in range(max_attempts):
            # Generate 8-digit random number
            random_digits = ''.join(random.choices(string.digits, k=8))
            account_number = prefix + random_digits
            
            # Check if account number already exists
            if not self.db_manager.get_account_by_number(account_number):
                return account_number
        
        raise Exception("Unable to generate unique account number")
    
    def create_account(self, user_id, account_type, initial_balance=0.00):
        """Create new account for user"""
        # PSEUDOCODE:
        # 1. Validate account type
        # 2. Check minimum balance requirements
        # 3. Generate account number
        # 4. Create account record in database
        # 5. Create initial transaction if balance > 0
        # 6. Return account details
        
        if account_type not in self.account_types:
            return {'success': False, 'message': 'Invalid account type'}
        
        config = self.account_types[account_type]
        
        # Check minimum balance requirement
        if initial_balance < config['min_balance']:
            return {
                'success': False,
                'message': f'Minimum balance for {account_type} account is ${config["min_balance"]:.2f}'
            }
        
        try:
            # Generate account number
            account_number = self.generate_account_number(account_type)
            
            # Create account in database
            account_id = self.db_manager.create_account(
                user_id=user_id,
                account_type=account_type,
                initial_balance=initial_balance
            )
            
            if account_id:
                # Create initial deposit transaction if balance > 0
                if initial_balance > 0:
                    self.create_transaction(
                        account_id=account_id,
                        transaction_type='deposit',
                        amount=initial_balance,
                        description='Initial deposit'
                    )
                
                return {
                    'success': True,
                    'account_id': account_id,
                    'account_number': account_number,
                    'account_type': account_type,
                    'balance': initial_balance
                }
            else:
                return {'success': False, 'message': 'Failed to create account'}
                
        except Exception as e:
            return {'success': False, 'message': f'Error creating account: {str(e)}'}
    
    def get_user_accounts(self, user_id):
        """Get all accounts for a user"""
        # PSEUDOCODE:
        # 1. Query database for user accounts
        # 2. Format account information
        # 3. Calculate interest if applicable
        # 4. Return account list
        
        accounts = self.db_manager.get_user_accounts(user_id)
        
        formatted_accounts = []
        for account in accounts:
            formatted_account = {
                'account_id': account['account_id'],
                'account_number': account['account_number'],
                'account_type': account['account_type'],
                'balance': account['balance'],
                'interest_rate': account['interest_rate'],
                'created_at': account['created_at'],
                'is_active': account['is_active']
            }
            
            # Add account type specific information
            if account['account_type'] in self.account_types:
                config = self.account_types[account['account_type']]
                formatted_account['min_balance'] = config['min_balance']
                formatted_account['maintenance_fee'] = config['maintenance_fee']
            
            formatted_accounts.append(formatted_account)
        
        return formatted_accounts
    
    def get_account_details(self, account_id):
        """Get detailed account information"""
        # PSEUDOCODE:
        # 1. Get account from database
        # 2. Get recent transactions
        # 3. Calculate account statistics
        # 4. Return comprehensive account details
        
        with self.db_manager.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM accounts WHERE account_id = ?", (account_id,)
            )
            account = cursor.fetchone()
            
            if not account:
                return None
            
            # Get recent transactions
            transactions = self.db_manager.get_account_transactions(account_id, limit=10)
            
            # Calculate statistics
            total_deposits = sum(t['amount'] for t in transactions if t['transaction_type'] == 'deposit')
            total_withdrawals = sum(t['amount'] for t in transactions if t['transaction_type'] == 'withdrawal')
            
            return {
                'account_id': account['account_id'],
                'account_number': account['account_number'],
                'account_type': account['account_type'],
                'balance': account['balance'],
                'interest_rate': account['interest_rate'],
                'created_at': account['created_at'],
                'recent_transactions': transactions,
                'statistics': {
                    'total_deposits': total_deposits,
                    'total_withdrawals': total_withdrawals,
                    'transaction_count': len(transactions)
                }
            }
    
    def deposit_funds(self, account_id, amount, description="Deposit"):
        """Deposit funds to account"""
        # PSEUDOCODE:
        # 1. Validate amount (positive, reasonable)
        # 2. Get current account balance
        # 3. Update account balance
        # 4. Create transaction record
        # 5. Return transaction result
        
        if amount <= 0:
            return {'success': False, 'message': 'Deposit amount must be positive'}
        
        if amount > 10000:  # Daily deposit limit
            return {'success': False, 'message': 'Deposit amount exceeds daily limit of $10,000'}
        
        try:
            # Get current account
            with self.db_manager.get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM accounts WHERE account_id = ?", (account_id,)
                )
                account = cursor.fetchone()
                
                if not account:
                    return {'success': False, 'message': 'Account not found'}
                
                # Calculate new balance
                new_balance = account['balance'] + amount
                
                # Update account balance
                self.db_manager.update_account_balance(account_id, new_balance)
                
                # Create transaction record
                transaction_id = self.create_transaction(
                    account_id=account_id,
                    transaction_type='deposit',
                    amount=amount,
                    description=description
                )
                
                return {
                    'success': True,
                    'transaction_id': transaction_id,
                    'new_balance': new_balance,
                    'amount': amount
                }
                
        except Exception as e:
            return {'success': False, 'message': f'Error processing deposit: {str(e)}'}
    
    def withdraw_funds(self, account_id, amount, description="Withdrawal"):
        """Withdraw funds from account"""
        # PSEUDOCODE:
        # 1. Validate amount (positive, reasonable)
        # 2. Get current account balance
        # 3. Check sufficient funds
        # 4. Check minimum balance requirements
        # 5. Update account balance
        # 6. Create transaction record
        # 7. Return transaction result
        
        if amount <= 0:
            return {'success': False, 'message': 'Withdrawal amount must be positive'}
        
        if amount > 5000:  # Daily withdrawal limit
            return {'success': False, 'message': 'Withdrawal amount exceeds daily limit of $5,000'}
        
        try:
            # Get current account
            with self.db_manager.get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM accounts WHERE account_id = ?", (account_id,)
                )
                account = cursor.fetchone()
                
                if not account:
                    return {'success': False, 'message': 'Account not found'}
                
                # Check sufficient funds
                if account['balance'] < amount:
                    return {'success': False, 'message': 'Insufficient funds'}
                
                # Check minimum balance requirement
                new_balance = account['balance'] - amount
                account_type = account['account_type']
                
                if account_type in self.account_types:
                    min_balance = self.account_types[account_type]['min_balance']
                    if new_balance < min_balance:
                        return {
                            'success': False,
                            'message': f'Withdrawal would violate minimum balance of ${min_balance:.2f}'
                        }
                
                # Update account balance
                self.db_manager.update_account_balance(account_id, new_balance)
                
                # Create transaction record
                transaction_id = self.create_transaction(
                    account_id=account_id,
                    transaction_type='withdrawal',
                    amount=amount,
                    description=description
                )
                
                return {
                    'success': True,
                    'transaction_id': transaction_id,
                    'new_balance': new_balance,
                    'amount': amount
                }
                
        except Exception as e:
            return {'success': False, 'message': f'Error processing withdrawal: {str(e)}'}
    
    def transfer_funds(self, from_account_id, to_account_number, amount, description="Transfer"):
        """Transfer funds between accounts"""
        # PSEUDOCODE:
        # 1. Validate transfer amount
        # 2. Get source account details
        # 3. Get destination account details
        # 4. Check sufficient funds in source account
        # 5. Perform withdrawal from source
        # 6. Perform deposit to destination
        # 7. Create transaction records for both accounts
        # 8. Return transfer result
        
        if amount <= 0:
            return {'success': False, 'message': 'Transfer amount must be positive'}
        
        if amount > 10000:  # Daily transfer limit
            return {'success': False, 'message': 'Transfer amount exceeds daily limit of $10,000'}
        
        try:
            # Get source account
            with self.db_manager.get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM accounts WHERE account_id = ?", (from_account_id,)
                )
                from_account = cursor.fetchone()
                
                if not from_account:
                    return {'success': False, 'message': 'Source account not found'}
                
                # Get destination account
                to_account = self.db_manager.get_account_by_number(to_account_number)
                
                if not to_account:
                    return {'success': False, 'message': 'Destination account not found'}
                
                # Check if transferring to same account
                if from_account['account_id'] == to_account['account_id']:
                    return {'success': False, 'message': 'Cannot transfer to same account'}
                
                # Check sufficient funds
                if from_account['balance'] < amount:
                    return {'success': False, 'message': 'Insufficient funds'}
                
                # Check minimum balance requirement for source account
                new_from_balance = from_account['balance'] - amount
                from_account_type = from_account['account_type']
                
                if from_account_type in self.account_types:
                    min_balance = self.account_types[from_account_type]['min_balance']
                    if new_from_balance < min_balance:
                        return {
                            'success': False,
                            'message': f'Transfer would violate minimum balance of ${min_balance:.2f}'
                        }
                
                # Perform transfer
                new_to_balance = to_account['balance'] + amount
                
                # Update both account balances
                self.db_manager.update_account_balance(from_account['account_id'], new_from_balance)
                self.db_manager.update_account_balance(to_account['account_id'], new_to_balance)
                
                # Create transaction records
                from_transaction_id = self.create_transaction(
                    account_id=from_account['account_id'],
                    transaction_type='transfer_out',
                    amount=amount,
                    description=f"Transfer to {to_account_number}: {description}",
                    recipient_account=to_account_number
                )
                
                to_transaction_id = self.create_transaction(
                    account_id=to_account['account_id'],
                    transaction_type='transfer_in',
                    amount=amount,
                    description=f"Transfer from {from_account['account_number']}: {description}",
                    recipient_account=from_account['account_number']
                )
                
                return {
                    'success': True,
                    'from_transaction_id': from_transaction_id,
                    'to_transaction_id': to_transaction_id,
                    'from_balance': new_from_balance,
                    'to_balance': new_to_balance,
                    'amount': amount
                }
                
        except Exception as e:
            return {'success': False, 'message': f'Error processing transfer: {str(e)}'}
    
    def create_transaction(self, account_id, transaction_type, amount, description, recipient_account=None):
        """Create transaction record"""
        # PSEUDOCODE:
        # 1. Prepare transaction data
        # 2. Insert into database
        # 3. Return transaction_id
        
        transaction_data = {
            'account_id': account_id,
            'transaction_type': transaction_type,
            'amount': amount,
            'description': description,
            'recipient_account': recipient_account
        }
        
        return self.db_manager.create_transaction(transaction_data)
    
    def get_account_transactions(self, account_id, limit=50):
        """Get transaction history for account"""
        # PSEUDOCODE:
        # 1. Query database for account transactions
        # 2. Format transaction data
        # 3. Return transaction list
        
        transactions = self.db_manager.get_account_transactions(account_id, limit)
        
        # Format transactions for display
        formatted_transactions = []
        for transaction in transactions:
            formatted_transaction = {
                'transaction_id': transaction['transaction_id'],
                'transaction_type': transaction['transaction_type'],
                'amount': transaction['amount'],
                'description': transaction['description'],
                'recipient_account': transaction['recipient_account'],
                'created_at': transaction['created_at'],
                'status': transaction['status']
            }
            formatted_transactions.append(formatted_transaction)
        
        return formatted_transactions
    
    def calculate_interest(self, account_id):
        """Calculate and apply interest to account"""
        # PSEUDOCODE:
        # 1. Get account details
        # 2. Calculate interest based on account type and balance
        # 3. Apply interest to account
        # 4. Create interest transaction
        # 5. Return interest amount
        
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM accounts WHERE account_id = ?", (account_id,)
                )
                account = cursor.fetchone()
                
                if not account:
                    return {'success': False, 'message': 'Account not found'}
                
                # Only calculate interest for savings and CD accounts
                if account['account_type'] not in ['savings', 'cd']:
                    return {'success': False, 'message': 'Account type does not earn interest'}
                
                # Calculate monthly interest
                annual_rate = account['interest_rate']
                monthly_rate = annual_rate / 12
                interest_amount = account['balance'] * monthly_rate
                
                if interest_amount > 0:
                    # Apply interest
                    new_balance = account['balance'] + interest_amount
                    self.db_manager.update_account_balance(account_id, new_balance)
                    
                    # Create interest transaction
                    transaction_id = self.create_transaction(
                        account_id=account_id,
                        transaction_type='interest',
                        amount=interest_amount,
                        description='Monthly interest payment'
                    )
                    
                    return {
                        'success': True,
                        'interest_amount': interest_amount,
                        'new_balance': new_balance,
                        'transaction_id': transaction_id
                    }
                else:
                    return {'success': False, 'message': 'No interest earned'}
                    
        except Exception as e:
            return {'success': False, 'message': f'Error calculating interest: {str(e)}'}
    
    def close_account(self, account_id, reason="Customer request"):
        """Close account"""
        # PSEUDOCODE:
        # 1. Get account details
        # 2. Check if account has zero balance
        # 3. Mark account as inactive
        # 4. Create closure transaction
        # 5. Return closure result
        
        try:
            with self.db_manager.get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM accounts WHERE account_id = ?", (account_id,)
                )
                account = cursor.fetchone()
                
                if not account:
                    return {'success': False, 'message': 'Account not found'}
                
                if account['balance'] != 0:
                    return {'success': False, 'message': 'Account must have zero balance to close'}
                
                # Mark account as inactive
                conn.execute(
                    "UPDATE accounts SET is_active = FALSE, updated_at = ? WHERE account_id = ?",
                    (datetime.now(), account_id)
                )
                
                # Create closure transaction
                transaction_id = self.create_transaction(
                    account_id=account_id,
                    transaction_type='closure',
                    amount=0,
                    description=f'Account closed: {reason}'
                )
                
                return {
                    'success': True,
                    'message': 'Account closed successfully',
                    'transaction_id': transaction_id
                }
                
        except Exception as e:
            return {'success': False, 'message': f'Error closing account: {str(e)}'}
    
    def get_account_summary(self, user_id):
        """Get summary of all user accounts"""
        # PSEUDOCODE:
        # 1. Get all user accounts
        # 2. Calculate totals by account type
        # 3. Calculate overall totals
        # 4. Return summary data
        
        accounts = self.get_user_accounts(user_id)
        
        summary = {
            'total_accounts': len(accounts),
            'total_balance': 0,
            'account_types': {
                'checking': {'count': 0, 'balance': 0},
                'savings': {'count': 0, 'balance': 0},
                'cd': {'count': 0, 'balance': 0}
            }
        }
        
        for account in accounts:
            account_type = account['account_type']
            balance = account['balance']
            
            summary['total_balance'] += balance
            
            if account_type in summary['account_types']:
                summary['account_types'][account_type]['count'] += 1
                summary['account_types'][account_type]['balance'] += balance
        
        return summary