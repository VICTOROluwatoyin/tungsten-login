import os
import uuid
import boto3
import json
import time
import logging
import hmac
import hashlib
import base64
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from config import Config
from models import db, ShortLink
import random
import string
from aws_config import configure_aws_credentials

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
app.wsgi_app = ProxyFix(app.wsgi_app)

# Initialize the mail extension
mail = Mail(app)

# Initialize SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tungsten.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Create database tables if they don't exist
with app.app_context():
    db.create_all()

# Configure AWS credentials
configure_aws_credentials()

# Initialize AWS Cognito client
cognito_client = boto3.client(
    'cognito-idp',
    region_name=app.config['AWS_REGION']
)

# Serializer for generating secure tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Helper function to calculate SECRET_HASH
def get_secret_hash(username):
    msg = username + app.config['COGNITO_APP_CLIENT_ID']
    dig = hmac.new(
        str(app.config['COGNITO_APP_CLIENT_SECRET']).encode('utf-8'), 
        msg=msg.encode('utf-8'), 
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

# User roles
ROLES = {
    'admin': 'Admin Dashboard',
    'staff': 'Staff Dashboard',
    'client': 'Client Dashboard'
}

# Authentication decorator for routes
def login_required(allowed_roles=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                flash('Please log in to access this page', 'warning')
                return redirect(url_for('login'))
            
            if allowed_roles and session['user']['role'] not in allowed_roles:
                flash('You do not have permission to access this page', 'danger')
                return redirect(url_for('dashboard'))
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Simple test route to verify application is working
@app.route('/test')
def test():
    return "Application is working correctly!"

# Home route
@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Validate email
        if not email:
            flash('Email is required', 'danger')
            return render_template('login.html')
        
        try:
            # Check if user exists in Cognito
            try:
                user_info = cognito_client.admin_get_user(
                    UserPoolId=app.config['COGNITO_USER_POOL_ID'],
                    Username=email
                )
                
                # User exists, send OTP via forgot password flow
                try:
                    # This will send a verification code to the user's email
                    cognito_client.forgot_password(
                        ClientId=app.config['COGNITO_APP_CLIENT_ID'],
                        SecretHash=get_secret_hash(email),
                        Username=email
                    )
                    
                    logger.info(f"One-time password sent to {email} via AWS Cognito")
                    flash('A one-time password has been sent to your email. Please check your inbox.', 'success')
                    return redirect(url_for('verify_otp', email=email))
                    
                except Exception as e:
                    logger.error(f"Error sending OTP: {str(e)}")
                    flash('Error sending one-time password. Please try again later.', 'danger')
                    return render_template('login.html')
                
            except Exception as e:
                if 'UserNotFoundException' in str(e):
                    flash('Email not registered. Please contact your administrator.', 'danger')
                else:
                    logger.error(f"Error checking user: {str(e)}")
                    flash('An error occurred. Please try again.', 'danger')
                return render_template('login.html')
                
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('An error occurred. Please try again.', 'danger')
            return render_template('login.html')
    
    return render_template('login.html')

# Verify OTP route
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        email = request.form.get('email')
        otp = request.form.get('otp')
        
        if not email or not otp:
            flash('Email and one-time password are required', 'danger')
            return render_template('verify_otp.html', email=email)
        
        # Trim any whitespace from the OTP
        otp = otp.strip()
        
        try:
            # Generate a random secure password that the user won't need to remember
            # Ensure it includes letters, numbers, and special characters to meet Cognito requirements
            import secrets
            import string
            
            # Ensure we have at least one of each required character type
            letters = ''.join(secrets.choice(string.ascii_letters) for _ in range(10))
            digits = ''.join(secrets.choice(string.digits) for _ in range(5))
            special_chars = ''.join(secrets.choice('!@#$%^&*()_+-=[]{}|;:,.<>?') for _ in range(5))
            
            # Combine and shuffle
            all_chars = list(letters + digits + special_chars)
            secrets.SystemRandom().shuffle(all_chars)
            temp_password = ''.join(all_chars)
            
            # Confirm the forgot password flow with the OTP
            cognito_client.confirm_forgot_password(
                ClientId=app.config['COGNITO_APP_CLIENT_ID'],
                SecretHash=get_secret_hash(email),
                Username=email,
                ConfirmationCode=otp,
                Password=temp_password
            )
            
            # Since we can't use USER_PASSWORD_AUTH or ADMIN_NO_SRP_AUTH, let's use a different approach
            # We'll set the user's session directly after confirming the OTP
            
            # Get user info from Cognito
            user_response = cognito_client.admin_get_user(
                UserPoolId=app.config['COGNITO_USER_POOL_ID'],
                Username=email
            )
            
            # Extract user attributes
            user_attrs = {}
            for attr in user_response['UserAttributes']:
                user_attrs[attr['Name']] = attr['Value']
            
            # Set up user session
            session['user'] = {
                'email': email,
                'name': user_attrs.get('name', email),
                'role': user_attrs.get('custom:role', 'client')
            }
            
            # Redirect based on role
            role = user_attrs.get('custom:role', 'client')
            flash('Login successful!', 'success')
            return redirect(url_for(f'{role}_dashboard'))
            
        except Exception as e:
            logger.error(f"Error verifying OTP: {str(e)}")
            flash('Authentication failed. Please check your one-time password and try again.', 'danger')
            return render_template('verify_otp.html', email=email)
    
    # GET request - show the form
    email = request.args.get('email', '')
    return render_template('verify_otp.html', email=email)

# Confirm forgot password route
@app.route('/confirm_forgot_password', methods=['GET', 'POST'])
def confirm_forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        verification_code = request.form.get('verification_code')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not email or not verification_code or not new_password or not confirm_password:
            flash('All fields are required', 'danger')
            return render_template('confirm_forgot_password.html', email=email)
        
        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('confirm_forgot_password.html', email=email)
        
        try:
            # Confirm forgot password with Cognito
            cognito_client.confirm_forgot_password(
                ClientId=app.config['COGNITO_APP_CLIENT_ID'],
                SecretHash=get_secret_hash(email),
                Username=email,
                ConfirmationCode=verification_code,
                Password=new_password
            )
            
            try:
                auth_response = cognito_client.initiate_auth(
                    ClientId=app.config['COGNITO_APP_CLIENT_ID'],
                    SecretHash=get_secret_hash(email),
                    AuthFlow='USER_PASSWORD_AUTH',
                    AuthParameters={
                        'USERNAME': email,
                        'PASSWORD': new_password,
                        'SECRET_HASH': get_secret_hash(email)
                    }
                )
                
                # Store tokens in session
                session['id_token'] = auth_response['AuthenticationResult']['IdToken']
                session['access_token'] = auth_response['AuthenticationResult']['AccessToken']
                session['refresh_token'] = auth_response['AuthenticationResult']['RefreshToken']
                
                # Get user info
                user_info = get_user_info(email)
                session['user'] = user_info
                
                # Redirect based on role
                role = user_info.get('custom:role', 'client')
                flash('Password has been reset successfully!', 'success')
                return redirect(url_for(f'{role}_dashboard'))
                
            except Exception as e:
                logger.error(f"Error during authentication after password reset: {str(e)}")
                flash('Password reset successful. Please log in with your new password.', 'success')
                return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Error confirming password reset: {str(e)}")
            flash('Error confirming password reset. Please check your verification code and try again.', 'danger')
            return render_template('confirm_forgot_password.html', email=email)
    
    # GET request - show the form
    email = request.args.get('email', '')
    return render_template('confirm_forgot_password.html', email=email)

# Password verification route
@app.route('/verify_password', methods=['GET', 'POST'])
def verify_password():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Email and password are required', 'danger')
            return render_template('verify_password.html', email=email)
        
        try:
            # Attempt to authenticate with the temporary password
            auth_response = cognito_client.admin_initiate_auth(
                UserPoolId=app.config['COGNITO_USER_POOL_ID'],
                ClientId=app.config['COGNITO_APP_CLIENT_ID'],
                AuthFlow='ADMIN_NO_SRP_AUTH',
                AuthParameters={
                    'USERNAME': email,
                    'PASSWORD': password,
                    'SECRET_HASH': get_secret_hash(email)
                }
            )
            
            # Check if we need to change password
            if 'ChallengeName' in auth_response and auth_response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
                # Store challenge session for the next step
                session['challenge_session'] = auth_response['Session']
                session['challenge_email'] = email
                return redirect(url_for('new_password'))
            
            # If no challenge, user is authenticated
            if 'AuthenticationResult' in auth_response:
                # Store tokens in session
                session['id_token'] = auth_response['AuthenticationResult']['IdToken']
                session['access_token'] = auth_response['AuthenticationResult']['AccessToken']
                session['refresh_token'] = auth_response['AuthenticationResult']['RefreshToken']
                
                # Get user attributes
                user_info = get_user_info(email)
                session['user'] = user_info
                
                # Redirect based on role
                role = user_info.get('custom:role', 'client')
                return redirect(url_for(f'{role}_dashboard'))
            
            flash('Authentication failed. Please try again.', 'danger')
            return render_template('verify_password.html', email=email)
            
        except Exception as e:
            logger.error(f"Error during password verification: {str(e)}")
            flash('Authentication failed. Please check your temporary password and try again.', 'danger')
            return render_template('verify_password.html', email=email)
    
    # GET request - show the form
    email = request.args.get('email', '')
    return render_template('verify_password.html', email=email)

# New password route (for temporary password flow)
@app.route('/new_password', methods=['GET', 'POST'])
def new_password():
    # Check if we have a challenge session
    if 'challenge_session' not in session or 'challenge_email' not in session:
        flash('No active password reset session. Please start again.', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate passwords
        if not new_password or not confirm_password:
            flash('Please enter and confirm your new password', 'warning')
            return render_template('new_password.html')
        
        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('new_password.html')
        
        try:
            # Complete the auth challenge with the new password
            auth_response = cognito_client.admin_respond_to_auth_challenge(
                UserPoolId=app.config['COGNITO_USER_POOL_ID'],
                ClientId=app.config['COGNITO_APP_CLIENT_ID'],
                ChallengeName='NEW_PASSWORD_REQUIRED',
                ChallengeResponses={
                    'USERNAME': session['challenge_email'],
                    'NEW_PASSWORD': new_password,
                    'SECRET_HASH': get_secret_hash(session['challenge_email'])
                },
                Session=session['challenge_session']
            )
            
            # Clear challenge data
            session.pop('challenge_session', None)
            session.pop('challenge_email', None)
            
            # Store tokens in session
            session['id_token'] = auth_response['AuthenticationResult']['IdToken']
            session['access_token'] = auth_response['AuthenticationResult']['AccessToken']
            session['refresh_token'] = auth_response['AuthenticationResult']['RefreshToken']
            
            # Get user info
            user_info = get_user_info(session['challenge_email'])
            session['user'] = user_info
            
            # Redirect based on role
            role = user_info.get('custom:role', 'client')
            flash('Password updated successfully!', 'success')
            return redirect(url_for(f'{role}_dashboard'))
            
        except Exception as e:
            logger.error(f"Error setting new password: {str(e)}")
            flash('Error setting new password. Please try again.', 'danger')
            return render_template('new_password.html')
    
    return render_template('new_password.html')

# Token verification route (remove this as we're not using magic links anymore)
@app.route('/verify/<token>')
def verify_token(token):
    flash('This login method is no longer supported. Please use the temporary password sent to your email.', 'warning')
    return redirect(url_for('login'))

# Dashboard route - redirects to appropriate dashboard based on role
@app.route('/dashboard')
@login_required()
def dashboard():
    role = session['user']['role']
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'staff':
        return redirect(url_for('staff_dashboard'))
    else:  # client
        return redirect(url_for('client_dashboard'))

# Admin dashboard
@app.route('/admin/dashboard')
@login_required(['admin'])
def admin_dashboard():
    try:
        # Get all users from Cognito
        response = cognito_client.list_users(
            UserPoolId=app.config['COGNITO_USER_POOL_ID'],
            Limit=60
        )
        
        # Process users
        staff_users = []
        client_users = []
        
        for user in response.get('Users', []):
            # Extract attributes
            user_attrs = {}
            for attr in user.get('Attributes', []):
                user_attrs[attr['Name']] = attr['Value']
            
            # Create user data object
            user_data = {
                'username': user.get('Username'),
                'status': user.get('UserStatus'),
                'enabled': user.get('Enabled', True),
                'created_date': user.get('UserCreateDate').strftime('%Y-%m-%d') if user.get('UserCreateDate') else 'N/A',
                'email': user_attrs.get('email', ''),
                'role': user_attrs.get('custom:role', ''),
                'company_id': user_attrs.get('custom:company_id', '')
            }
            
            # Sort users by role
            if user_data['role'] == 'staff':
                staff_users.append(user_data)
            elif user_data['role'] == 'client':
                client_users.append(user_data)
        
        # Pass dashboard_route and current_user_role for the sidebar navigation
        return render_template('admin_dashboard_new.html', 
                              staff_users=staff_users, 
                              client_users=client_users,
                              dashboard_route='admin_dashboard',
                              current_user_role='admin',
                              active_page='dashboard')
    except Exception as e:
        logger.error(f"Error fetching users: {str(e)}")
        flash(f"Error fetching users: {str(e)}", 'danger')
        return render_template('admin_dashboard_new.html', 
                              staff_users=[], 
                              client_users=[],
                              dashboard_route='admin_dashboard',
                              current_user_role='admin',
                              active_page='dashboard')

# Staff dashboard
@app.route('/staff/dashboard')
@login_required(['staff'])
def staff_dashboard():
    try:
        # Get client users from Cognito
        response = cognito_client.list_users(
            UserPoolId=app.config['COGNITO_USER_POOL_ID'],
            Limit=60  # Adjust as needed
        )
        
        # Process users
        client_users = []
        
        for user in response.get('Users', []):
            # Extract attributes first
            user_attrs = {}
            for attr in user.get('Attributes', []):
                user_attrs[attr['Name']] = attr['Value']
            
            # Only include users with role = client
            if user_attrs.get('custom:role') == 'client':
                user_data = {
                    'username': user.get('Username'),
                    'status': user.get('UserStatus'),
                    'enabled': user.get('Enabled', True),
                    'created_date': user.get('UserCreateDate').strftime('%Y-%m-%d') if user.get('UserCreateDate') else 'N/A',
                    'email': user_attrs.get('email', ''),
                    'company_id': user_attrs.get('custom:company_id', '')
                }
                
                client_users.append(user_data)
        
        return render_template('staff_dashboard_new.html', 
                              client_users=client_users,
                              dashboard_route='staff_dashboard',
                              current_user_role='staff',
                              active_page='dashboard')
    except Exception as e:
        logger.error(f"Error fetching users: {str(e)}")
        flash(f"Error fetching users: {str(e)}", 'danger')
        return render_template('staff_dashboard_new.html', 
                              client_users=[],
                              dashboard_route='staff_dashboard',
                              current_user_role='staff',
                              active_page='dashboard')

# Admin route to add a new user (staff or client)
@app.route('/admin/add_user', methods=['POST'])
@login_required(['admin'])
def add_user():
    email = request.form.get('email')
    role = request.form.get('role')
    company_name = request.form.get('company_name', '')
    company_id = request.form.get('company_id', '')
    
    # Generate company_id if not provided and it's a client
    if role == 'client':
        if not company_id:
            if company_name:
                # Create a company_id from company name (slugified)
                company_id = company_name.lower().replace(' ', '-')
            else:
                # Generate a random company_id
                company_id = f"company-{uuid.uuid4().hex[:8]}"
        
        # Store the company_id for display in the flash message
        display_company_id = company_id
    else:
        # Not a client, so no company_id needed
        company_id = ''
        display_company_id = ''
    
    # Create user attributes
    user_attributes = [
        {'Name': 'email', 'Value': email},
        {'Name': 'email_verified', 'Value': 'true'},
        {'Name': 'custom:role', 'Value': role}
    ]
    
    if role == 'client' and company_id:
        user_attributes.append({'Name': 'custom:company_id', 'Value': company_id})
    
    try:
        # Generate a secure random password that meets Cognito requirements
        import secrets
        import string
        letters = ''.join(secrets.choice(string.ascii_letters) for _ in range(10))
        digits = ''.join(secrets.choice(string.digits) for _ in range(5))
        special_chars = ''.join(secrets.choice('!@#$%^&*()_+-=[]{}|;:,.<>?') for _ in range(5))
        all_chars = list(letters + digits + special_chars)
        secrets.SystemRandom().shuffle(all_chars)
        temp_password = ''.join(all_chars)
        
        # Create the user in Cognito
        response = cognito_client.admin_create_user(
            UserPoolId=app.config['COGNITO_USER_POOL_ID'],
            Username=email,
            UserAttributes=user_attributes,
            TemporaryPassword=temp_password,
            MessageAction='SUPPRESS'  # Don't send welcome email
        )
        
        # Set the user's password and mark as confirmed
        cognito_client.admin_set_user_password(
            UserPoolId=app.config['COGNITO_USER_POOL_ID'],
            Username=email,
            Password=temp_password,
            Permanent=True  # This makes the password permanent and confirms the user
        )
        
        # Ensure the user is confirmed and can use OTP login
        cognito_client.admin_update_user_attributes(
            UserPoolId=app.config['COGNITO_USER_POOL_ID'],
            Username=email,
            UserAttributes=[
                {'Name': 'email_verified', 'Value': 'true'}
            ]
        )
        
        if role == 'client' and display_company_id:
            flash(f'User {email} added successfully as {role} with Company ID: {display_company_id}!', 'success')
        else:
            flash(f'User {email} added successfully as {role}!', 'success')
    except Exception as e:
        logger.error(f"Error adding user: {str(e)}")
        flash(f'Error adding user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

# Admin route to edit a user
@app.route('/admin/edit_user/<username>', methods=['GET', 'POST'])
@login_required(['admin'])
def edit_user(username):
    if request.method == 'POST':
        # Get form data
        email = request.form.get('email')
        role = request.form.get('role')
        company_name = request.form.get('company_name', '')
        company_id = request.form.get('company_id', '')
        
        # Generate company_id if not provided and it's a client
        if role == 'client':
            if not company_id:
                if company_name:
                    # Create a company_id from company name (slugified)
                    company_id = company_name.lower().replace(' ', '-')
                else:
                    # Generate a random company_id
                    company_id = f"company-{uuid.uuid4().hex[:8]}"
        
        # Create user attributes
        user_attributes = [
            {'Name': 'custom:role', 'Value': role}
        ]
        
        if role == 'client' and company_id:
            user_attributes.append({'Name': 'custom:company_id', 'Value': company_id})
        
        try:
            # Update the user in Cognito
            response = cognito_client.admin_update_user_attributes(
                UserPoolId=app.config['COGNITO_USER_POOL_ID'],
                Username=username,
                UserAttributes=user_attributes
            )
            
            flash(f'User {username} updated successfully!', 'success')
        except Exception as e:
            logger.error(f"Error updating user: {str(e)}")
            flash(f'Error updating user: {str(e)}', 'danger')
        
        return redirect(url_for('admin_dashboard'))
    
    # GET request - show the form with user data
    try:
        # Get user data from Cognito
        response = cognito_client.admin_get_user(
            UserPoolId=app.config['COGNITO_USER_POOL_ID'],
            Username=username
        )
        
        # Extract user attributes
        user_data = {
            'username': username,
            'email': '',
            'role': '',
            'company_id': '',
            'status': response.get('UserStatus', '')
        }
        
        for attr in response.get('UserAttributes', []):
            if attr['Name'] == 'email':
                user_data['email'] = attr['Value']
            elif attr['Name'] == 'custom:role':
                user_data['role'] = attr['Value']
            elif attr['Name'] == 'custom:company_id':
                user_data['company_id'] = attr['Value']
        
        return render_template('edit_user.html', user=user_data)
    except Exception as e:
        logger.error(f"Error getting user data: {str(e)}")
        flash(f'Error getting user data: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))

# Admin route to delete a user
@app.route('/admin/delete_user/<username>', methods=['POST'])
@login_required(['admin'])
def delete_user(username):
    try:
        # Delete the user from Cognito
        response = cognito_client.admin_delete_user(
            UserPoolId=app.config['COGNITO_USER_POOL_ID'],
            Username=username
        )
        
        flash(f'User {username} deleted successfully!', 'success')
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

# Logout route
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Context processor to make current year available to all templates
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

# Helper function to generate a magic link token
def generate_magic_link_token(email):
    # Create token with email and timestamp
    payload = {
        'email': email,
        'timestamp': time.time()
    }
    token = serializer.dumps(payload)
    return token

# Helper function to verify a magic link token
def verify_magic_link_token(token):
    # Verify token with expiry (default is 15 minutes)
    payload = serializer.loads(token, max_age=app.config['MAGIC_LINK_EXPIRY'] * 60)
    return payload['email']

# Helper function to send a magic link email
def send_magic_link_email(email, magic_link):
    try:
        msg = Message('Your Tungsten Login Link', 
                      sender=app.config['MAIL_DEFAULT_SENDER'],
                      recipients=[email])
        msg.html = render_template('email/magic_link.html', magic_link=magic_link)
        
        # Check if this is a development environment or if email credentials are missing
        if app.debug or not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
            # Development mode or missing credentials - print to console instead of sending
            print("\n------------------------")
            print("MAGIC LINK EMAIL")
            print("To:", email)
            print("From:", app.config['MAIL_DEFAULT_SENDER'])
            print("Subject: Your Tungsten Login Link")
            print("------------------------")
            print("Magic Link URL:", magic_link)
            print("------------------------\n")
            return True
        else:
            # Production mode with valid credentials - send the email
            mail.send(msg)
            return True
    except Exception as e:
        logger.error(f"Error sending magic link email: {str(e)}")
        return False

# Helper function to send an invitation email
def send_invitation_email(email, role, magic_link):
    try:
        msg = Message(f'Invitation to Tungsten as {role.capitalize()}', 
                      sender=app.config['MAIL_DEFAULT_SENDER'],
                      recipients=[email])
        msg.html = render_template('email/invitation.html', magic_link=magic_link, role=role)
        
        # Check if this is a development environment or if email credentials are missing
        if app.debug or not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
            # Development mode or missing credentials - print to console instead of sending
            print("\n------------------------")
            print("INVITATION EMAIL")
            print("To:", email)
            print("From:", app.config['MAIL_DEFAULT_SENDER'])
            print("Subject: Invitation to Tungsten as", role.capitalize())
            print("------------------------")
            print("Magic Link URL:", magic_link)
            print("------------------------\n")
            return True
        else:
            # Production mode with valid credentials - send the email
            mail.send(msg)
            return True
    except Exception as e:
        logger.error(f"Error sending invitation email: {str(e)}")
        return False

def get_user_from_token(token):
    # Get user attributes from token
    user_info = cognito_client.get_user(
        AccessToken=token
    )
    
    # Extract user attributes
    user_attrs = {}
    for attr in user_info['UserAttributes']:
        user_attrs[attr['Name']] = attr['Value']
    
    return {
        'email': user_attrs.get('email', ''),
        'name': user_attrs.get('name', ''),
        'role': user_attrs.get('custom:role', 'client')
    }

def get_user_info(email):
    # Get user attributes from Cognito
    user_response = cognito_client.admin_get_user(
        UserPoolId=app.config['COGNITO_USER_POOL_ID'],
        Username=email
    )
    
    # Extract user attributes
    user_attrs = {}
    for attr in user_response['UserAttributes']:
        user_attrs[attr['Name']] = attr['Value']
    
    return {
        'email': email,
        'name': user_attrs.get('name', email),
        'role': user_attrs.get('custom:role', 'client')
    }

# Client dashboard
@app.route('/client/dashboard')
@login_required(['client'])
def client_dashboard():
    # Get company_id from session
    company_id = session['user'].get('custom:company_id', '')
    
    try:
        # If we have a company_id, get other users from the same company
        team_members = []
        if company_id:
            response = cognito_client.list_users(
                UserPoolId=app.config['COGNITO_USER_POOL_ID'],
                Filter=f"custom:company_id = \"{company_id}\"",
                Limit=60
            )
            
            for user in response.get('Users', []):
                user_email = ''
                for attr in user.get('Attributes', []):
                    if attr['Name'] == 'email':
                        user_email = attr['Value']
                        break
                
                # Don't include the current user in the team members list
                if user_email and user_email != session['user']['email']:
                    team_members.append({
                        'email': user_email,
                        'status': user.get('UserStatus'),
                        'created_date': user.get('UserCreateDate').strftime('%Y-%m-%d') if user.get('UserCreateDate') else 'N/A'
                    })
        
        # Add current datetime to the template context
        from datetime import datetime, timedelta
        now = datetime.now()
        
        return render_template('client_dashboard_new.html', 
                              team_members=team_members, 
                              now=now,
                              dashboard_route='client_dashboard',
                              current_user_role='client',
                              active_page='dashboard')
    except Exception as e:
        logger.error(f"Error fetching team members: {str(e)}")
        flash(f"Error fetching team members: {str(e)}", 'danger')
        # Also include the datetime here
        from datetime import datetime, timedelta
        now = datetime.now()
        return render_template('client_dashboard_new.html', 
                              team_members=[], 
                              now=now,
                              dashboard_route='client_dashboard',
                              current_user_role='client',
                              active_page='dashboard')

# Link shortener routes
@app.route('/tools/link-shortener')
@login_required(['admin', 'staff', 'client'])
def link_shortener():
    # Get user's shortened links
    user_email = session.get('user', {}).get('email')
    links = ShortLink.query.filter_by(created_by=user_email).order_by(ShortLink.created_at.desc()).all()
    
    # Get user role for navigation
    user_role = session.get('user', {}).get('custom:role', '')
    if not user_role and 'role' in session.get('user', {}):
        user_role = session['user']['role']
    
    # Default to client if role is still not found
    if not user_role:
        user_role = 'client'
    
    return render_template('link_shortener.html', 
                          links=links,
                          dashboard_route=f"{user_role}_dashboard",
                          current_user_role=user_role,
                          active_page='tools')

@app.route('/tools/link-shortener/create', methods=['POST'])
@login_required(['admin', 'staff', 'client'])
def create_short_link():
    original_url = request.form.get('original_url')
    custom_code = request.form.get('custom_code', '').strip()
    
    if not original_url:
        flash('Please enter a URL to shorten', 'danger')
        return redirect(url_for('link_shortener'))
    
    # Validate URL format
    if not original_url.startswith(('http://', 'https://')):
        original_url = 'https://' + original_url
    
    # Generate short code if not provided
    if not custom_code:
        # Generate a random 6-character code
        short_code = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    else:
        short_code = custom_code
        
        # Check if custom code already exists
        existing_link = ShortLink.query.filter_by(short_code=short_code).first()
        if existing_link:
            flash(f'Custom code "{short_code}" is already in use. Please choose another.', 'danger')
            return redirect(url_for('link_shortener'))
    
    # Create new short link
    user_email = session.get('user', {}).get('email')
    new_link = ShortLink(
        original_url=original_url,
        short_code=short_code,
        created_by=user_email
    )
    
    try:
        db.session.add(new_link)
        db.session.commit()
        flash('Link shortened successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating short link: {str(e)}")
        flash(f'Error creating short link: {str(e)}', 'danger')
    
    return redirect(url_for('link_shortener'))

@app.route('/s/<short_code>')
def redirect_short_link(short_code):
    # Find the short link
    link = ShortLink.query.filter_by(short_code=short_code).first_or_404()
    
    # Increment click count
    link.clicks += 1
    db.session.commit()
    
    # Redirect to the original URL
    return redirect(link.original_url)

@app.route('/tools/link-shortener/delete/<int:link_id>', methods=['POST'])
@login_required(['admin', 'staff', 'client'])
def delete_short_link(link_id):
    link = ShortLink.query.get_or_404(link_id)
    
    # Ensure the user can only delete their own links (except for admins)
    user_role = session.get('user', {}).get('custom:role', '')
    if user_role != 'admin' and link.created_by != session.get('user', {}).get('email'):
        flash('You do not have permission to delete this link', 'danger')
        return redirect(url_for('link_shortener'))
    
    try:
        db.session.delete(link)
        db.session.commit()
        flash('Link deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting short link: {str(e)}")
        flash(f'Error deleting short link: {str(e)}', 'danger')
    
    return redirect(url_for('link_shortener'))

# Redirect the admin URL
@app.route('/admin')
def admin_redirect():
    return redirect('https://tngstn.com/admin')

if __name__ == '__main__':
    app.config['PROPAGATE_EXCEPTIONS'] = True  # Ensure exceptions are propagated to the console
    app.run(debug=True, use_reloader=True)
