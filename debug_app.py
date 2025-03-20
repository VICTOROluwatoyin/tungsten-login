import os
import sys
import uuid
import boto3
import json
import time
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from config import Config

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
app.wsgi_app = ProxyFix(app.wsgi_app)

# Initialize the mail extension
mail = Mail(app)

try:
    # Initialize AWS Cognito client
    cognito_client = boto3.client(
        'cognito-idp',
        region_name=app.config['AWS_REGION'],
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
    )
    logger.info("AWS Cognito client initialized successfully")
except Exception as e:
    logger.error(f"Error initializing AWS Cognito client: {str(e)}")
    sys.exit(1)

# Serializer for generating secure tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# User roles
ROLES = {
    'admin': 'Admin Dashboard',
    'staff': 'Staff Dashboard',
    'client': 'Client Dashboard'
}

# Context processor to make current year available to all templates
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

# Simple test route to verify application is working
@app.route('/test')
def test():
    return "Application is working correctly!"

# Home route
@app.route('/')
def index():
    try:
        logger.info("Accessed home route")
        if 'user' in session:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        return f"Error: {str(e)}", 500

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        logger.info("Accessed login route")
        if request.method == 'POST':
            email = request.form.get('email')
            if not email:
                flash('Please enter an email address', 'warning')
                return render_template('login.html')
            
            # Generate magic link token
            token = generate_magic_link_token(email)
            magic_link = f"{app.config['BASE_URL']}/verify/{token}"
            
            # Send magic link email
            send_magic_link_email(email, magic_link)
            
            flash('Magic link has been sent to your email. Please check your inbox.', 'success')
            return render_template('login_sent.html', email=email)
        
        return render_template('login.html')
    except Exception as e:
        logger.error(f"Error in login route: {str(e)}")
        return f"Error: {str(e)}", 500

# Helper function to generate a magic link token
def generate_magic_link_token(email):
    try:
        # Create token with email and timestamp
        data = {
            'email': email,
            'timestamp': time.time()
        }
        return serializer.dumps(data)
    except Exception as e:
        logger.error(f"Error generating magic link token: {str(e)}")
        raise

# Helper function to send a magic link email
def send_magic_link_email(email, magic_link):
    try:
        msg = Message('Your Login Magic Link', sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[email])
        msg.html = render_template('email/magic_link.html', magic_link=magic_link)
        mail.send(msg)
        logger.info(f"Magic link email sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Error sending magic link email: {str(e)}")
        return False

if __name__ == '__main__':
    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(debug=True, port=5002)
