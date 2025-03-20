import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

# Flask application configuration
class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-for-development')
    DEBUG = os.environ.get('DEBUG', 'True') == 'True'
    
    # AWS Cognito configuration
    AWS_REGION = os.environ.get('AWS_REGION', 'eu-west-2')
    COGNITO_USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID', 'eu-west-2_DkBDsNbxJ')
    COGNITO_APP_CLIENT_ID = os.environ.get('COGNITO_APP_CLIENT_ID', '38eqsomii5hvjluilhfn0um7kh')
    COGNITO_APP_CLIENT_SECRET = os.environ.get('COGNITO_APP_CLIENT_SECRET', '1q6h8pad3ntsjhbd7tv5lar1mt4qfm1i207eg6ntcukv6to21vqh')
    COGNITO_DOMAIN = os.environ.get('COGNITO_DOMAIN', 'https://tungsten-auth-463470954412-v2.auth.eu-west-2.amazoncognito.com')
    JWKS_URL = f'https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json'
    
    # Email configuration for magic links
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'vegbinade@tungstenadvertising.com')
    
    # Application URLs
    BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')
    
    # Magic link configuration
    MAGIC_LINK_EXPIRY = int(os.environ.get('MAGIC_LINK_EXPIRY', 15))  # minutes
