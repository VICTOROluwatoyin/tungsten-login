import boto3
import os
import sys
import hmac
import hashlib
import base64
import uuid
from config import Config

# Initialize AWS Cognito client
cognito_client = boto3.client(
    'cognito-idp',
    region_name=Config.AWS_REGION,
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
)

def get_secret_hash(username):
    """Calculate the secret hash for Cognito API calls"""
    msg = username + Config.COGNITO_APP_CLIENT_ID
    dig = hmac.new(
        str(Config.COGNITO_APP_CLIENT_SECRET).encode('utf-8'), 
        msg=msg.encode('utf-8'), 
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

def create_confirmed_user(email, password, role, company_id=None):
    """Create a new user in Cognito with CONFIRMED status"""
    try:
        # Get the user pool ID from config
        user_pool_id = Config.COGNITO_USER_POOL_ID
        
        print(f"Creating user with email {email} in user pool {user_pool_id}")
        
        # Create the user
        response = cognito_client.admin_create_user(
            UserPoolId=user_pool_id,
            Username=email,
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': email
                },
                {
                    'Name': 'email_verified',
                    'Value': 'true'
                },
                {
                    'Name': 'custom:role',
                    'Value': role
                },
                {
                    'Name': 'custom:company_id',
                    'Value': company_id if company_id else str(uuid.uuid4())
                }
            ],
            MessageAction='SUPPRESS',  # Don't send welcome email
            TemporaryPassword=password
        )
        
        # Set the user's password and mark as confirmed
        cognito_client.admin_set_user_password(
            UserPoolId=user_pool_id,
            Username=email,
            Password=password,
            Permanent=True  # This makes the password permanent and confirms the user
        )
        
        print(f"User created successfully: {email}")
        print(f"Temporary password: {password}")
        return True
        
    except Exception as e:
        print(f"Error creating user: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python create_confirmed_user.py <email> <password> <role> [company_id]")
        print("Example: python create_confirmed_user.py admin@example.com Password123! admin")
        sys.exit(1)
        
    email = sys.argv[1]
    password = sys.argv[2]
    role = sys.argv[3]
    company_id = sys.argv[4] if len(sys.argv) > 4 else None
    
    create_confirmed_user(email, password, role, company_id)
