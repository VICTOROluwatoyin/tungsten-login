import boto3
import os
import sys
from config import Config

# Initialize AWS Cognito client
cognito_client = boto3.client(
    'cognito-idp',
    region_name=Config.AWS_REGION,
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
)

def create_user(email, role="admin"):
    """
    Create a new user in the Cognito user pool
    
    Args:
        email (str): Email address of the user
        role (str): Role of the user (admin, staff, client)
    """
    try:
        # Get the user pool ID from config
        user_pool_id = Config.COGNITO_USER_POOL_ID
        
        print(f"Creating user with email {email} and role {role} in user pool {user_pool_id}")
        
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
                }
            ],
            MessageAction='SUPPRESS',  # Don't send welcome email, we'll handle login with temp password
            DesiredDeliveryMediums=['EMAIL']
        )
        
        print(f"User created successfully: {email}")
        print(f"User status: {response['User']['UserStatus']}")
        
        return True
        
    except Exception as e:
        print(f"Error creating user: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python create_user.py <email> [role]")
        print("Example: python create_user.py admin@example.com admin")
        sys.exit(1)
        
    email = sys.argv[1]
    role = sys.argv[2] if len(sys.argv) > 2 else "client"
    
    create_user(email, role)
