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

def delete_user(email):
    """Delete a user from the Cognito user pool"""
    try:
        # Get the user pool ID from config
        user_pool_id = Config.COGNITO_USER_POOL_ID
        
        print(f"Deleting user with email {email} from user pool {user_pool_id}")
        
        # Delete the user
        cognito_client.admin_delete_user(
            UserPoolId=user_pool_id,
            Username=email
        )
        
        print(f"User deleted successfully: {email}")
        return True
        
    except Exception as e:
        print(f"Error deleting user: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python delete_user.py <email>")
        print("Example: python delete_user.py admin@example.com")
        sys.exit(1)
        
    email = sys.argv[1]
    delete_user(email)
