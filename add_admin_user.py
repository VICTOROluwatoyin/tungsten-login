import boto3
import os
import uuid
from config import Config

# Initialize AWS Cognito client
cognito_client = boto3.client(
    'cognito-idp',
    region_name=Config.AWS_REGION,
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
)

def add_user(email, role):
    """Add a new user through the normal flow that will send an OTP"""
    try:
        # Create the user
        response = cognito_client.admin_create_user(
            UserPoolId=Config.COGNITO_USER_POOL_ID,
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
            DesiredDeliveryMediums=['EMAIL']
        )
        
        print(f"User {email} added successfully as {role}!")
        print("A one-time password has been sent to their email.")
        return True
    except Exception as e:
        print(f"Error adding user: {str(e)}")
        return False

if __name__ == "__main__":
    # Add admin user
    add_user('mbakshi@tungstenadvertising.com', 'admin')
