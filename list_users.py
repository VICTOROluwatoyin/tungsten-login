import boto3
import os
import json
from config import Config

# Initialize AWS Cognito client
cognito_client = boto3.client(
    'cognito-idp',
    region_name=Config.AWS_REGION,
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
)

def list_all_users():
    """List all users in the Cognito user pool"""
    try:
        # Get the user pool ID from config
        user_pool_id = Config.COGNITO_USER_POOL_ID
        
        print(f"Listing all users in user pool: {user_pool_id}")
        print("-" * 50)
        
        # Get users with pagination
        response = cognito_client.list_users(
            UserPoolId=user_pool_id,
            Limit=60  # Maximum allowed by Cognito
        )
        
        if not response.get('Users'):
            print("No users found in the user pool.")
            return
        
        # Print user information
        print(f"Total users found: {len(response['Users'])}")
        print("-" * 50)
        
        for user in response['Users']:
            username = user['Username']
            status = user['UserStatus']
            created_date = user['UserCreateDate'].strftime('%Y-%m-%d %H:%M:%S')
            
            # Extract attributes
            attributes = {attr['Name']: attr['Value'] for attr in user['Attributes']}
            email = attributes.get('email', 'No email')
            role = attributes.get('custom:role', 'No role')
            
            print(f"Username: {username}")
            print(f"Email: {email}")
            print(f"Status: {status}")
            print(f"Role: {role}")
            print(f"Created: {created_date}")
            print("-" * 50)
            
        # Check if there are more users (pagination)
        if 'PaginationToken' in response:
            print("Note: There are more users. This script shows only the first 60 users.")
            
    except Exception as e:
        print(f"Error listing users: {str(e)}")

if __name__ == "__main__":
    list_all_users()
