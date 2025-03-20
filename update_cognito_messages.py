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

def update_user_pool_messages():
    """Update the message templates for the Cognito user pool"""
    try:
        # Get the user pool ID from config
        user_pool_id = Config.COGNITO_USER_POOL_ID
        
        print(f"Updating message templates for user pool {user_pool_id}")
        
        # Update the message templates
        response = cognito_client.update_user_pool(
            UserPoolId=user_pool_id,
            EmailConfiguration={
                'EmailSendingAccount': 'COGNITO_DEFAULT'
            },
            AdminCreateUserConfig={
                'AllowAdminCreateUserOnly': False,
                'InviteMessageTemplate': {
                    'EmailMessage': 'Your Tungsten username is {username} and temporary password is {####}. Please login at our website to set up your account.',
                    'EmailSubject': 'Your Tungsten temporary password',
                    'SMSMessage': 'Your Tungsten username is {username} and temporary password is {####}'
                }
            },
            VerificationMessageTemplate={
                'EmailMessage': 'Your one-time password is {####}',
                'EmailSubject': 'Your Tungsten one-time password',
                'DefaultEmailOption': 'CONFIRM_WITH_CODE'
            }
        )
        
        print("Message templates updated successfully!")
        return True
        
    except Exception as e:
        print(f"Error updating message templates: {str(e)}")
        return False

if __name__ == "__main__":
    update_user_pool_messages()
