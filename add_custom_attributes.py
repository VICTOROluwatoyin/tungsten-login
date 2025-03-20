import boto3
import os
from config import Config

# Initialize AWS Cognito client
cognito_client = boto3.client(
    'cognito-idp',
    region_name=Config.AWS_REGION,
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
)

def add_custom_attributes():
    """Add custom attributes to the Cognito user pool"""
    try:
        # Get the user pool ID from config
        user_pool_id = Config.COGNITO_USER_POOL_ID
        
        print(f"Adding custom attributes to user pool: {user_pool_id}")
        
        # Add custom attributes
        response = cognito_client.add_custom_attributes(
            UserPoolId=user_pool_id,
            CustomAttributes=[
                {
                    'Name': 'role',
                    'AttributeDataType': 'String',
                    'DeveloperOnlyAttribute': False,
                    'Mutable': True,
                    'Required': False,
                    'StringAttributeConstraints': {
                        'MinLength': '1',
                        'MaxLength': '20'
                    }
                },
                {
                    'Name': 'company_id',
                    'AttributeDataType': 'String',
                    'DeveloperOnlyAttribute': False,
                    'Mutable': True,
                    'Required': False,
                    'StringAttributeConstraints': {
                        'MinLength': '0',
                        'MaxLength': '50'
                    }
                }
            ]
        )
        
        print("Custom attributes added successfully!")
        return True
        
    except Exception as e:
        print(f"Error adding custom attributes: {str(e)}")
        return False

if __name__ == "__main__":
    add_custom_attributes()
