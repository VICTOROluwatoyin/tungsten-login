#!/usr/bin/env python
import boto3
import json
import os
import sys
from botocore.exceptions import ClientError

# AWS Region
REGION = 'eu-west-2'  # Europe (London)

# User Pool Configuration
USER_POOL_NAME = 'Project'
ADMIN_EMAIL = 'vegbinade@tungstenadvertising.com'

def create_user_pool():
    """Create a Cognito User Pool with custom attributes"""
    cognito = boto3.client('cognito-idp', region_name=REGION)
    
    try:
        # Create the user pool with custom attributes
        response = cognito.create_user_pool(
            PoolName=USER_POOL_NAME,
            AutoVerifiedAttributes=['email'],
            AdminCreateUserConfig={
                'AllowAdminCreateUserOnly': True
            },
            Schema=[
                {
                    'Name': 'email',
                    'AttributeDataType': 'String',
                    'Required': True,
                },
                {
                    'Name': 'custom:role',
                    'AttributeDataType': 'String',
                    'Mutable': True,
                },
                {
                    'Name': 'custom:company_id',
                    'AttributeDataType': 'String',
                    'Mutable': True,
                }
            ],
            EmailConfiguration={
                'EmailSendingAccount': 'COGNITO_DEFAULT'
            }
        )
        
        user_pool_id = response['UserPool']['Id']
        print(f"User Pool created successfully: {user_pool_id}")
        
        # Save user pool ID to a file for future reference
        with open('user_pool_info.json', 'w') as f:
            json.dump({'user_pool_id': user_pool_id}, f)
        
        return user_pool_id
    
    except ClientError as e:
        print(f"Error creating user pool: {e}")
        sys.exit(1)

def create_app_client(user_pool_id):
    """Create an App Client for the User Pool"""
    cognito = boto3.client('cognito-idp', region_name=REGION)
    
    try:
        response = cognito.create_user_pool_client(
            UserPoolId=user_pool_id,
            ClientName='tungsten-login-app',
            GenerateSecret=True,
            RefreshTokenValidity=30,
            AccessTokenValidity=1,
            IdTokenValidity=1,
            TokenValidityUnits={
                'AccessToken': 'days',
                'IdToken': 'days',
                'RefreshToken': 'days'
            },
            ExplicitAuthFlows=[
                'ALLOW_CUSTOM_AUTH',
                'ALLOW_USER_SRP_AUTH',
                'ALLOW_REFRESH_TOKEN_AUTH'
            ]
        )
        
        client_id = response['UserPoolClient']['ClientId']
        client_secret = response['UserPoolClient']['ClientSecret']
        
        print(f"App Client created successfully: {client_id}")
        
        # Save client info to a file
        with open('user_pool_info.json', 'r') as f:
            data = json.load(f)
        
        data['client_id'] = client_id
        data['client_secret'] = client_secret
        
        with open('user_pool_info.json', 'w') as f:
            json.dump(data, f)
        
        return client_id, client_secret
    
    except ClientError as e:
        print(f"Error creating app client: {e}")
        sys.exit(1)

def create_admin_user(user_pool_id, email):
    """Create the initial admin user"""
    cognito = boto3.client('cognito-idp', region_name=REGION)
    
    try:
        # Create admin user
        response = cognito.admin_create_user(
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
                    'Value': 'admin'
                }
            ],
            MessageAction='SUPPRESS'  # No welcome email as we'll use magic links
        )
        
        print(f"Admin user created: {email}")
        return True
    
    except ClientError as e:
        print(f"Error creating admin user: {e}")
        return False

def main():
    """Main execution function"""
    # Create the user pool
    user_pool_id = create_user_pool()
    
    if user_pool_id:
        # Create an app client
        client_id, client_secret = create_app_client(user_pool_id)
        
        # Create the admin user
        create_admin_user(user_pool_id, ADMIN_EMAIL)
        
        print("\nAWS Cognito setup complete!")
        print(f"User Pool ID: {user_pool_id}")
        print(f"App Client ID: {client_id}")
        print("Configuration stored in user_pool_info.json")
        print("\nNext steps:")
        print("1. Update config.py with the Cognito details")
        print("2. Set up your application to use these credentials")

if __name__ == "__main__":
    main()