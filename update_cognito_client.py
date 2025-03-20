import boto3
import json
import os
from config import Config

# Load configuration
config = Config()

# Load user pool info
with open('user_pool_info.json', 'r') as f:
    user_pool_info = json.load(f)

user_pool_id = user_pool_info['user_pool_id']
client_id = user_pool_info['client_id']
client_secret = user_pool_info['client_secret']

# Create Cognito client
cognito_client = boto3.client('cognito-idp', region_name='eu-west-2')

try:
    # Get current client settings
    response = cognito_client.describe_user_pool_client(
        UserPoolId=user_pool_id,
        ClientId=client_id
    )
    
    client_settings = response['UserPoolClient']
    
    # Update client settings to enable required auth flows
    updated_response = cognito_client.update_user_pool_client(
        UserPoolId=user_pool_id,
        ClientId=client_id,
        ClientName=client_settings['ClientName'],
        RefreshTokenValidity=client_settings.get('RefreshTokenValidity', 30),
        AccessTokenValidity=client_settings.get('AccessTokenValidity', 60),
        IdTokenValidity=client_settings.get('IdTokenValidity', 60),
        TokenValidityUnits=client_settings.get('TokenValidityUnits', {
            'AccessToken': 'minutes',
            'IdToken': 'minutes',
            'RefreshToken': 'days'
        }),
        ExplicitAuthFlows=[
            'ADMIN_NO_SRP_AUTH',
            'USER_PASSWORD_AUTH',
            'REFRESH_TOKEN_AUTH'
        ],
        AllowedOAuthFlows=client_settings.get('AllowedOAuthFlows', []),
        AllowedOAuthScopes=client_settings.get('AllowedOAuthScopes', []),
        AllowedOAuthFlowsUserPoolClient=client_settings.get('AllowedOAuthFlowsUserPoolClient', False),
        PreventUserExistenceErrors=client_settings.get('PreventUserExistenceErrors', 'ENABLED'),
        EnableTokenRevocation=client_settings.get('EnableTokenRevocation', True),
        SupportedIdentityProviders=client_settings.get('SupportedIdentityProviders', []),
        CallbackURLs=client_settings.get('CallbackURLs', []),
        LogoutURLs=client_settings.get('LogoutURLs', []),
        ReadAttributes=client_settings.get('ReadAttributes', []),
        WriteAttributes=client_settings.get('WriteAttributes', [])
    )
    
    print("Successfully updated app client settings!")
    print("Enabled auth flows:", updated_response['UserPoolClient']['ExplicitAuthFlows'])
    
except Exception as e:
    print(f"Error updating app client settings: {str(e)}")
