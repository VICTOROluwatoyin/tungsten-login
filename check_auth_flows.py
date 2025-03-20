import boto3
import json

# Load user pool info
with open('user_pool_info.json', 'r') as f:
    info = json.load(f)

# Create Cognito client
client = boto3.client('cognito-idp', region_name='eu-west-2')

# Get client settings
response = client.describe_user_pool_client(
    UserPoolId=info['user_pool_id'],
    ClientId=info['client_id']
)

# Print enabled auth flows
print('Enabled auth flows:', response['UserPoolClient'].get('ExplicitAuthFlows', []))
print('Client name:', response['UserPoolClient'].get('ClientName', ''))
print('Allowed OAuth flows:', response['UserPoolClient'].get('AllowedOAuthFlows', []))
