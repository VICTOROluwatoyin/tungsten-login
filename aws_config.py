import os
import boto3
import json
import logging

def configure_aws_credentials():
    """
    Configure AWS credentials for boto3 clients.
    This function will check for credentials in environment variables
    and set them up for boto3 to use.
    """
    # Get AWS credentials from environment variables
    aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    aws_region = os.environ.get('AWS_REGION', 'eu-west-2')
    
    if not aws_access_key or not aws_secret_key:
        logging.warning("AWS credentials not found in environment variables")
        # Try to load from a credentials file if available
        try:
            with open('aws_credentials.json', 'r') as f:
                creds = json.load(f)
                aws_access_key = creds.get('AWS_ACCESS_KEY_ID')
                aws_secret_key = creds.get('AWS_SECRET_ACCESS_KEY')
                aws_region = creds.get('AWS_REGION', aws_region)
        except (FileNotFoundError, json.JSONDecodeError):
            logging.warning("AWS credentials file not found or invalid")
    
    # Set up boto3 session with credentials
    if aws_access_key and aws_secret_key:
        boto3.setup_default_session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=aws_region
        )
        return True
    else:
        logging.error("No AWS credentials found. AWS functionality will not work.")
        return False
