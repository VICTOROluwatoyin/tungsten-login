from itsdangerous import URLSafeTimedSerializer
import time

# Create a serializer with your secret key
serializer = URLSafeTimedSerializer('your-secret-key-for-development')

# Email to generate token for
email = 'vegbinade@tungstenadvertising.com'

# Create token with email and timestamp
data = {
    'email': email,
    'timestamp': time.time()
}
token = serializer.dumps(data)

# Create the magic link
magic_link = f"http://localhost:5000/verify/{token}"

print("\n------------------------")
print("MAGIC LINK EMAIL")
print("To:", email)
print("Subject: Your Tungsten Login Link")
print("------------------------")
print("Magic Link URL:", magic_link)
print("------------------------\n")
