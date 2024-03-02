#Chaitanya Chunduri
#cc1278
#11498621
#Project 1: Implementing a JWKS Server


from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import jwt
import datetime

app = Flask(__name__)

# Generate RSA private key and corresponding public numbers
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Serialize private keys to PEM format without encryption
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Extract public numbers from private keys
numbers = private_key.private_numbers()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """Endpoint to expose JSON Web Key Set (JWKS) for authentication"""
    keys = {
        "keys": [
            {
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "kid": "goodKID",
                "n": int_to_base64(numbers.public_numbers.n),
                "e": int_to_base64(numbers.public_numbers.e),
            }
        ]
    }
    return jsonify(keys)

@app.route('/auth', methods=['POST'])
def authenticate():
    """Endpoint to generate a JWT token for authentication"""
    token_payload = {
        "user": "username",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }

    headers = {"kid": "goodKID"}

    # Check for an optional 'expired' query parameter to simulate an expired token
    if request.args.get('expired') == 'true':
        headers["kid"] = "expiredKID"
        token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)

    # Encode JWT using the selected private key and RS256 algorithm
    encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)

    return encoded_jwt

if __name__ == '__main__':
    # Run the Flask application on localhost:8080
    app.run(host='localhost', port=8080)
