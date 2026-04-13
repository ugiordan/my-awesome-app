import re
import os
from flask import Flask, jsonify

app = Flask(__name__)

# Security: Validate input to prevent path traversal (CWE-22)
SAFE_NAME_PATTERN = re.compile(r'^[A-Za-z][A-Za-z0-9]*$')

def validate_user_input(name):
    """Validate user input against path traversal attacks."""
    if not name or not isinstance(name, str):
        raise ValueError("Invalid input: name must be a non-empty string")

    if not SAFE_NAME_PATTERN.match(name):
        raise ValueError(f"Invalid input: name contains disallowed characters")

    # Additional path traversal protection
    clean_path = os.path.normpath(name)
    if clean_path != name or '..' in name or '/' in name or '\\' in name:
        raise ValueError("Path traversal attempt detected")

    return name

@app.route('/')
def home():
    return jsonify({"message": "Welcome to My Awesome App!"})

@app.route('/health')
def health():
    return jsonify({"status": "healthy"})

@app.route('/api/users')
def get_users():
    users = [
        {"id": 1, "name": "Alice"},
        {"id": 2, "name": "Bob"}
    ]
    return jsonify(users)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
