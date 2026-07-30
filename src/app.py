import re
import subprocess
from flask import Flask, jsonify

app = Flask(__name__)

# Security: Sanitize command input to prevent injection (CWE-78)
SAFE_CMD_PATTERN = re.compile(r'^[A-Za-z0-9_\-\.]+$')

def sanitize_command_input(cmd_arg):
    """Sanitize command arguments to prevent command injection."""
    if not cmd_arg or not isinstance(cmd_arg, str):
        raise ValueError("Invalid input: command argument must be a non-empty string")

    if not SAFE_CMD_PATTERN.match(cmd_arg):
        raise ValueError(f"Invalid input: command argument contains disallowed characters")

    # Additional injection protection
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>']
    for char in dangerous_chars:
        if char in cmd_arg:
            raise ValueError("Command injection attempt detected")

    return cmd_arg

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
