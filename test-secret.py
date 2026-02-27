# Test file to trigger semgrep rule from central coderabbit repo
# This hardcoded password should be caught by the test-hardcoded-password rule

password = "super_secret_123"
api_key = "my-api-key-value-here"

def connect():
    return password
