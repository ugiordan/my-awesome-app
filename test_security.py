"""Test file with intentional security issues for OpenGrep/Semgrep validation."""

import pickle
import subprocess
import os
import yaml
import requests


# Rule: python-hardcoded-password (CWE-798)
password = "SuperSecretPassword123!"
api_key = "sk-1234567890abcdef"

# Rule: python-pickle-unsafe-load (CWE-502)
def load_model(path):
    with open(path, "rb") as f:
        return pickle.load(f)

# Rule: python-eval-exec-injection (CWE-94)
def process_input(user_input):
    result = eval(user_input)
    return result

# Rule: python-shell-injection-subprocess (CWE-78)
def run_command(cmd):
    subprocess.run(cmd, shell=True)

# Rule: python-yaml-unsafe-load (CWE-502)
def parse_config(config_file):
    with open(config_file) as f:
        return yaml.load(f)

# Rule: python-os-system (CWE-78)
def cleanup(path):
    os.system(f"rm -rf {path}")

# Rule: python-ssl-verify-disabled (CWE-295)
def fetch_data(url):
    return requests.get(url, verify=False)

# Rule: python-sql-injection-format (CWE-89)
def get_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
