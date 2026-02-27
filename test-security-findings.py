# Test file to trigger multiple semgrep security rules
# This file is intentionally insecure for testing purposes

import pickle
import subprocess
import os
import yaml
import requests
import torch
import grpc
from transformers import AutoModel

# --- Rule: python-hardcoded-password ---
password = "super_secret_password_123"
api_key = "my-production-api-key-value"

# --- Rule: python-pickle-unsafe-load ---
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

# --- Rule: python-torch-load-unsafe ---
loaded_model = torch.load("checkpoint.pt")

# --- Rule: python-huggingface-trust-remote-code ---
hf_model = AutoModel.from_pretrained("malicious/model", trust_remote_code=True)

# --- Rule: python-yaml-unsafe-load ---
with open("config.yaml") as f:
    config = yaml.load(f)

# --- Rule: python-shell-injection-subprocess ---
user_input = "safe_command"
subprocess.run(f"echo {user_input}", shell=True)

# --- Rule: python-os-system ---
os.system(user_input)

# --- Rule: python-eval-exec-injection ---
eval(user_input)

# --- Rule: python-ssl-verify-disabled ---
response = requests.get("https://api.example.com", verify=False)

# --- Rule: python-grpc-insecure-channel ---
channel = grpc.insecure_channel("model-server:8081")

# --- Rule: python-sql-injection-format ---
import sqlite3
conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")

# --- Rule: python-unsafe-deserialization-dill-cloudpickle ---
import dill
with open("serialized.dill", "rb") as f:
    obj = dill.load(f)


def connect():
    return password
