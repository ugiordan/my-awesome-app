# TEST FILE - Intentionally insecure for security scanning validation
# DO NOT USE IN PRODUCTION

import pickle
import subprocess
import os
import yaml
import requests
import torch
import grpc
import dill
from transformers import AutoModel

# Hardcoded credentials (CWE-798)
password = "super_secret_password_123"
api_key = "my-production-api-key-value"

# Unsafe deserialization (CWE-502)
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

# Unsafe torch.load (CWE-502)
loaded_model = torch.load("checkpoint.pt")

# Remote code execution via trust_remote_code (CWE-94)
hf_model = AutoModel.from_pretrained("malicious/model", trust_remote_code=True)

# Unsafe YAML loading (CWE-502)
with open("config.yaml") as f:
    config = yaml.load(f)

# Command injection (CWE-78)
user_input = "harmless"
subprocess.run(f"echo {user_input}", shell=True)

# OS command injection (CWE-78)
os.system(user_input)

# Code injection (CWE-94)
eval(user_input)

# SSL verification disabled (CWE-295)
response = requests.get("https://api.example.com", verify=False)

# Insecure gRPC channel (CWE-319)
channel = grpc.insecure_channel("model-server:8081")

# SQL injection (CWE-89)
import sqlite3
conn = sqlite3.connect("test.db")
cursor = conn.cursor()
cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")

# Unsafe dill deserialization (CWE-502)
with open("data.dill", "rb") as f:
    obj = dill.load(f)


def connect():
    return password
