# Test file for OpenGrep minimal rule validation
import pickle

password = "super_secret_123"

with open("data.pkl", "rb") as f:
    obj = pickle.load(f)
