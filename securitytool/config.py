import json
import yaml
import os

REQUIRED_FIELDS = ["target", "report"]

def load_config(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    
    with open(path, "r") as f:
        if path.endswith(".yaml") or path.endswith(".yml"):
            config = yaml.safe_load(f)
        elif path.endswith(".json"):
            config = json.load(f)
        else:
            raise ValueError("Config file must be .json or .yaml")
    
    for field in REQUIRED_FIELDS:
        if field not in config:
            raise ValueError(f"Missing required config field: {field}")
    
    return config