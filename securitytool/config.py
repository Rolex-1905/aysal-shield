import json
import yaml
import os
import re

REQUIRED_FIELDS = ["target", "report"]


def resolve_env_vars(value):
    if isinstance(value, str):
        pattern = r'\$\{([^}]+)\}'
        matches = re.findall(pattern, value)
        for match in matches:
            env_value = os.environ.get(match, "")
            if not env_value:
                raise ValueError(f"Environment variable '{match}' is not set")
            value = value.replace(f"${{{match}}}", env_value)
        return value
    elif isinstance(value, dict):
        return {k: resolve_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [resolve_env_vars(i) for i in value]
    return value


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

    try:
        config = resolve_env_vars(config)
    except ValueError as e:
        raise ValueError(f"Config env var error: {e}")

    return config