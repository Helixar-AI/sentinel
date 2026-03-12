"""Fixture config dictionaries used across test modules."""

SECURE_CONFIG = {
    "auth": {
        "scheme": "bearer",
        "token_validation": "strict",
    },
    "tls": {
        "cert": "/etc/ssl/certs/server.crt",
        "key": "/etc/ssl/private/server.key",
        "min_version": "TLS1.2",
    },
    "rate_limit": {
        "requests_per_minute": 60,
        "burst": 10,
    },
    "debug": False,
    "cors": {
        "allowed_origins": ["https://app.example.com"],
    },
    "input_validation": {
        "enabled": True,
        "strict": True,
    },
    "logging": {
        "level": "info",
        "log_sensitive": False,
        "log_body": False,
        "log_auth": False,
    },
    "timeout_seconds": 30,
    "permissions": ["read_resource", "call_tool"],
}

INSECURE_CONFIG = {
    # no auth block
    # no tls block
    # no rate_limit block
    "api_key": "sk-abc123supersecretkey",  # plaintext secret
    "debug": True,
    "cors": {
        "allowed_origins": "*",
    },
    # no input_validation
    "logging": {
        "level": "debug",
        "log_sensitive": True,
        "log_body": True,
        "log_auth": True,
    },
    # no timeout
    "permissions": "*",
}
