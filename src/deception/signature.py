import hashlib

def generate_signature(path, params, attack_type):
    # Create a unique but stable hash for the attack context
    raw = f"{path}|{params}|{attack_type}"
    return hashlib.sha256(raw.encode()).hexdigest()
