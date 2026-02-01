import re
from src.rules.patterns import *

def evaluate_rules(payload: str, user_agent: str):
    matches = []

    for pattern in SQLI_PATTERNS:
        if re.search(pattern, payload):
            matches.append("SQL Injection")

    for pattern in XSS_PATTERNS:
        if re.search(pattern, payload):
            matches.append("XSS")

    for pattern in DIR_TRAVERSAL_PATTERNS:
        if re.search(pattern, payload):
            matches.append("Directory Traversal")

    for pattern in CMD_INJECTION_PATTERNS:
        if re.search(pattern, payload):
            matches.append("Command Injection")

    for agent in SCANNER_USER_AGENTS:
        if agent.lower() in user_agent.lower():
            matches.append("Malicious Scanner")

    if len(matches) == 0:
        return "SAFE", []

    if len(matches) == 1:
        return "SUSPICIOUS", matches

    return "MALICIOUS", matches
