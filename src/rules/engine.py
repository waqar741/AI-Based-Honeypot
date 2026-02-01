import re
from src.rules.patterns import SecurityFilter

# Instantiate filter once
filter_engine = SecurityFilter()

def evaluate_rules(payload: str, user_agent: str):
    matches = []

    # 1. Check Payload using SecurityFilter
    matches.extend(filter_engine.check_input(payload))

    # 2. Check User Agent (Scanner Detection)
    for agent in filter_engine.SCANNER_AGENTS:
        if re.search(agent, user_agent):
             matches.append(f"Malicious Scanner: {agent}")

    if len(matches) == 0:
        return "SAFE", []

    if len(matches) == 1:
        return "SUSPICIOUS", matches

    return "MALICIOUS", matches
