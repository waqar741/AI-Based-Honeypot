def calculate_risk(rule_verdict, rule_matches, llm_verdict):
    score = 0

    # Rule-based contribution
    if rule_verdict == "SUSPICIOUS":
        score += 2
    elif rule_verdict == "MALICIOUS":
        score += 5

    # Multiple rule matches = higher confidence
    if rule_matches:
        score += len(rule_matches.split(","))

    # LLM advisory (only adds, never overrides)
    if llm_verdict == "UNSAFE":
        score += 3

    return score
