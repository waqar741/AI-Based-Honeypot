def decide_action(risk_score):
    if risk_score < 3:
        return "ALLOW"
    elif 3 <= risk_score < 6:
        return "MONITOR"
    elif 6 <= risk_score < 9:
        return "DECEIVE"
    else:
        return "THROTTLE"
