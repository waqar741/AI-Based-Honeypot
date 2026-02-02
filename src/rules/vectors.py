import re

ATTACK_VECTORS = {
    "sql_injection": [
        r"(?i)(UNION\s+SELECT|UNION\s+ALL\s+SELECT)",
        r"(?i)(OR\s+1=1)",
        r"(?i)(--|\#|\/\*)",
        r"(?i)(DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM)",
        r"(?i)(WAITFOR\s+DELAY|SLEEP\()",
    ],
    "xss": [
        r"(?i)(<script>|javascript:|onerror=|onload=)",
        r"(?i)(alert\(|prompt\(|document\.cookie)",
        r"(?i)(<img\s+src=x)",
    ],
    "directory_traversal": [
        r"(?i)(\.\./\.\./|\.\.\\\.\.\\)",
        r"(?i)(etc/passwd|windows/win.ini)",
        r"(?i)(\%2e\%2e\%2f)", # URL encoded ../
    ],
    "command_injection": [
        r"(?i)(;|\&|\|)\s*(ping|cat|ls|whoami|net user)",
        r"(?i)(\$\(.*\)|`.*`)", # Command substitution
    ],
    "ssrf": [
        r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0)",
        r"(?i)(169\.254\.169\.254)", # AWS Metadata
        r"(?i)(file:///)",
    ],
    "lfi_rfi": [
        r"(?i)(include\s*\(|require\s*\(|php://input)",
        r"(?i)(\.php\?|\.jsp\?)",
    ],
    "credential_stuffing": [
        # Pattern detection usually logic-based (rate limit), but here's a placeholder for potential payload keywords
        # r"(?i)(admin|root|administrator|password|123456)",
    ],
    "http_parameter_pollution": [
        # This will be handled by logic checking duplicate keys, but regex for weird formats
        r"(?i)(\?id=.*\?id=|\&id=.*\?id=)",
    ],
    "xxe_injection": [
        r"(?i)(<!ENTITY|SYSTEM\s+\"file:)",
        r"(?i)(<!DOCTYPE.*\[)",
    ],
    "web_shells": [
        r"(?i)(cmd\.php|shell\.jsp|c99\.php|r57\.php)",
        r"(?i)(eval\(|exec\(|passthru\()",
    ],
    "malicious_user_agents": [
        r"(?i)(sqlmap|nikto|burp|nmap|gobuster|dirbuster|hydra)",
        r"(?i)(python-requests|curl/|wget/)", # Suspicious in browser-only app
    ],
    "typosquatting_spoofing": [
        # Harder to regex in payload, usually domain analysis. 
        # We'll check for fake host headers if needed.
        r"(?i)(Host:\s*google\.com|Host:\s*paypal\.com)",
    ]
}

def check_payload(content):
    """
    Scans a string against all vectors.
    Returns list of detected vector names.
    """
    detected = []
    if not content:
        return detected
        
    for vector, patterns in ATTACK_VECTORS.items():
        for pattern in patterns:
            if re.search(pattern, content):
                detected.append(vector)
                break
    return detected
