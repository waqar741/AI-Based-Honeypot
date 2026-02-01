import re

SQLI_PATTERNS = [
    r"(?i)(union\s+select)",
    r"(?i)(or\s+1\s*=\s*1)",
    r"(?i)(drop\s+table)",
    r"(?i)(--|\#)"
]

XSS_PATTERNS = [
    r"(?i)(<script.*?>)",
    r"(?i)(javascript:)",
    r"(?i)(onerror\s*=)",
]

DIR_TRAVERSAL_PATTERNS = [
    r"(\.\./)",
    r"(\.\.\\)"
]

CMD_INJECTION_PATTERNS = [
    r"(;|\|\|)",
    r"(?i)(whoami|id|uname)"
]

SCANNER_USER_AGENTS = [
    "sqlmap",
    "nikto",
    "nmap",
    "dirbuster",
    "acunetix"
]
