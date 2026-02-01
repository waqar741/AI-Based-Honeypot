import re
from urllib.parse import urlparse, parse_qs

class SecurityFilter:
    def __init__(self):
        # 1. Malicious Scanners / User Agents
        self.SCANNER_AGENTS = [
            r"(?i)(sqlmap)", r"(?i)(nikto)", r"(?i)(nmap)", r"(?i)(dirbuster)",
            r"(?i)(acunetix)", r"(?i)(havij)", r"(?i)(w3af)", r"(?i)(netsparker)",
            r"(?i)(masscan)", r"(?i)(burp)", r"(?i)(nessus)", r"(?i)(zaproxy)",
            r"(?i)(webscantest)", r"(?i)(hydra)"
        ]

        # 2. SQL Injection (SQLi)
        # Covers: Union-based, Error-based, Boolean-based, Time-based, Stacked queries
        self.SQL_PATTERNS = [
            r"(?i)(SELECT.+FROM)",
            r"(?i)(UNION\s+(ALL\s+)?SELECT)",
            r"(?i)(INSERT\s+INTO.+VALUES)",
            r"(?i)(UPDATE.+SET)",
            r"(?i)(DELETE\s+FROM)",
            r"(?i)(DROP\s+TABLE)",
            r"(?i)(ALTER\s+TABLE)",
            r"(?i)(TRUNCATE\s+TABLE)",
            r"(?i)(OR\s+[\d\w]+=[\d\w]+)",        # Generic boolean (OR 1=1, OR a=a)
            r"(?i)(\)\s*OR\s*[\d\w]+=[\d\w]+)",   # Closed parenthesis boolean
            r"(?i)(--\s)",                        # SQL comment
            r"(?i)(\#)",                          # MySQL comment
            r"(?i)(/\*.*\*/)",                    # Inline comment
            r"(?i)(;\s*WAITFOR\s+DELAY)",         # MSSQL Time-based
            r"(?i)(BENCHMARK\()",                 # MySQL Time-based
            r"(?i)(pg_sleep\()",                  # PostgreSQL Time-based
            r"(?i)(@@version)"
        ]

        # 3. Cross-Site Scripting (XSS)
        # Covers: Script tags, Event handlers, Pseudo-protocols, SVG/Img vectors
        self.XSS_PATTERNS = [
            r"(?i)(<script.*?>)",
            r"(?i)(</script>)",
            r"(?i)(javascript:)",
            r"(?i)(vbscript:)",
            r"(?i)(on(error|load|click|mouseover|submit|focus|blur)=)",
            r"(?i)(<img.+src.+>)",
            r"(?i)(<iframe.+>)",
            r"(?i)(<svg.+>)",
            r"(?i)(document\.cookie)",
            r"(?i)(document\.domain)",
            r"(?i)(alert\()",
            r"(?i)(prompt\()",
            r"(?i)(eval\()",
            r"(?i)(base64,)"  # Detecting potential encoded payloads
        ]

        # 4. Directory Traversal / Path Traversal
        # Covers: Standard ../, encoded variations, mixed slash/backslash
        self.DIR_TRAVERSAL_PATTERNS = [
            r"(\.\./)",
            r"(\.\.\\)",
            r"(%2e%2e%2f)",          # URL Encoded ../
            r"(%2e%2e/)",            # Mixed encoding
            r"(\.\.%2f)",
            r"(%2e%2e%5c)",          # URL Encoded ..\
            r"(?i)(/etc/passwd)",    # Target file
            r"(?i)(c:\\windows\\win.ini)"
        ]

        # 5. Command Injection (OS Command Injection)
        # Covers: Chaining, Piping, dangerous binaries (rm, netcat, wget)
        self.CMD_PATTERNS = [
            r"(?i)(;|\||&&|\$\()",             # Chaining characters
            r"(?i)(\|\|)",                     # Double pipe
            r"(?i)(/bin/sh)",
            r"(?i)(/bin/bash)",
            r"(?i)(cmd\.exe)",
            r"(?i)(powershell)",
            # Specific dangerous commands (with boundaries to avoid false positives on words like 'category')
            r"(?i)(^|[\s;|])(rm\s+-rf)",
            r"(?i)(^|[\s;|])(wget\s+http)",
            r"(?i)(^|[\s;|])(curl\s+http)",
            r"(?i)(^|[\s;|])(netcat|nc\s+)",
            r"(?i)(^|[\s;|])(whoami)",
            r"(?i)(^|[\s;|])(ping\s+-)",
            r"(?i)(^|[\s;|])(cat\s+/etc/)",
            r"(?i)(`.*`)"                      # Backticks execution
        ]

        # 6. Server-Side Request Forgery (SSRF)
        # Covers: Cloud metadata, Localhost, Private IPs, dangerous protocols
        self.SSRF_PATTERNS = [
            r"(?i)(http://localhost)",
            r"(?i)(http://127\.0\.0\.1)",
            r"(?i)(http://0\.0\.0\.0)",
            r"(?i)(http://169\.254\.169\.254)",    # AWS/GCP/Azure Metadata
            r"(?i)(http://\[::1\])",               # IPv6 Localhost
            r"(?i)(file://)",
            r"(?i)(gopher://)",
            r"(?i)(dict://)",
            r"(?i)(ftp://)",
            r"(?i)(ldap://)"
        ]

        # 7. Local/Remote File Inclusion (LFI/RFI)
        # Covers: PHP wrappers, system files, remote URLs in file parameters
        self.FILE_INCLUSION_PATTERNS = [
            r"(?i)(/etc/passwd)",
            r"(?i)(/etc/shadow)",
            r"(?i)(/proc/self/environ)",
            r"(?i)(c:\\boot.ini)",
            r"(?i)(php://)",
            r"(?i)(zlib://)",
            r"(?i)(data://)",
            r"(?i)(expect://)",
            r"(?i)(input://)",
            r"(?i)(http://.+?\.php)", # Remote file include attempt
            r"(?i)(https://.+?\.php)"
        ]

        # 8. XML External Entity (XXE)
        # Covers: Entity declarations, SYSTEM calls
        self.XXE_PATTERNS = [
            r"(?i)(<!ENTITY)",
            r"(?i)(<!DOCTYPE)",
            r"(?i)(SYSTEM\s+\")",
            r"(?i)(PUBLIC\s+\")"
        ]

        # 9. Web Shell / Malicious Uploads
        # Covers: Dangerous extensions and common shell names
        self.WEB_SHELL_PATTERNS = [
            r"(?i)(\.php|\.php3|\.php4|\.php5|\.phtml)$",
            r"(?i)(\.jsp|\.jspx|\.jsw|\.jsv)$",
            r"(?i)(\.asp|\.aspx|\.asa|\.asax)$",
            r"(?i)(\.exe|\.dll|\.sh|\.bat|\.cmd)$",
            r"(?i)(cmd\.jsp)",
            r"(?i)(shell\.php)",
            r"(?i)(c99\.php)",
            r"(?i)(r57\.php)",
            r"(?i)(backdoor)"
        ]

        # 10. Typosquatting / Spoofing
        # Covers: Common misspellings of major domains (add your organization's domain here)
        self.SPOOFING_PATTERNS = [
            r"paypa[l1]\.",
            r"go{2}gle\.",
            r"faceb[o0]{2}k\.",
            r"micros[o0]ft\.",
            r"app[l1]e\.",
            r"support.*\.com",  # Generic support scams
            r"login.*\.net"
        ]

        # 11. Credential Stuffing / Brute Force (Payload Detection)
        # Note: True detection requires rate limiting. These are rule-based checks for *bad* payloads.
        self.CRED_STUFFING_PATTERNS = [
            r"(?i)(admin/admin)",
            r"(?i)(root/toor)",
            r"(?i)(guest/guest)",
            r"(?i)(test/test)",
            r"(?i)(password123)"
        ]

    def check_input(self, input_string):
        """Checks a single string against all regex categories."""
        matches = []
        
        checks = {
            "SQL Injection": self.SQL_PATTERNS,
            "XSS": self.XSS_PATTERNS,
            "Directory Traversal": self.DIR_TRAVERSAL_PATTERNS,
            "Command Injection": self.CMD_PATTERNS,
            "SSRF": self.SSRF_PATTERNS,
            "File Inclusion": self.FILE_INCLUSION_PATTERNS,
            "XXE": self.XXE_PATTERNS,
            "Web Shell": self.WEB_SHELL_PATTERNS,
            "Spoofing": self.SPOOFING_PATTERNS,
            "Bad Credentials": self.CRED_STUFFING_PATTERNS
        }

        for threat_name, patterns in checks.items():
            for pattern in patterns:
                if re.search(pattern, input_string):
                    matches.append(f"{threat_name} detected: {pattern}")
                    break # Stop checking this category if one match found
        
        return matches

    def check_hpp(self, url):
        """
        12. HTTP Parameter Pollution (HPP)
        Logic: Checks if the same parameter appears twice in the URL.
        """
        parsed = urlparse(url)
        # keep_blank_values=True ensures we see empty params
        # parse_qs returns a dict where values are lists: {'id': ['1', '2']}
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        detected = []
        for key, value_list in params.items():
            if len(value_list) > 1:
                detected.append(f"HPP detected on parameter: '{key}' (Values: {value_list})")
        
        return detected

# --- Usage Example ---

filter_engine = SecurityFilter()

# Example 1: Malicious Input String (CMD Injection + SQLi)
test_payload = "cat /etc/passwd; DROP TABLE users;"
alerts = filter_engine.check_input(test_payload)
print("--- Payload Alerts ---")
for alert in alerts:
    print(alert)

# Example 2: HPP Detection
test_url = "http://example.com/page?id=1&action=view&id=2"
hpp_alerts = filter_engine.check_hpp(test_url)
print("\n--- HPP Alerts ---")
for alert in hpp_alerts:
    print(alert)
