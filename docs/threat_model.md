# Threat Model

## Threat Landscape

### In-Scope Attackers (Handled)
The system is designed to observe and engage:
*   **Automated Scanners**: Tools like `sqlmap`, `nikto`, `nmap`.
*   **SQL Injection**: Union-based, Boolean-blind, Encoded variants.
*   **Cross-Site Scripting (XSS)**: Basic reflected vectors and script injection.
*   **Server-Side Request Forgery (SSRF)**: Attempts to access localhost or cloud metadata services.
*   **File Inclusion**: LFI/RFI patterns (`/etc/passwd`, remote shells).
*   **XML External Entity (XXE)**: Malicious entity definitions.
*   **Web Shell Uploads**: Uploading executable scripts (`.php`, `.jsp`).
*   **Credential Stuffing**: Brute force and dictionary attacks (via Behavioral Analysis).
*   **HTTP Parameter Pollution**: Duplicate parameters to confuse backend logic.
*   **URL Spoofing**: Typosquatting and homoglyphs.

**Engineering Scope:**
> “The system targets common application-layer attack vectors observable through HTTP requests.”

### Out-of-Scope Attackers (Explicitly Not Handled)
The system does *not* attempt to detect or prevent:
*   **Kernel-level Exploits**: OS vulnerabilities.
*   **Memory Corruption**: Buffer overflows in the underlying interpreter.
*   **Zero-day Vulnerabilities**: Unknown flaws in FastAPI or Uvicorn.
*   **Encrypted Payloads**: We assume TLS termination happens upstream.
*   **Insider Attacks**: Threats originating from within the trusted network.
*   **DDoS**: Volumetric network-layer attacks (UDP floods).

**Viva Line:**
> “These attacks require lower-level or production-grade defenses (like hardware firewalls) and are intentionally out of scope for this application-layer honeypot.”

## Attack Surface
*   **Primary Surface**: HTTP/HTTPS Requests (Methods, Headers, Path, Body).
*   **Secondary Surface**: The Gateway itself (must be hardened in production).

## Security Assumptions
1.  **Secure Backend**: The backend application is reasonably secure; the gateway is an added layer of intelligence, not a patch for broken code.
2.  **Single Node**: This deployment assumes a single gateway instance (no distributed state sync limitations).
