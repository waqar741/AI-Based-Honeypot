# Threat Model

## Threat Landscape

| Category | Description |
| :--- | :--- |
| **In-scope Attackers** | **Automated Scanners**: Bots searching for common vulnerabilities (e.g., Nikto, SQLMap, Burp Suite).<br>**Script Kiddies**: Unskilled attackers using pre-made exploit tools.<br>**Manual Attackers**: Curious individuals probing for specific logic flaws. |
| **In-scope Attacks** | **Injection**: SQL Injection (Union, Boolean, Time-based), Command Injection (OS commands, pipes).<br>**Web Attacks**: XSS (Reflected/Stored), SSRF (Localhost, Metadata), LFI/RFI (File inclusion), XXE (Entity attacks).<br>**Auth**: Brute force, Credential stuffing, Password guessing.<br>**Recon**: Directory fuzzing, Port scanning (via web), URL Spoofing (Homoglyphs).<br>**Uploads**: Web shells (`.php`, `.jsp` uploads). |
| **Out-of-scope** | **DDoS**: Volumetric network-layer attacks (UDP/TCP floods).<br>**Kernel Exploits**: OS-level vulnerabilities below the application layer.<br>**Zero-days**: Previously unknown vulnerabilities in the underlying Python framework or web server. |
| **Attack Surface** | **HTTP/HTTPS Requests**: The gateway processes Layer 7 application traffic. It monitors Paths, Query Parameters, Headers (User-Agent), and Body content. |
| **Assumption** | **Secure Backend Implementation**: We assume the backend developers follow basic secure coding practices. The gateway is a "Safety Net" or "First Line of Defense", not a replacement for patching known vulnerabilities in the backend code. |

## Defense Capabilities

1.  **Scanner Detection**: Blocks known security scanner User-Agents.
2.  **Payload Analysis**: Inspects all input vectors (URL, Body) for malicious patterns.
3.  **Semantic Analysis**: Uses LLM to understand the *intent* of a payload, catching obfuscation.
4.  **Behavioral Tracking**: Identifies and throttles high-frequency attack sources.
