# Threat Model

## Threat Landscape

| Category | Description |
| :--- | :--- |
| **In-scope Attackers** | **Automated Scanners**: Bots searching for common vulnerabilities.<br>**Script Kiddies**: Unskilled attackers using pre-made tools.<br>**Manual Attackers**: Curious individuals probing for specific logic flaws. |
| **In-scope Attacks** | **Injection**: SQLi, Command Injection.<br>**Web Attacks**: XSS, SSRF, LFI/RFI.<br>**Auth**: Brute force, Credential stuffing.<br>**Recon**: Directory fuzzing, Port scanning (via web). |
| **Out-of-scope** | **DDoS**: Volumetric attacks (handled by infrastructure).<br>**Kernel Exploits**: OS-level vulnerabilities.<br>**Zero-days**: Previously unknown vulnerabilities in the framework itself. |
| **Attack Surface** | **HTTP/HTTPS Requests**: The gateway only processes layer 7 application traffic. It does not monitor low-level TCP/UDP packets outside of HTTP context. |
| **Assumption** | **Secure Backend Implementation**: We assume the backend developers follow basic secure coding practices. The gateway is a safety net, not a replacement for patching. |
