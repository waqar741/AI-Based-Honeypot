# Attack Coverage Matrix

This table maps specific attack vectors to the primary detection mechanism used by the gateway's `SecurityFilter` and AI engine.

| Attack Type | Detection Layer | Mechanism |
| :--- | :--- | :--- |
| **Scanner User-Agents** | **Rule-Based** | Matches known scanner strings (e.g., `sqlmap`, `nikto`, `burp`, `nmap`) against a static blocklist. |
| **SQL Injection (SQLi)** | **Rules + LLM** | Regex detects keywords (`UNION SELECT`, `DROP TABLE`, `OR 1=1`, Time-based delays). LLM analyzes context for obfuscated queries. |
| **Cross-Site Scripting (XSS)** | **Rules + Semantic** | Regex catches `<script>`, `javascript:`, `alert()`, and event handlers. Semantic analysis checks for execution intent. |
| **Directory Traversal** | **Path Analysis** | Checks URL paths for sequences like `../`, encoded variations (`%2e%2e`), and system file paths (`/etc/passwd`). |
| **Command Injection** | **Tokens + LLM** | Identifies shell metacharacters (`|`, `;`, `$()`) and dangerous binaries (`nc`, `wget`, `bash`) in input fields. |
| **SSRF** | **URL Semantics** | Analyzes URL parameters for internal IP ranges (`127.0.0.1`, `169.254...`), `file://` schemes, and localhost references. |
| **LFI / RFI** | **File Path Logic** | Detects PHP wrappers (`php://`), remote includes, and access to sensitive filesystem locations. |
| **Brute Force** | **Behavioral** | Monitors login failure rates and high-frequency requests from a single IP address. |
| **XXE** | **XML Patterns** | Scans XML bodies for `<!ENTITY`, `SYSTEM`, and external DTD references. |
| **Web Shell** | **File Extension** | Blocks uploads or access to executable file types (`.php`, `.jsp`, `.sh`, `.cmd`) in non-executable paths. |
| **URL Spoofing** | **Host Similarity** | Checks for homoglyphs or subtle misspellings of trusted domains (e.g., `paypa1`, `go0gle`). |
| **Credential Stuffing** | **Pattern + Rate** | Detects common default credentials (`admin/admin`, `root/toor`) and repeated login attempts. |
