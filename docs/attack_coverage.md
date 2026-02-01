# Attack Coverage Matrix

This table maps specific attack vectors to the primary detection mechanism used by the gateway.

| Attack Type | Detection Layer | Mechanism |
| :--- | :--- | :--- |
| **Scanner User-Agents** | **Rule-Based** | Matches known bad User-Agent strings (e.g., Nikto, Burp, Nmap) against a static blocklist. |
| **SQL Injection (SQLi)** | **Rules + LLM** | Regex detects common keywords (`UNION SELECT`). LLM analyzes context for obfuscated queries. |
| **Cross-Site Scripting (XSS)** | **Rules + Semantic** | Regex catches `<script>` tags. Semantic analysis looks for JavaScript execution intent in inputs. |
| **Directory Traversal** | **Path Analysis** | Checks URL paths for sequences like `../`, `..%2f`, and access to sensitive files (`/etc/passwd`). |
| **Command Injection** | **Tokens + LLM** | Identifies shell metacharacters (`|`, `;`, `$()`) and standard OS commands in input fields. |
| **SSRF** | **URL Semantics** | Analyzes URL parameters for internal IP ranges or localhost references. |
| **LFI / RFI** | **File Path Logic** | Detects attempts to include local system files or remote external resources. |
| **Brute Force** | **Rate + Behavior** | Monitors request frequency and patterned failures (e.g., multiple 401s from same IP). |
| **XXE** | **XML Patterns** | Scans XML bodies for `<!ENTITY` definitions and external DTD references. |
| **Web Shell** | **File Extension** | Blocks uploads or access to executable file types (`.php`, `.jsp`, `.sh`) in non-executable paths. |
| **URL Spoofing** | **Host Similarity** | Checks for homoglyphs or subtle misspellings of the trusted domain. |
