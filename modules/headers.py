def analyze_headers(headers):

    findings = []

    if "Content-Security-Policy" not in headers:
        findings.append(
            "[HIGH] Missing Content-Security-Policy"
        )

    if "Strict-Transport-Security" not in headers:
        findings.append(
            "[HIGH] Missing HSTS"
        )

    if "X-Frame-Options" not in headers:
        findings.append(
            "[MEDIUM] Missing X-Frame-Options"
        )

    if "X-Content-Type-Options" not in headers:
        findings.append(
            "[MEDIUM] Missing X-Content-Type-Options"
        )

    if "Referrer-Policy" not in headers:
        findings.append(
            "[LOW] Missing Referrer-Policy"
        )

    return findings