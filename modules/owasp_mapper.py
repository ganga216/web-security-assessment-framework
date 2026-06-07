def map_owasp(findings):

    mapping = []

    for finding in findings:

        if "Content-Security-Policy" in finding:
            mapping.append("OWASP A03: Injection")

        elif "X-Frame-Options" in finding:
            mapping.append("OWASP A05: Security Misconfiguration")

        elif "HSTS" in finding:
            mapping.append("OWASP A05: Security Misconfiguration")

    return list(set(mapping))