def fingerprint(headers):

    findings = []

    server = headers.get("Server")

    powered = headers.get("X-Powered-By")

    if server:
        findings.append(f"Server: {server}")

    if powered:
        findings.append(f"Technology: {powered}")

    return findings