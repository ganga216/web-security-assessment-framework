def map_mitre(findings):

    techniques = []

    for finding in findings:

        if "Content-Security-Policy" in finding:
            techniques.append("T1059 - Command and Scripting Interpreter")

        if "X-Frame-Options" in finding:
            techniques.append("T1185 - Browser Session Hijacking")

    return list(set(techniques))