# modules/recommendations.py
def generate_recommendations(findings):
    recs = []
    for finding in findings:
        if "Missing Content-Security-Policy" in finding:
            recs.append(
                "Enable CSP by sending the `Content-Security-Policy` HTTP header. "
                "For example: `Content-Security-Policy: default-src 'self'; script-src 'self'; ...`. "
                "This mitigates XSS."
            )
        if "Missing Strict-Transport-Security" in finding:
            recs.append(
                "Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` "
                "to enforce HTTPS. Ensure all subdomains use HTTPS."
            )
        if "Missing X-Frame-Options" in finding:
            recs.append(
                "Set `X-Frame-Options: DENY` on all HTML pages to prevent clickjacking."
            )
        if "Missing X-Content-Type-Options" in finding:
            recs.append(
                "Send `X-Content-Type-Options: nosniff` to prevent MIME-sniffing attacks."
            )
        if "Missing Referrer-Policy" in finding:
            recs.append(
                "Use `Referrer-Policy: strict-origin-when-cross-origin` to limit Referer leakage."
            )
        # Add more mappings as needed...
    return recs
