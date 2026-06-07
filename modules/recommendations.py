def generate_recommendations(findings):

    recommendations = []

    for finding in findings:

        if "Content-Security-Policy" in finding:

            recommendations.append(
                "Implement Content-Security-Policy to reduce XSS risks."
            )

        elif "HSTS" in finding:

            recommendations.append(
                "Enable Strict-Transport-Security to enforce HTTPS."
            )

        elif "X-Frame-Options" in finding:

            recommendations.append(
                "Enable X-Frame-Options to prevent clickjacking."
            )

    return recommendations